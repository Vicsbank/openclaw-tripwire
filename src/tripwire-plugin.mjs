// Wires the guard, the budget and exec approval into the OpenClaw plugin API.
//
//   host guard   trusted tool policy "host-guard"   (runs before ordinary hooks)
//   tool budget  trusted tool policy "tool-budget"  + after_tool_call observer
//   exec review  before_tool_call hook, asks through native plugin approvals
//
// On an OpenClaw host without trusted tool policies the same checks fall back
// to high-priority before_tool_call hooks.
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHostGuard, insecureTls } from './tripwire-guard.mjs';
import { ToolBudget, BudgetRegistry } from './tripwire-budget.mjs';
import { createExecApproval, execCall, GrantStore } from './tripwire-exec.mjs';
import { resolveConfig, openclawStateRoot, PLUGIN_ID } from './config.mjs';
import { createEventLog } from './events.mjs';

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const inScope = (agents, ctx) => agents.length === 0 || agents.includes(ctx?.agentId);
const unwrap = event => (event?.toolName === 'tool_call' && typeof event.params?.id === 'string'
  ? { toolName: event.params.id, params: event.params.args ?? event.params.arguments ?? {} }
  : { toolName: event?.toolName, params: event?.params ?? {} });

export function registerCli(api) {
  if (typeof api.registerCli !== 'function') return;
  api.registerCli(async ({ program, config, logger }) => {
    const { registerTripwireCli } = await import('./cli.mjs');
    registerTripwireCli(program, { config, logger });
  }, { descriptors: [{ name: 'tripwire', description: 'Check Tripwire setup, test commands against the guard, manage approvals', hasSubcommands: true }] });
}

export function registerTripwire(api, deps = {}) {
  const mode = api.registrationMode;
  if (mode === undefined || mode === 'full' || mode === 'discovery' || mode === 'cli-metadata') registerCli(api);
  if (mode === 'cli-metadata' || mode === 'setup-only') return null;

  const stateRoot = deps.stateRoot ?? openclawStateRoot(process.env, api.runtime);
  const settings = deps.settings ?? resolveConfig(api.pluginConfig ?? {}, { stateRoot });
  const log = deps.record ?? createEventLog(settings.eventsFile, { logger: api.logger });
  const hg = settings.hostGuard, tb = settings.toolBudget, ea = settings.execApproval;

  const guard = deps.guard ?? createHostGuard({
    home: deps.home,
    user: deps.user,
    pluginDirs: deps.pluginDirs ?? [...new Set([api.rootDir, PACKAGE_ROOT].filter(Boolean))],
    stateDir: settings.dataDir,
    secretPaths: hg.secretPaths,
    protectedPaths: hg.protectedPaths,
    keepFolders: hg.keepFolders,
    protectOpenClawConfig: hg.protectOpenClawConfig,
    protectPluginFiles: hg.protectPluginFiles,
    pluginIds: [PLUGIN_ID, api.id].filter(Boolean),
    openclawRoots: [stateRoot],
    openclawConfigPath: deps.configPath ?? process.env.OPENCLAW_CONFIG_PATH,
  });

  const approval = ea.enabled ? (deps.approval ?? createExecApproval({
    config: ea,
    model: ea.model,
    complete: deps.complete ?? (api.runtime?.llm?.complete ? params => api.runtime.llm.complete(params) : undefined),
    grants: deps.grants ?? new GrantStore(settings.grantsFile),
    metric: (type, fields) => log(type, fields),
    logger: api.logger,
  })) : null;

  const budgets = new BudgetRegistry(() => new ToolBudget({
    now: deps.now,
    maxCalls: tb.maxCalls,
    maxMs: tb.maxSeconds * 1000,
    maxFailures: tb.maxFailures,
    execCapSeconds: tb.execTimeoutCapSeconds,
    stateful: tb.statefulTools,
    untimed: tb.untimedTools,
    recovery: tb.recoveryTools,
    dedupe: tb.refuseRepeats,
  }));

  // ---- host guard -------------------------------------------------------
  const guardPolicy = (event, ctx) => {
    if (!hg.enabled || !inScope(hg.agents, ctx)) return undefined;
    const { toolName, params } = unwrap(event);
    if (hg.blockInsecureTls && insecureTls(toolName, params)) {
      log('blocked', { rule: 'insecure-tls', tool: toolName, agentId: ctx?.agentId, runId: ctx?.runId });
      return { block: true, blockReason: 'Tripwire host guard: switching off TLS certificate checks is not allowed; it would expose credentials. Report the TLS error instead.' };
    }
    const v = guard.verdict(event.toolName, event.params);
    if (!v) return undefined;
    const call = execCall(event);
    if (v.askable && approval) {
      const asked = approval.guardApproval(v, event, ctx);
      if (asked !== null) {
        log(asked === undefined ? 'guard_allowed_earlier' : asked.requireApproval ? 'guard_ask' : 'blocked', { rule: v.rule, tool: toolName, agentId: ctx?.agentId, runId: ctx?.runId, command: call?.command });
        return asked;
      }
    }
    log('blocked', { rule: v.rule, tool: toolName, agentId: ctx?.agentId, runId: ctx?.runId, command: call?.command, path: call ? undefined : String(params.path ?? params.file ?? '') || undefined });
    return v.block;
  };

  // ---- tool budget -------------------------------------------------------
  const budgetPolicy = (event, ctx) => {
    if (!tb.enabled || !inScope(tb.agents, ctx)) return undefined;
    const runId = ctx?.runId ?? event?.runId;
    const budget = budgets.get(runId, ctx);
    if (!budget) return undefined;
    const d = budget.inspect(event.toolName, event.params ?? {});
    if (d?.block) log('budget_blocked', { kind: d.kind, tool: event.toolName, agentId: ctx?.agentId, runId, ...budget.snapshot() });
    return d ?? undefined;
  };

  const trusted = typeof api.registerTrustedToolPolicy === 'function' && deps.forceHooks !== true;
  if (trusted) {
    api.registerTrustedToolPolicy({ id: 'host-guard', description: 'Blocks secret reads, writes to protected files, self-escalation and destructive system commands.', evaluate: guardPolicy });
    api.registerTrustedToolPolicy({ id: 'tool-budget', description: 'Per-run limits on tool calls, tool time, failures and exact repeats.', evaluate: budgetPolicy });
  } else {
    api.on('before_tool_call', guardPolicy, { priority: 1000 });
    api.on('before_tool_call', budgetPolicy, { priority: 990 });
  }

  api.on('after_tool_call', (event, ctx) => {
    if (!tb.enabled) return;
    const budget = budgets.peek(ctx?.runId ?? event?.runId);
    if (budget) budget.observe(event.result, event.toolName, event.error);
  });

  // ---- exec approval -----------------------------------------------------
  if (approval) {
    const requests = new Map();
    const conversation = api.config?.plugins?.entries?.[api.id ?? PLUGIN_ID]?.hooks?.allowConversationAccess === true || deps.conversationAccess === true;
    if (approval.mode === 'review' && conversation) {
      api.on('before_prompt_build', (event, ctx) => {
        if (!ctx?.runId || !approval.applies(ctx)) return;
        requests.set(ctx.runId, String(event?.currentUserMessage ?? event?.prompt ?? ''));
        if (requests.size > 200) requests.delete(requests.keys().next().value);
      });
    }
    api.on('before_tool_call', async (event, ctx) => {
      if (!execCall(event)) return undefined;
      if (hg.enabled && inScope(hg.agents, ctx) && guard.verdict(event.toolName, event.params)) return undefined; // the guard policy decided
      return approval.review(event, ctx, requests.get(ctx?.runId));
    }, { priority: 50, timeoutMs: ea.reviewTimeoutSeconds * 1000 + 10_000 });
  }

  api.logger?.info?.(`tripwire: host guard ${hg.enabled ? 'on' : 'off'}, tool budget ${tb.enabled ? 'on' : 'off'}, exec approval ${approval ? `on (${approval.mode})` : 'off'}${trusted ? '' : ' (hook fallback)'}`);
  return { settings, guard, approval, budgets };
}
