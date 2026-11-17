// Turns plugins.entries.tripwire.config into a complete, defaulted settings
// object, and reports setup problems in plain language for `openclaw tripwire status`.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { BUDGET_DEFAULTS } from './tripwire-budget.mjs';

export const PLUGIN_ID = 'tripwire';

export function openclawStateRoot(env = process.env, runtime) {
  try { const dir = runtime?.state?.resolveStateDir?.(env); if (typeof dir === 'string' && dir) return dir; } catch {}
  return env.OPENCLAW_STATE_DIR || join(homedir(), '.openclaw');
}

const strings = v => (Array.isArray(v) ? v.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim()) : []);
const num = (v, d, min, max) => (Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : d);

export function resolveConfig(raw = {}, { stateRoot = openclawStateRoot() } = {}) {
  const c = raw && typeof raw === 'object' ? raw : {};
  const hg = c.hostGuard ?? {}, tb = c.toolBudget ?? {}, ea = c.execApproval ?? {};
  const dataDir = typeof c.dataDir === 'string' && c.dataDir.trim() ? c.dataDir.trim().replace(/^~(?=\/|$)/, homedir()) : join(stateRoot, 'state', PLUGIN_ID);
  return {
    dataDir,
    grantsFile: join(dataDir, 'tripwire-grants.json'),
    eventsFile: join(dataDir, 'events.jsonl'),
    hostGuard: {
      enabled: hg.enabled !== false,
      agents: strings(hg.agents),
      secretPaths: strings(hg.secretPaths),
      protectedPaths: strings(hg.protectedPaths),
      keepFolders: strings(hg.keepFolders),
      protectOpenClawConfig: hg.protectOpenClawConfig !== false,
      protectPluginFiles: hg.protectPluginFiles !== false,
      blockInsecureTls: hg.blockInsecureTls !== false,
    },
    toolBudget: {
      enabled: tb.enabled !== false,
      agents: strings(tb.agents),
      maxCalls: num(tb.maxCalls, BUDGET_DEFAULTS.maxCalls, 5, 1000),
      maxSeconds: num(tb.maxSeconds, BUDGET_DEFAULTS.maxSeconds, 30, 7200),
      maxFailures: num(tb.maxFailures, BUDGET_DEFAULTS.maxFailures, 1, 100),
      execTimeoutCapSeconds: num(tb.execTimeoutCapSeconds, BUDGET_DEFAULTS.execTimeoutCapSeconds, 0, 3600),
      refuseRepeats: tb.refuseRepeats !== false,
      statefulTools: strings(tb.statefulTools),
      untimedTools: strings(tb.untimedTools),
      recoveryTools: strings(tb.recoveryTools),
    },
    execApproval: {
      enabled: ea.enabled === true,
      mode: ea.mode === 'ask' ? 'ask' : 'review',
      agents: strings(ea.agents),
      model: typeof ea.model === 'string' && ea.model.trim() ? ea.model.trim() : undefined,
      language: ea.language === 'zh-CN' ? 'zh-CN' : 'en',
      askTimeoutSeconds: num(ea.askTimeoutSeconds, 240, 30, 600),
      reviewTimeoutSeconds: num(ea.reviewTimeoutSeconds, 20, 3, 60),
      maxAsksPerRun: num(ea.maxAsksPerRun, 3, 1, 20),
      readOnlyCommands: strings(ea.readOnlyCommands),
    },
  };
}

// Setup checks against the whole OpenClaw config. Each item: { level: 'ok'|'warn'|'error', text }.
export function setupChecks(openclawConfig = {}, settings = resolveConfig(openclawConfig?.plugins?.entries?.[PLUGIN_ID]?.config)) {
  const entry = openclawConfig?.plugins?.entries?.[PLUGIN_ID] ?? {};
  const out = [];
  const add = (level, text) => out.push({ level, text });
  if (entry.enabled === false) add('error', `The plugin is disabled. Run: openclaw plugins enable ${PLUGIN_ID}`);
  const deny = openclawConfig?.plugins?.deny;
  if (Array.isArray(deny) && deny.includes(PLUGIN_ID)) add('error', `plugins.deny lists "${PLUGIN_ID}"; nothing is enforced.`);
  const allow = openclawConfig?.plugins?.allow;
  if (Array.isArray(allow) && allow.length && !allow.includes(PLUGIN_ID)) add('error', `plugins.allow does not list "${PLUGIN_ID}"; the plugin will not load.`);
  if (!settings.hostGuard.enabled) add('warn', 'hostGuard is off: secrets and protected files are not guarded.');
  else add('ok', `Host guard on${settings.hostGuard.agents.length ? ` for agents: ${settings.hostGuard.agents.join(', ')}` : ' for every agent'}.`);
  if (settings.toolBudget.enabled) add('ok', `Tool budget on: ${settings.toolBudget.maxCalls} calls, ${settings.toolBudget.maxSeconds} s of tool time, ${settings.toolBudget.maxFailures} failures per run.`);
  else add('ok', 'Tool budget off.');
  const ea = settings.execApproval;
  if (!ea.enabled) add('ok', 'Exec approval off (owner-only commands are simply blocked).');
  else {
    add('ok', `Exec approval on, mode "${ea.mode}"${ea.agents.length ? ` for agents: ${ea.agents.join(', ')}` : ' for every agent'}.`);
    if (ea.mode === 'review' && entry.hooks?.allowConversationAccess !== true) add('warn', `Review mode works best with the owner's request as context. Set plugins.entries.${PLUGIN_ID}.hooks.allowConversationAccess to true; without it the reviewer sees only the command.`);
    if (ea.model && entry.llm?.allowModelOverride !== true) add('error', `execApproval.model is set, so plugins.entries.${PLUGIN_ID}.llm.allowModelOverride must be true (and llm.allowedModels must include "${ea.model}" if you restrict it).`);
    const allowed = entry.llm?.allowedModels;
    if (ea.model && Array.isArray(allowed) && allowed.length && !allowed.includes(ea.model)) add('error', `plugins.entries.${PLUGIN_ID}.llm.allowedModels does not include "${ea.model}".`);
    add('ok', 'Approvals use OpenClaw plugin approvals: chat buttons, the Control UI or /approve. Runs with no approval surface (for example cron with no delivery) are blocked rather than run.');
  }
  return out;
}
