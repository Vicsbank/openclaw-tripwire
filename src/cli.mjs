// `openclaw tripwire ...` — setup check, dry-run of the guard, approvals and the decision log.
import { existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHostGuard, insecureTls } from './tripwire-guard.mjs';
import { analyze, GrantStore } from './tripwire-exec.mjs';
import { resolveConfig, setupChecks, openclawStateRoot, PLUGIN_ID } from './config.mjs';
import { readEvents } from './events.mjs';

const PACKAGE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MARK = { ok: '✓', warn: '!', error: '✗' };

// Commands that must be refused on every install; `status` runs them as a self-test.
export const SELF_TEST = [
  ['cat ~/.ssh/id_ed25519', true],
  ['cat ~/.openclaw/credentials/*.json', true],
  ["bash -c 'security find-generic-password -s x -w'", true],
  ['rm -rf ~', true],
  ['openclaw plugins disable tripwire', true],
  ['ls -la ~/Documents', false],
  ['git status', false],
];

export function context(openclawConfig = {}) {
  const raw = openclawConfig?.plugins?.entries?.[PLUGIN_ID]?.config ?? {};
  const stateRoot = openclawStateRoot();
  const settings = resolveConfig(raw, { stateRoot });
  const guard = createHostGuard({
    openclawRoots: [stateRoot], openclawConfigPath: process.env.OPENCLAW_CONFIG_PATH,
    pluginDirs: [PACKAGE_ROOT], stateDir: settings.dataDir,
    secretPaths: settings.hostGuard.secretPaths, protectedPaths: settings.hostGuard.protectedPaths, keepFolders: settings.hostGuard.keepFolders,
    protectOpenClawConfig: settings.hostGuard.protectOpenClawConfig, protectPluginFiles: settings.hostGuard.protectPluginFiles,
  });
  return { settings, guard };
}

export function statusReport(openclawConfig = {}) {
  const { settings, guard } = context(openclawConfig);
  const checks = setupChecks(openclawConfig, settings);
  const failures = SELF_TEST.filter(([cmd, shouldBlock]) => Boolean(guard.verdict('exec', { command: cmd })) !== shouldBlock).map(([cmd]) => cmd);
  checks.push(failures.length ? { level: 'error', text: `Self-test failed for: ${failures.join(' | ')}` } : { level: 'ok', text: `Self-test passed (${SELF_TEST.length} sample commands).` });
  const grants = existsSync(settings.grantsFile) ? new GrantStore(settings.grantsFile).list().length : 0;
  const events = readEvents(settings.eventsFile, { limit: 1000 });
  const dayAgo = Date.now() - 86_400_000;
  const recent = events.filter(e => Date.parse(e.ts) >= dayAgo);
  const count = type => recent.filter(e => e.type === type).length;
  return {
    ok: !checks.some(c => c.level === 'error'),
    checks,
    dataDir: settings.dataDir,
    grants,
    last24h: { blocked: count('blocked'), budgetBlocked: count('budget_blocked'), approvalsAsked: count('exec_ask') + count('guard_ask') },
  };
}

export function testCommand(openclawConfig, command, { cwd, tool = 'exec' } = {}) {
  const { settings, guard } = context(openclawConfig);
  const params = tool === 'exec' ? { command, ...(cwd ? { workdir: cwd } : {}) } : { path: command };
  if (tool === 'exec' && settings.hostGuard.blockInsecureTls && insecureTls('exec', params)) return { decision: 'block', by: 'host guard', rule: 'insecure-tls', reason: 'Switching off TLS certificate checks is not allowed.' };
  const v = guard.verdict(tool, params);
  if (v) {
    const ask = v.askable && settings.execApproval.enabled;
    return { decision: ask ? 'ask-once' : 'block', by: 'host guard', rule: v.rule, reason: v.reason, ...(v.selfEscalation ? { selfEscalation: true } : {}) };
  }
  if (tool !== 'exec') return { decision: 'allow', by: 'host guard', reason: 'No guard rule matches this path.' };
  if (!settings.execApproval.enabled) return { decision: 'allow', by: 'host guard', reason: 'No guard rule matches. Exec approval is off.' };
  const a = analyze(command, { readOnlyCommands: settings.execApproval.readOnlyCommands });
  if (a.readOnly) return { decision: 'allow', by: 'exec approval', reason: 'Read-only command.' };
  const grant = existsSync(settings.grantsFile) ? new GrantStore(settings.grantsFile).covers(a) : null;
  if (grant) return { decision: 'allow', by: 'exec approval', reason: `Covered by an "allow always" grant (${grant}).` };
  return settings.execApproval.mode === 'ask'
    ? { decision: 'ask', by: 'exec approval', reason: 'Not read-only and not granted: the owner is asked.', alwaysRule: a.rules ?? 'exact command only' }
    : { decision: 'review', by: 'exec approval', reason: 'Not read-only and not granted: the review model decides, and asks the owner if unsure.', alwaysRule: a.rules ?? 'exact command only' };
}

export function registerTripwireCli(program, { config } = {}) {
  const root = program.command('tripwire').description('Check Tripwire setup, test commands against the guard, manage approvals');
  const print = (json, value, human) => { if (json) console.log(JSON.stringify(value, null, 2)); else human(value); };

  root.command('status').description('Check the setup and run the guard self-test').option('--json', 'Print JSON').action(opts => {
    const r = statusReport(config);
    print(opts.json, r, () => {
      for (const c of r.checks) console.log(`${MARK[c.level]} ${c.text}`);
      console.log(`\nState folder: ${r.dataDir}`);
      console.log(`Allow-always grants: ${r.grants}`);
      console.log(`Last 24 h: ${r.last24h.blocked} blocked by the guard, ${r.last24h.budgetBlocked} stopped by the budget, ${r.last24h.approvalsAsked} approvals asked.`);
    });
    if (!r.ok) process.exitCode = 1;
  });

  root.command('test').description('Show what Tripwire would do with a command (nothing is run)')
    .argument('<command...>', 'The shell command, or a path with --tool read/write')
    .option('--cwd <dir>', 'Working directory of the command')
    .option('--tool <name>', 'Tool to simulate: exec (default), read, write, edit, delete', 'exec')
    .option('--json', 'Print JSON')
    .action((parts, opts) => {
      const r = testCommand(config, parts.join(' '), { cwd: opts.cwd, tool: opts.tool });
      print(opts.json, r, () => {
        console.log(`${r.decision.toUpperCase()}  (${r.by}${r.rule ? `, rule ${r.rule}` : ''})`);
        console.log(r.reason);
        if (r.alwaysRule) console.log(`"Allow always" would remember: ${Array.isArray(r.alwaysRule) ? r.alwaysRule.join(', ') : r.alwaysRule}`);
      });
    });

  const grants = root.command('grants').description('List or remove "allow always" exec grants');
  const store = () => new GrantStore(context(config).settings.grantsFile);
  grants.command('list').option('--json', 'Print JSON').action(opts => {
    const list = store().list();
    print(opts.json, list, l => { if (!l.length) console.log('No grants.'); for (const g of l) console.log(`${g.kind.padEnd(6)} ${g.value}   (${g.addedAt})`); });
  });
  grants.command('remove').argument('<value>', 'Grant value exactly as listed').action(value => {
    const n = store().remove(value);
    console.log(n ? `Removed ${n} grant(s).` : 'No grant with that value.');
    if (!n) process.exitCode = 1;
  });
  grants.command('clear').description('Remove every grant').action(() => { store().clear(); console.log('All grants removed.'); });

  root.command('log').description('Show recent decisions from the local log').option('-n, --limit <n>', 'How many', '20').option('--json', 'Print JSON').action(opts => {
    const events = readEvents(context(config).settings.eventsFile, { limit: Number(opts.limit) || 20 });
    print(opts.json, events, list => {
      if (!list.length) console.log('No decisions logged yet.');
      for (const e of list) console.log(`${e.ts}  ${e.type.padEnd(16)} ${e.rule ?? e.kind ?? e.decision ?? ''}  ${e.tool ?? ''} ${e.command ? `$ ${e.command}` : e.path ?? ''}`.trimEnd());
    });
  });
  return root;
}
