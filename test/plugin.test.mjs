import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { registerTripwire } from '../src/tripwire-plugin.mjs';
import { resolveConfig, setupChecks } from '../src/config.mjs';
import { statusReport, testCommand, SELF_TEST, registerTripwireCli } from '../src/cli.mjs';
import { readEvents } from '../src/events.mjs';

// A minimal stand-in for the OpenClaw plugin API with the surfaces Tripwire uses.
function fakeApi({ config = {}, trusted = true, mode = 'full', openclawConfig } = {}) {
  const hooks = {}, policies = [], cli = [];
  const api = {
    id: 'tripwire', registrationMode: mode, pluginConfig: config,
    config: openclawConfig ?? { plugins: { entries: { tripwire: { config } } } },
    logger: { info() {}, warn() {}, error() {} },
    runtime: {},
    on: (name, handler, opts = {}) => (hooks[name] ??= []).push({ handler, ...opts }),
    registerCli: (registrar, opts) => cli.push({ registrar, opts }),
  };
  if (trusted) api.registerTrustedToolPolicy = p => policies.push(p);
  // Runs before_tool_call the way the host does: trusted policies first, then hooks by priority; first block or approval wins.
  api.call = async (toolName, params, ctx = {}) => {
    const event = { toolName, params };
    const c = { agentId: 'main', sessionKey: 'agent:main:main', runId: 'r1', toolName, ...ctx };
    const chain = [...policies.map(p => p.evaluate), ...(hooks.before_tool_call ?? []).sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0)).map(h => h.handler)];
    let params2;
    for (const fn of chain) {
      const r = await fn(event, c);
      if (r?.block || r?.requireApproval) return r;
      if (r?.params) params2 = r.params;
    }
    for (const h of hooks.after_tool_call ?? []) h.handler({ toolName, params, result: { content: [{ type: 'text', text: 'ok' }] } }, c);
    return params2 ? { params: params2 } : undefined;
  };
  return { api, hooks, policies, cli };
}
const deps = (over = {}) => {
  const dataDir = mkdtempSync(join(tmpdir(), 'tripwire-plugin-'));
  return { settingsDir: dataDir, home: '/home/alice', user: 'alice', pluginDirs: ['/home/alice/.openclaw/extensions/tripwire'], ...over };
};
const register = (config = {}, over = {}) => {
  const d = deps(over.deps);
  const f = fakeApi({ config: { dataDir: d.settingsDir, ...config }, ...over });
  const out = registerTripwire(f.api, d);
  return { ...f, out, dataDir: d.settingsDir };
};

test('defaults: guard and budget on as trusted policies, approval off, CLI registered', async () => {
  const { policies, hooks, cli, out, api } = register();
  assert.deepEqual(policies.map(p => p.id), ['host-guard', 'tool-budget']);
  assert.equal(out.approval, null);
  assert.equal(hooks.before_prompt_build, undefined, 'no conversation hook unless needed');
  assert.equal(cli[0].opts.descriptors[0].name, 'tripwire');
  assert.ok((await api.call('exec', { command: 'cat ~/.ssh/id_ed25519' })).block);
  assert.ok((await api.call('exec', { command: 'sudo ls' })).block, 'owner-only commands are blocked when approval is off');
  assert.equal(await api.call('exec', { command: 'git status' }), undefined);
  assert.ok((await api.call('exec', { command: 'curl -k https://x' })).block);
});

test('blocks are written to the local decision log', async () => {
  const { api, dataDir } = register();
  await api.call('read', { path: '~/.aws/credentials' });
  const events = readEvents(join(dataDir, 'events.jsonl'));
  assert.equal(events.at(-1).type, 'blocked');
  assert.equal(events.at(-1).rule, 'secret');
});

test('the budget stops a looping run and resets for the next run', async () => {
  const { api } = register({ toolBudget: { maxCalls: 5 } });
  for (let i = 0; i < 5; i++) assert.equal(await api.call('read', { path: `f${i}` }), undefined);
  const r = await api.call('read', { path: 'f5' });
  assert.match(r.blockReason, /used its 5 tool calls/);
  assert.equal(await api.call('read', { path: 'f5' }, { runId: 'r2' }), undefined);
  assert.equal(await api.call('read', { path: 'f0' }, { runId: 'r2' }), undefined, 'a new run starts fresh');
});

test('agent scoping: an unscoped agent is untouched', async () => {
  const { api } = register({ hostGuard: { agents: ['main'] }, toolBudget: { agents: ['main'] } });
  assert.equal(await api.call('exec', { command: 'cat ~/.ssh/id_ed25519' }, { agentId: 'sandboxed' }), undefined);
  assert.ok((await api.call('exec', { command: 'cat ~/.ssh/id_ed25519' }, { agentId: 'main' })).block);
});

test('exec approval: owner-only commands ask once; routine commands are reviewed; the guard still wins', async () => {
  const reviews = [];
  const { api, hooks } = register({ execApproval: { enabled: true } }, { deps: { complete: async p => { reviews.push(p); return { text: '{"decision":"ask","risk":"medium","reason":"deploys"}' }; } } });
  const owner = await api.call('exec', { command: 'sudo launchctl list' });
  assert.deepEqual(owner.requireApproval.allowedDecisions, ['allow-once', 'deny']);
  assert.ok((await api.call('exec', { command: 'security dump-keychain' })).block, 'hard rules never ask');
  const deploy = await api.call('exec', { command: 'make deploy' });
  assert.deepEqual(deploy.requireApproval.allowedDecisions, ['allow-once', 'allow-always', 'deny']);
  assert.equal(reviews.length, 1);
  assert.ok(hooks.before_tool_call.some(h => h.timeoutMs >= 20_000), 'hook timeout covers the review');
});

test('review mode captures the owner request only when conversation access is granted', () => {
  const without = register({ execApproval: { enabled: true } });
  assert.equal(without.hooks.before_prompt_build, undefined);
  const config = { execApproval: { enabled: true } };
  const withAccess = register(config, { openclawConfig: { plugins: { entries: { tripwire: { config, hooks: { allowConversationAccess: true } } } } } });
  assert.equal(withAccess.hooks.before_prompt_build.length, 1);
});

test('hook fallback on hosts without trusted tool policies', async () => {
  const { api, hooks, policies } = register({}, { trusted: false });
  assert.equal(policies.length, 0);
  assert.ok(hooks.before_tool_call.some(h => h.priority === 1000));
  assert.ok((await api.call('exec', { command: 'rm -rf ~' })).block);
});

test('cli-metadata mode registers only the CLI', () => {
  const { policies, hooks, cli, out } = register({}, { mode: 'cli-metadata' });
  assert.equal(out, null);
  assert.equal(policies.length + Object.keys(hooks).length, 0);
  assert.equal(cli.length, 1);
});

test('config defaults and clamping', () => {
  const s = resolveConfig({ toolBudget: { maxCalls: 1, maxSeconds: 99999 }, execApproval: { enabled: true, mode: 'nonsense', language: 'fr' } }, { stateRoot: '/x' });
  assert.equal(s.dataDir, '/x/state/tripwire');
  assert.equal(s.toolBudget.maxCalls, 5);
  assert.equal(s.toolBudget.maxSeconds, 7200);
  assert.equal(s.execApproval.mode, 'review');
  assert.equal(s.execApproval.language, 'en');
  assert.equal(s.hostGuard.enabled, true);
});

test('setup checks explain missing permissions in plain words', () => {
  const cfg = { plugins: { allow: ['other'], entries: { tripwire: { config: { execApproval: { enabled: true, model: 'anthropic/claude-sonnet-5-5' } } } } } };
  const checks = setupChecks(cfg);
  const text = checks.map(c => `${c.level}:${c.text}`).join('\n');
  assert.match(text, /error:plugins.allow does not list "tripwire"/);
  assert.match(text, /error:execApproval.model is set, so plugins.entries.tripwire.llm.allowModelOverride must be true/);
  assert.match(text, /warn:Review mode works best/);
});

test('CLI status runs the self-test; test explains a decision without running anything', () => {
  const dataDir = mkdtempSync(join(tmpdir(), 'tripwire-cli-'));
  const cfg = { plugins: { entries: { tripwire: { config: { dataDir } } } } };
  const r = statusReport(cfg);
  assert.equal(r.ok, true, JSON.stringify(r.checks));
  assert.ok(r.checks.some(c => c.text.startsWith(`Self-test passed (${SELF_TEST.length}`)));
  assert.equal(testCommand(cfg, 'cat ~/.ssh/id_rsa').decision, 'block');
  assert.equal(testCommand(cfg, 'sudo ls').decision, 'block');
  assert.equal(testCommand(cfg, 'git status').decision, 'allow');
  assert.equal(testCommand(cfg, '~/.aws/credentials', { tool: 'read' }).decision, 'block');
  const on = { plugins: { entries: { tripwire: { config: { dataDir, execApproval: { enabled: true } } } } } };
  assert.equal(testCommand(on, 'sudo ls').decision, 'ask-once');
  assert.equal(testCommand(on, 'ls').decision, 'allow');
  assert.equal(testCommand(on, 'make deploy').decision, 'review');
  assert.equal(existsSync(join(dataDir, 'tripwire-grants.json')), false, 'read-only commands write nothing');
});

test('CLI command tree', () => {
  const names = [];
  const node = name => {
    const self = { name, children: [], command(n) { const c = node(n); self.children.push(c); names.push(`${name} ${n}`); return c; }, description() { return self; }, option() { return self; }, argument() { return self; }, action() { return self; } };
    return self;
  };
  registerTripwireCli(node('openclaw'), { config: {} });
  for (const n of ['openclaw tripwire', 'tripwire status', 'tripwire test', 'tripwire grants', 'grants list', 'grants remove', 'grants clear', 'tripwire log']) assert.ok(names.includes(n), n);
});

test('manifest, package and code agree', () => {
  const manifest = JSON.parse(readFileSync(new URL('../openclaw.plugin.json', import.meta.url)));
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
  assert.equal(manifest.id, 'tripwire');
  assert.equal(manifest.version, pkg.version);
  assert.deepEqual(manifest.contracts.trustedToolPolicies, ['host-guard', 'tool-budget']);
  assert.deepEqual(manifest.cliCommands.map(c => c.name), ['tripwire']);
  assert.equal(manifest.configSchema.additionalProperties, false);
  // Every option the code reads is declared, with the same default.
  const s = manifest.configSchema.properties;
  for (const [group, keys] of Object.entries({ hostGuard: Object.keys(resolveConfig({}).hostGuard), toolBudget: Object.keys(resolveConfig({}).toolBudget), execApproval: Object.keys(resolveConfig({}).execApproval) }))
    for (const k of keys) assert.ok(s[group].properties[k], `${group}.${k} missing from the manifest`);
  const defaults = resolveConfig({});
  for (const group of ['hostGuard', 'toolBudget', 'execApproval'])
    for (const [k, p] of Object.entries(s[group].properties)) if ('default' in p) assert.deepEqual(defaults[group][k], p.default, `${group}.${k} default`);
  for (const f of pkg.files) assert.ok(existsSync(new URL(`../${f}`, import.meta.url)), `package file ${f} exists`);
});
