import test from 'node:test';
import assert from 'node:assert/strict';
import { ToolBudget, BudgetRegistry } from '../src/tripwire-budget.mjs';

test('a changed title or key order cannot bypass repeat detection', () => {
  const b = new ToolBudget();
  assert.equal(b.inspect('read', { path: 'a', title: 'first' }), null);
  assert.equal(b.inspect('read', { title: 'different', path: 'a' }).block, true);
});

test('many different calls still hit the call budget', () => {
  const b = new ToolBudget({ maxCalls: 6 });
  for (let i = 0; i < 6; i++) assert.equal(b.inspect('read', { path: `file${i}` }), null);
  for (let i = 6; i < 30; i++) assert.equal(b.inspect('exec', { command: `different ${i}` }).kind, 'calls');
  assert.equal(b.calls, 6);
});

test('exec is left alone by default and capped only when configured', () => {
  assert.equal(new ToolBudget().inspect('exec', { command: 'sleep 999', timeoutSeconds: 999, background: true }), null);
  const r = new ToolBudget({ execCapSeconds: 8 }).inspect('exec', { command: 'sleep 999', timeoutSeconds: 999, background: true, yieldMs: 1 });
  assert.deepEqual([r.params.timeoutSeconds, r.params.background, r.params.yieldMs], [8, false, 8000]);
});

test('wrapper calls are not counted twice; tool time and failures close the run', () => {
  let clock = 0;
  const b = new ToolBudget({ now: () => clock, maxMs: 20000 });
  assert.equal(b.inspect('tool_call', {}), null);
  assert.equal(b.inspect('read', { path: 'a' }), null);
  clock = 20001;
  assert.equal(b.inspect('ls', {}).kind, 'time');
  const f = new ToolBudget({ maxFailures: 2 });
  f.observe({ isError: true }, 'read'); f.observe('Unexpected token < is not valid JSON', 'exec');
  assert.equal(f.inspect('read', { path: 'next' }).kind, 'failures');
});

test('model thinking time does not use the tool-time budget', () => {
  let clock = 0;
  const b = new ToolBudget({ now: () => clock, maxMs: 20000 });
  b.inspect('read', { path: 'a' }); clock = 20; b.observe({ ok: true }, 'read');
  clock = 60000;
  assert.equal(b.inspect('read', { path: 'b' }), null);
  clock = 60050; b.observe({ ok: true }, 'read');
  assert.equal(b.activeMs, 70);
});

test('a re-read or test re-run after a successful edit is allowed; identical edits stay repeats', () => {
  const b = new ToolBudget();
  b.inspect('read', { path: 'a' });
  assert.equal(b.inspect('edit', { path: 'a', old: '1', new: '2' }), null); b.observe({ ok: true }, 'edit');
  assert.equal(b.inspect('read', { path: 'a' }), null);
  assert.equal(b.inspect('edit', { path: 'a', old: '1', new: '2' }).kind, 'repeat');
  const t = new ToolBudget({ maxFailures: 4 });
  const run = { command: 'node --test a.test.mjs' };
  t.inspect('exec', run); t.observe({ content: [{ type: 'text', text: 'not ok 1' }] }, 'exec');
  assert.equal(t.inspect('exec', run).kind, 'repeat');
  t.inspect('edit', { path: 'a.mjs' }); t.observe({ isError: true }, 'edit');
  assert.equal(t.inspect('exec', run).kind, 'repeat', 'a failed edit changes nothing');
  t.inspect('edit', { path: 'a.mjs', v: 2 }); t.observe({ ok: true }, 'edit');
  assert.equal(t.inspect('exec', run), null);
});

test('refuseRepeats=false turns repeat detection off', () => {
  const b = new ToolBudget({ dedupe: false });
  assert.equal(b.inspect('read', { path: 'a' }), null);
  assert.equal(b.inspect('read', { path: 'a' }), null);
});

test('untimed tools neither use nor are refused by the time budget', () => {
  let t = 0;
  const b = new ToolBudget({ now: () => t, maxMs: 20000, untimed: ['slow_login'] });
  assert.equal(b.inspect('slow_login', { mode: 'status' }), null);
  t += 90000; b.observe({ ok: true }, 'slow_login');
  assert.equal(b.inspect('slow_login', { mode: 'recover' }), null);
  assert.equal(b.inspect('read', { path: 'x' }), null);
});

test('a successful recovery tool forgives one failure and lets the failed call run once more', () => {
  const b = new ToolBudget({ recovery: ['site_login'] });
  const q = { kind: 'grades' };
  b.inspect('portal_query', q); b.observe({ content: [{ type: 'text', text: 'portal_query failed: HTTP 403' }] }, 'portal_query');
  assert.equal(b.failures, 1);
  b.inspect('site_login', { site: 'portal' }); b.observe({ content: [{ type: 'text', text: '{"outcome":"signed_in"}' }] }, 'site_login');
  assert.equal(b.failures, 0);
  assert.equal(b.inspect('portal_query', q), null);
  assert.equal(b.inspect('portal_query', q).kind, 'repeat');
  const c = new ToolBudget({ recovery: ['site_login'] });
  c.inspect('portal_query', q); c.observe({ isError: true }, 'portal_query');
  c.inspect('site_login', {}); c.observe({ isError: true }, 'site_login');
  assert.equal(c.inspect('portal_query', q).kind, 'repeat', 'a failed recovery reopens nothing');
});

test('identical process waits are counted, not refused', () => {
  const b = new ToolBudget({ maxCalls: 4 });
  const wait = { action: 'poll', sessionId: 's1' };
  for (let i = 0; i < 4; i++) assert.equal(b.inspect('process', wait), null);
  assert.equal(b.inspect('process', wait).kind, 'calls');
});

test('failure text inside a good read is not a failure; raw command output and explicit errors are', () => {
  const b = new ToolBudget();
  const log = { content: [{ type: 'text', text: 'ERROR: command not found; No such file or directory' }] };
  for (const p of ['a.log', 'b.log']) { b.inspect('read', { path: p }); b.observe(log, 'read'); }
  assert.equal(b.failures, 0);
  const e = new ToolBudget({ maxFailures: 10 });
  e.observe({ content: [{ type: 'text', text: 'zsh: command not found: foo' }] }, 'exec');
  e.observe({ content: [{ type: 'text', text: 'x' }], details: { ok: false } }, 'read');
  e.observe({ isError: true }, 'memory_search');
  e.observe({ content: [{ type: 'text', text: 'my_tool failed: timeout' }] }, 'my_tool');
  e.observe({ ok: true }, 'read', 'tool threw');
  assert.equal(e.failures, 5);
});

test('the registry keeps one budget per run and stays bounded', () => {
  let made = 0;
  const r = new BudgetRegistry(() => { made++; return new ToolBudget(); }, { limit: 3 });
  assert.equal(r.get(undefined), null);
  const a = r.get('a'); assert.equal(r.get('a'), a);
  for (const id of ['b', 'c', 'd']) r.get(id);
  assert.equal(r.peek('a'), null, 'oldest run evicted');
  assert.equal(made, 4);
});
