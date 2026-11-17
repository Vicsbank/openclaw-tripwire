// End-to-end test against a real OpenClaw install. Not part of `npm test`.
//
//   node test/e2e/run.mjs            (needs `openclaw` on PATH, 2026.11.3+)
//
// It packs this checkout with `npm pack`, installs the tarball into a fresh,
// throw-away OpenClaw profile exactly as a user would (npm-pack:), points the
// profile at a scripted local model (test/e2e/mock-model.mjs: no network, no
// keys, no cost), runs real agent turns with --local, checks what each tool
// call returned, and deletes the profile again. Your real ~/.openclaw is not touched.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const PROFILE = `tripwire-e2e-${process.pid}`;
const PROFILE_DIR = join(homedir(), `.openclaw-${PROFILE}`);
const PORT = 18000 + (process.pid % 1000);
const WORK = mkdtempSync(join(tmpdir(), 'tripwire-e2e-'));
const oc = (args, opts = {}) => {
  const r = spawnSync('openclaw', ['--profile', PROFILE, ...args], { encoding: 'utf8', cwd: WORK, timeout: 300_000, ...opts });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
};
const step = s => console.log(`\n▶ ${s}`);
let mock;

function editConfig(fn) {
  const f = join(PROFILE_DIR, 'openclaw.json');
  const c = JSON.parse(readFileSync(f, 'utf8'));
  fn(c);
  writeFileSync(f, JSON.stringify(c, null, 2));
}
function turn(name, lines) {
  const msg = join(WORK, `${name}.txt`);
  writeFileSync(msg, `${lines.join('\n')}\nSAY finished\n`);
  const out = oc(['agent', '--local', '--session-id', `${PROFILE}-${name}`, '--message-file', msg, '--timeout', '200']);
  const results = [...out.matchAll(/^\[(\d+)\] (.*)$/gm)].map(m => m[2]);
  if (!/finished/.test(out)) throw new Error(`turn ${name} did not finish:\n${out.slice(-2000)}`);
  return results;
}

try {
  step('pack');
  const tgz = spawnSync('npm', ['pack', '--pack-destination', WORK, '--silent'], { cwd: ROOT, encoding: 'utf8' }).stdout.trim().split('\n').at(-1);
  const tarball = join(WORK, tgz);
  assert.ok(existsSync(tarball), 'npm pack produced a tarball');

  step(`install into fresh profile ${PROFILE}`);
  const install = oc(['plugins', 'install', `npm-pack:${tarball}`, '--force', '--accept-capabilities']);
  assert.match(install, /Installed plugin: tripwire/, install);
  assert.match(oc(['tripwire', 'status']), /Self-test passed/);

  step('scripted model');
  mock = spawn(process.execPath, [join(ROOT, 'test/e2e/mock-model.mjs'), String(PORT)], { stdio: 'ignore' });
  await new Promise(r => setTimeout(r, 500));
  const secret = join(WORK, 'fake-secret.txt'), normal = join(WORK, 'normal.txt');
  writeFileSync(secret, 'FAKE-SECRET\n'); writeFileSync(normal, 'hello\n');
  const configure = execApproval => editConfig(c => {
    c.tools = { ...(c.tools ?? {}), profile: 'coding' };
    c.models = { providers: { vllm: { baseUrl: `http://127.0.0.1:${PORT}/v1`, api: 'openai-completions', apiKey: 'mock-not-a-secret', models: [{ id: 'scripted', name: 'Scripted', reasoning: false, input: ['text'], contextWindow: 128000, maxTokens: 4096, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } }] } } };
    c.agents = { ...(c.agents ?? {}), defaults: { ...(c.agents?.defaults ?? {}), model: { primary: 'vllm/scripted' } } };
    const e = c.plugins.entries.tripwire;
    e.hooks = { ...(e.hooks ?? {}), allowConversationAccess: true };
    e.config = { ...(e.config ?? {}), hostGuard: { secretPaths: [secret] }, ...(execApproval ? { execApproval } : {}) };
  });
  configure();

  step('host guard and budget in a real agent turn');
  const guide = join(PROFILE_DIR, 'npm/projects/openclaw-tripwire/node_modules/openclaw-tripwire/src/tripwire-guard.mjs');
  const r1 = turn('guard', [
    `CALL read {"path":"${normal}"}`,
    `CALL read {"path":"${secret}"}`,
    `CALL exec {"command":"cat ${secret} | base64"}`,
    'CALL exec {"command":"sudo -n true"}',
    'CALL exec {"command":"curl -k https://example.invalid"}',
    `CALL write {"path":"${join(PROFILE_DIR, 'openclaw.json')}","content":"{}"}`,
    `CALL edit {"path":"${guide}","oldText":"a","newText":"b"}`,
    'CALL exec {"command":"openclaw plugins disable tripwire"}',
    `CALL read {"path":"${normal}"}`,
  ]);
  assert.match(r1[0], /hello/);
  for (const i of [1, 2, 3, 4, 5, 6, 7]) assert.match(r1[i], /Tripwire host guard/, `call ${i + 1}: ${r1[i]}`);
  assert.match(r1[8], /Tripwire budget: this exact tool call already ran/);
  assert.ok(JSON.parse(readFileSync(join(PROFILE_DIR, 'openclaw.json'), 'utf8')).plugins, 'config was not overwritten');

  step('exec approval, ask mode, with one grant');
  configure({ enabled: true, mode: 'ask' });
  mkdirSync(join(PROFILE_DIR, 'state/tripwire'), { recursive: true });
  writeFileSync(join(PROFILE_DIR, 'state/tripwire/tripwire-grants.json'), JSON.stringify({ version: 1, exact: [], prefix: [{ value: 'touch', addedAt: new Date().toISOString() }] }));
  const r2 = turn('ask', [`CALL exec {"command":"ls ${WORK}"}`, `CALL exec {"command":"touch ${join(WORK, 'granted')}"}`, `CALL exec {"command":"echo x > ${join(WORK, 'ungranted')}"}`]);
  assert.match(r2[0], /normal\.txt/);
  assert.ok(existsSync(join(WORK, 'granted')), 'granted command ran');
  assert.match(r2[2], /approval unavailable|approval/i, r2[2]);
  assert.ok(!existsSync(join(WORK, 'ungranted')), 'unapproved command did not run');

  step('exec approval, review mode, through api.runtime.llm.complete');
  configure({ enabled: true, mode: 'review' });
  turn('review', [`CALL exec {"command":"echo routine > ${join(WORK, 'reviewed-ok')}"}`, `CALL exec {"command":"echo DANGER > ${join(WORK, 'reviewed-danger')}"}`]);
  assert.ok(existsSync(join(WORK, 'reviewed-ok')), 'reviewer allowed the routine command');
  assert.ok(!existsSync(join(WORK, 'reviewed-danger')), 'reviewer did not allow the dangerous one');

  console.log('\n✓ end-to-end: all checks passed');
} catch (error) {
  console.error(`\n✗ end-to-end failed: ${error?.stack ?? error}`);
  process.exitCode = 1;
} finally {
  mock?.kill();
  if (!process.env.KEEP_E2E) { rmSync(PROFILE_DIR, { recursive: true, force: true }); rmSync(WORK, { recursive: true, force: true }); }
  else console.log(`kept: ${PROFILE_DIR} and ${WORK}`);
}
