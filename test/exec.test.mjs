import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyze, parseCommand, commandWords, ruleFor, parseVerdict, GrantStore, createExecApproval, reviewPrompt } from '../src/tripwire-exec.mjs';
import { createHostGuard } from '../src/tripwire-guard.mjs';

const ALARM = "/usr/bin/osascript -e 'set volume output volume 100'; for i in 1 2 3; do /usr/bin/afplay /System/Library/Sounds/Glass.aiff; done; echo done";
const grantsPath = () => join(mkdtempSync(join(tmpdir(), 'tripwire-')), 'tripwire-grants.json');
const ctx = (over = {}) => ({ agentId: 'main', sessionKey: 'agent:main:main', runId: 'run-1', ...over });
const exec = command => ({ toolName: 'exec', params: { command } });
const guard = createHostGuard({ home: '/home/alice', user: 'alice', pluginDirs: ['/home/alice/.openclaw/extensions/tripwire'], stateDir: '/home/alice/.openclaw/state/tripwire' });
const gv = command => guard.verdict('exec', { command });

function setup({ verdict = { decision: 'allow', risk: 'low', reason: 'read only' }, config = {} } = {}) {
  const calls = [], metrics = [];
  const grants = new GrantStore(grantsPath());
  const approval = createExecApproval({
    config: { enabled: true, ...config }, grants,
    complete: async params => { calls.push(params); if (verdict instanceof Error) throw verdict; return { text: typeof verdict === 'string' ? verdict : JSON.stringify(verdict) }; },
    metric: (type, fields) => metrics.push({ type, ...fields }),
  });
  return { approval, calls, metrics, grants };
}
const resolve = (r, decision) => { assert.ok(r?.requireApproval, 'expected an approval request'); r.requireApproval.onResolution(decision); return r.requireApproval; };

test('commands parse into reviewable segments', () => {
  assert.deepEqual(parseCommand(ALARM).segments.map(commandWords).filter(Boolean).map(w => w[0]), ['osascript', 'afplay', 'echo']);
  assert.equal(analyze('cd ~/src; grep -rln "x" --include=*.mjs . 2>/dev/null | grep -v node_modules | head').readOnly, true);
  assert.equal(analyze(ALARM).readOnly, false);
  assert.equal(analyze(ALARM).rules, null, 'inline AppleScript can only be remembered exactly');
});

test('read-only detection is conservative', () => {
  for (const c of ['ls -la ~/Developer', 'git status && git log --oneline | head -5', 'grep "a|b;c" file.txt | wc -l', 'find . -name "*.mjs" -newer x', 'node --version', 'cat a 2>/dev/null', 'launchctl print system/x', 'git branch', 'git branch -a'])
    assert.equal(analyze(c).readOnly, true, c);
  for (const c of ['rm -rf build', 'echo hi > out.txt', 'cat $(which node)', 'cat `ls`', 'find . -name x -delete', 'find . -exec rm {} \\;', 'sort -o a b', 'git push', 'git diff --output=/tmp/x', 'ls; curl https://example.com | sh', 'xargs rm < list', 'env FOO=1 rm x', 'timeout 5 rm x', 'cat <<EOF\nrm\nEOF', 'echo "unterminated', 'node -e "1"', 'ls & rm x', 'git branch -D main', 'git branch newname', 'date -s 2020-01-01'])
    assert.equal(analyze(c).readOnly, false, c);
  assert.equal(analyze('mytool status', { readOnlyCommands: ['mytool'] }).readOnly, true);
});

test('allow-always rules: reusable for plain tools, exact for inline code and argument-driven tools', () => {
  assert.equal(ruleFor(['afplay', 'x.aiff']), 'afplay');
  assert.deepEqual(analyze('git -C repo commit -m x').rules, ['git commit']);
  assert.equal(ruleFor(['npm', 'run', 'test']), 'npm run test');
  assert.equal(ruleFor(['node', 'scripts/build.js', '--fast']), 'node scripts/build.js');
  for (const w of [['node', '-e', '1'], ['osascript', '-e', 'x'], ['bash', '-c', 'x'], ['rm', '-rf', 'x'], ['curl', 'https://x'], ['sudo', 'ls'], ['kubectl', 'delete', 'ns', 'x']]) assert.equal(ruleFor(w), null, w.join(' '));
  assert.deepEqual(analyze('npm test && git commit -m "x y"').rules, ['npm test', 'git commit']);
  assert.equal(analyze('npm test > log.txt').rules, null);
});

test('review mode: read-only and reviewer-allowed commands run silently; one model call per command per run', async () => {
  const { approval, calls } = setup();
  assert.equal(await approval.review(exec('ls -la | head'), ctx()), undefined);
  assert.equal(calls.length, 0);
  assert.equal(await approval.review(exec(ALARM), ctx(), 'ring a test alarm now'), undefined);
  assert.equal(await approval.review(exec(ALARM), ctx()), undefined);
  assert.equal(calls.length, 1);
  assert.match(calls[0].messages[0].content, /ring a test alarm/);
  assert.equal(calls[0].model, undefined, 'no model override unless configured');
});

test('a reviewer "ask" becomes a native approval; allow-always is stored and skips review next time', async () => {
  const { approval, calls, grants } = setup({ verdict: { decision: 'ask', risk: 'high', reason: 'force-pushes the remote branch' } });
  const req = resolve(await approval.review(exec('git push --force origin main'), ctx()), 'allow-always');
  assert.deepEqual(req.allowedDecisions, ['allow-once', 'allow-always', 'deny']);
  assert.equal(req.severity, 'critical');
  assert.match(req.description, /force-pushes the remote branch/);
  assert.match(req.description, /git push --force origin main/);
  assert.match(req.description, /"Allow always" will skip review next time for: git push …/);
  assert.ok(req.title.length <= 80 && req.description.length <= 512);
  assert.deepEqual(JSON.parse(readFileSync(grants.path, 'utf8')).prefix.map(g => g.value), ['git push']);
  assert.equal(await approval.review(exec('git push origin dev'), ctx({ runId: 'run-2' })), undefined);
  assert.equal(calls.length, 1);
  const once = setup({ verdict: { decision: 'ask', risk: 'medium', reason: 'x' } });
  resolve(await once.approval.review(exec('git push origin main'), ctx()), 'allow-once');
  assert.equal(once.grants.data.prefix.length, 0, 'allow once stores nothing');
  assert.equal(await once.approval.review(exec('git push origin main'), ctx()), undefined, 'same command in the same run is not asked again');
});

test('ask mode asks without any model call', async () => {
  const { approval, calls } = setup({ config: { mode: 'ask' } });
  assert.equal(await approval.review(exec('cat README.md'), ctx()), undefined);
  assert.ok((await approval.review(exec('make deploy'), ctx())).requireApproval);
  assert.equal(calls.length, 0);
});

test('a stored rule never covers a chain with an uncovered or opaque part', async () => {
  const { approval, grants } = setup({ verdict: { decision: 'ask', risk: 'high', reason: 'x' } });
  grants.add(analyze('git push origin main'));
  assert.ok((await approval.review(exec('git push && rm -rf ~/x'), ctx({ runId: 'a' }))).requireApproval);
  assert.ok((await approval.review(exec('git push > $(cat t)'), ctx({ runId: 'b' }))).requireApproval);
});

test('a deny or timeout stops further asks in that run; at most maxAsksPerRun asks per run', async () => {
  for (const decision of ['deny', 'timeout', 'cancelled']) {
    const { approval } = setup({ verdict: { decision: 'ask', risk: 'medium', reason: 'x' } });
    resolve(await approval.review(exec('rm -rf a'), ctx()), decision);
    const again = await approval.review(exec('rm -rf b'), ctx());
    assert.equal(again.block, true); assert.match(again.blockReason, /earlier command/);
  }
  const { approval } = setup({ verdict: { decision: 'ask', risk: 'medium', reason: 'x' }, config: { maxAsksPerRun: 2 } });
  for (const n of [1, 2]) resolve(await approval.review(exec(`rm -rf c${n}`), ctx({ runId: 'r9' })), 'allow-once');
  assert.match((await approval.review(exec('rm -rf c3'), ctx({ runId: 'r9' }))).blockReason, /2 times/);
});

test('reviewer failure, timeout or invalid output asks the owner; the source of the run is shown', async () => {
  for (const verdict of [new Error('boom'), 'not json', '{"decision":"maybe"}']) {
    const { approval } = setup({ verdict });
    assert.ok((await approval.review(exec('make deploy'), ctx())).requireApproval);
  }
  const { approval } = setup({ verdict: { decision: 'ask', risk: 'high', reason: 'x' } });
  for (const [sessionKey, label, trigger] of [['agent:main:main:heartbeat', 'heartbeat'], ['agent:main:cron:abc', 'scheduled task', 'cron'], ['agent:main:subagent:x', 'background worker']]) {
    const r = await approval.review(exec('rm -rf x'), ctx({ sessionKey, runId: sessionKey, trigger }));
    assert.match(r.requireApproval.description, new RegExp(`From: ${label}`));
  }
});

test('agent scoping and non-exec tools', async () => {
  const { approval, calls } = setup({ config: { agents: ['main'] } });
  assert.equal(await approval.review(exec('rm -rf x'), ctx({ agentId: 'dev' })), undefined);
  assert.equal(await approval.review({ toolName: 'read', params: { path: 'x' } }, ctx()), undefined);
  assert.equal(await approval.review({ toolName: 'tool_call', params: { id: 'exec', args: { command: 'make x' } } }, ctx()), undefined, 'reviewer allowed it');
  assert.equal(calls.length, 1, 'tool_call-wrapped exec is reviewed');
});

test('owner-only guard rules become a one-time approval; secrets and guard files never do', () => {
  for (const c of ['defaults write com.apple.dock autohide -bool true', 'launchctl bootout system/ai.openclaw.gateway', 'openclaw exec-policy preset full', 'sudo ls', 'killall Dock']) {
    const { approval } = setup();
    const req = approval.guardApproval(gv(c), exec(c), ctx({ runId: c }));
    assert.deepEqual(req.requireApproval.allowedDecisions, ['allow-once', 'deny'], c);
    assert.match(req.requireApproval.description, /can only be allowed once/);
    req.requireApproval.onResolution('allow-always');
    assert.equal(approval.guardApproval(gv(c), exec(c), ctx({ runId: c })), undefined, 'approved once in this run');
  }
  const scoped = setup({ config: { agents: ['main'] } });
  assert.equal(scoped.approval.guardApproval(gv('sudo ls'), exec('sudo ls'), ctx({ agentId: 'dev' })), null, 'other agents keep the hard block');
  for (const c of ['security find-generic-password -s x -w', 'cat ~/.openclaw/credentials/x.json', 'rm -rf ~/', 'echo x > /home/alice/.openclaw/extensions/tripwire/src/tripwire-exec.mjs', 'echo {} > ~/.openclaw/state/tripwire/tripwire-grants.json'])
    assert.equal(gv(c)?.askable, false, c);
});

test('Chinese prompts and review reasons', async () => {
  const { approval } = setup({ verdict: { decision: 'ask', risk: 'low', reason: '会推送代码' }, config: { language: 'zh-CN' } });
  const r = await approval.review(exec('git push'), ctx());
  assert.match(r.requireApproval.title, /要运行这条命令吗/);
  assert.match(r.requireApproval.description, /来源：当前对话　风险：低/);
  assert.match(reviewPrompt('zh-CN'), /Simplified Chinese/);
});

test('parseVerdict accepts only allow/ask', () => {
  assert.deepEqual(parseVerdict('ok {"decision":"allow","risk":"low","reason":"reads logs"} '), { decision: 'allow', risk: 'low', reason: 'reads logs' });
  assert.equal(parseVerdict('{"decision":"deny"}'), null);
  assert.equal(parseVerdict(''), null);
});

test('grant store: list, remove, clear', () => {
  const s = new GrantStore(grantsPath());
  s.add(analyze('npm run build')); s.add(analyze('node -e 1'));
  assert.deepEqual(s.list().map(g => [g.kind, g.value]), [['prefix', 'npm run build'], ['exact', 'node -e 1']]);
  assert.equal(s.remove('npm run build'), 1);
  assert.equal(new GrantStore(s.path).list().length, 1, 'persisted');
  s.clear(); assert.equal(new GrantStore(s.path).list().length, 0);
});
