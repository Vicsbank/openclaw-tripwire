// A scripted OpenAI-compatible model for end-to-end tests. No network, no keys.
//
// The user message is a script, one step per line:
//   CALL <tool> <json args>     the model calls that tool
//   SAY <text>                  the model answers with text (ends the turn)
// After each tool result the model moves on to the next line. The final answer
// is "RESULTS:" followed by every tool result it received, so the test can see
// exactly what each tool returned (or that Tripwire blocked it).
//
// It also answers Tripwire's exec reviewer: allow, unless the command contains DANGER.
//
//   node test/e2e/mock-model.mjs [port]      (default 18999)
import { createServer } from 'node:http';

const port = Number(process.argv[2] ?? 18999);
const MODEL = 'scripted';
const text = c => (typeof c === 'string' ? c : Array.isArray(c) ? c.map(p => p?.text ?? '').join('') : '');

function nextStep(messages) {
  // Tripwire's exec reviewer: allow, unless the command contains the word DANGER.
  if (messages.some(m => m.role === 'system' && /You review one shell command/.test(text(m.content)))) {
    const cmd = /<command>([\s\S]*?)<\/command>/.exec(text(messages.at(-1)?.content))?.[1] ?? '';
    return { say: JSON.stringify(/DANGER/.test(cmd) ? { decision: 'ask', risk: 'high', reason: 'mock reviewer: dangerous' } : { decision: 'allow', risk: 'low', reason: 'mock reviewer: fine' }) };
  }
  // OpenClaw can add context messages after the request; use the latest user message that holds a script.
  const steps = m => text(m.content).split('\n').map(l => /\b(?:CALL|SAY)\b.*$/.exec(l)?.[0]).filter(Boolean);
  const lastUser = messages.findLastIndex(m => m.role === 'user' && steps(m).length);
  const script = lastUser < 0 ? [] : steps(messages[lastUser]);
  if (process.env.MOCK_DEBUG) console.error('[mock] steps:', script.length, 'roles:', messages.map(m => m.role).join(','));
  const results = lastUser < 0 ? [] : messages.slice(lastUser + 1).filter(m => m.role === 'tool').map(m => text(m.content));
  const step = script[results.length];
  if (!step || step.startsWith('SAY')) return { say: `${step ? step.slice(4) : 'done'}\nRESULTS:\n${results.map((r, i) => `[${i + 1}] ${r.replace(/\s+/g, ' ').slice(0, 400)}`).join('\n')}` };
  const m = /^CALL\s+(\S+)\s*(.*)$/.exec(step);
  return { call: { name: m[1], args: m[2] || '{}' }, n: results.length };
}

function sse(res, chunks) {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  for (const c of chunks) res.write(`data: ${JSON.stringify(c)}\n\n`);
  res.end('data: [DONE]\n\n');
}

createServer((req, res) => {
  let body = '';
  req.on('data', d => { body += d; });
  req.on('end', () => {
    if (req.url.endsWith('/models')) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ object: 'list', data: [{ id: MODEL, object: 'model', owned_by: 'test' }] })); }
    if (!req.url.endsWith('/chat/completions')) { res.writeHead(404); return res.end(); }
    const r = JSON.parse(body || '{}');
    const step = nextStep(r.messages ?? []);
    const id = `chatcmpl-${Date.now()}`, created = Math.floor(Date.now() / 1000);
    const base = { id, object: 'chat.completion.chunk', created, model: MODEL };
    const usage = { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 };
    const toolCall = step.call && { index: 0, id: `call_${step.n}_${Date.now()}`, type: 'function', function: { name: step.call.name, arguments: step.call.args } };
    if (r.stream) {
      const delta = step.call ? { role: 'assistant', tool_calls: [toolCall] } : { role: 'assistant', content: step.say };
      return sse(res, [
        { ...base, choices: [{ index: 0, delta, finish_reason: null }] },
        { ...base, choices: [{ index: 0, delta: {}, finish_reason: step.call ? 'tool_calls' : 'stop' }] },
        { ...base, choices: [], usage },
      ]);
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id, object: 'chat.completion', created, model: MODEL, usage, choices: [{ index: 0, finish_reason: step.call ? 'tool_calls' : 'stop', message: step.call ? { role: 'assistant', content: null, tool_calls: [toolCall] } : { role: 'assistant', content: step.say } }] }));
  });
}).listen(port, '127.0.0.1', () => console.log(`mock model on http://127.0.0.1:${port}/v1`));
