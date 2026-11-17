// Per-run tool budget: call count, active tool time, failures, and
// refusal of exact repeats. One ToolBudget instance covers one agent run.
//
// Why: a model that is stuck tends to loop — the same read, the same failing
// command, one more search. The budget turns that loop into a clear stop with
// a reason the model can act on, instead of a long silent burn.
import { createHash } from 'node:crypto';

const canonical = x => Array.isArray(x) ? x.map(canonical)
  : x && typeof x === 'object' ? Object.fromEntries(Object.keys(x).sort().filter(k => !['title', 'description'].includes(k)).map(k => [k, canonical(x[k])]))
  : x;

// Tools that only wrap or hand off another call; the wrapped call is checked itself.
const PASS_THROUGH = new Set(['tool_call', 'sessions_yield', 'sessions_spawn']);
// Output text is only a failure signal for tools that print raw command or page output.
const TEXT_FAILURE_TOOLS = new Set(['exec', 'bash', 'shell', 'process', 'web_fetch']);
const FAILURE_TEXT = /Unexpected token|not valid JSON|command not found|No such file|HTTP 40[134]|ENOTFOUND/;
// A re-read (or re-running the same test) after a successful edit is new evidence, not a repeat.
const REVISION_TOOLS = new Set(['read', 'ls', 'web_fetch', 'memory_search', 'memory_get', 'exec', 'bash', 'shell', 'process']);
const EDIT_TOOLS = new Set(['edit', 'write', 'apply_patch', 'multi_edit', 'file_write']);
// Each call to these is new evidence even with identical arguments (page or process state changes).
const DEFAULT_STATEFUL = ['browser', 'computer', 'process'];

export const BUDGET_DEFAULTS = Object.freeze({ maxCalls: 60, maxSeconds: 900, maxFailures: 8, execTimeoutCapSeconds: 0 });

export class ToolBudget {
  /**
   * maxCalls        tool calls per run
   * maxMs           active tool time per run (time spent inside tools, not model time)
   * maxFailures     failed tool calls per run
   * execCapSeconds  >0: every exec runs in the foreground with at most this timeout
   * stateful        tools whose identical calls are counted but never refused as repeats
   * untimed         slow tools with their own timeouts; their time does not count
   * recovery        sign-in / recovery tools; a success re-opens one retry of failed calls
   * dedupe          refuse exact repeats (default true)
   */
  constructor({ now = Date.now, maxCalls = BUDGET_DEFAULTS.maxCalls, maxMs = BUDGET_DEFAULTS.maxSeconds * 1000, maxFailures = BUDGET_DEFAULTS.maxFailures, execCapSeconds = 0, stateful = [], untimed = [], recovery = [], dedupe = true } = {}) {
    this.stateful = new Set([...DEFAULT_STATEFUL, ...stateful]);
    this.untimed = new Set(untimed);
    this.recovery = new Set(recovery);
    Object.assign(this, { now, maxCalls, maxMs, maxFailures, execCapSeconds, dedupe });
    this.seen = new Set();
    this.pending = new Map();
    this.calls = 0; this.blocked = 0; this.failures = 0; this.successes = 0;
    this.revision = 0; this.recoveries = 0; this.activeMs = 0;
  }

  usedMs() {
    return this.activeMs + [...this.pending].filter(([n]) => !this.untimed.has(n)).flatMap(([, v]) => v).reduce((sum, start) => sum + Math.max(0, this.now() - start), 0);
  }

  // Returns null (allow), { params } (allow with adjusted params) or { block, blockReason }.
  inspect(name, args = {}) {
    if (PASS_THROUGH.has(name)) return null;
    const block = (reason, kind) => { this.blocked++; return { block: true, blockReason: `Tripwire budget: ${reason} Stop exploring now. Answer with what you have verified and name the specific evidence that is still missing; do not switch to another tool to get around this.`, kind }; };
    const stateful = this.stateful.has(name);
    const key = createHash('sha256').update(name + JSON.stringify(canonical(args))
      + (REVISION_TOOLS.has(name) ? `:r${this.revision}` : '')
      + (stateful ? `:${this.calls}` : '')
      + (this.recovery.has(name) ? '' : `:a${this.recoveries}`)).digest('hex');
    if (this.dedupe && this.seen.has(key)) return block('this exact tool call already ran in this run. Reuse its result, including any failure.', 'repeat');
    if (this.calls >= this.maxCalls) return block(`this run has used its ${this.maxCalls} tool calls.`, 'calls');
    if (this.failures >= this.maxFailures) return block(`${this.failures} tool calls in this run have failed.`, 'failures');
    if (this.usedMs() >= this.maxMs && !this.untimed.has(name)) return block(`this run has used its ${Math.round(this.maxMs / 1000)} seconds of tool time.`, 'time');
    this.seen.add(key); this.calls++;
    const pending = this.pending.get(name) ?? []; pending.push(this.now()); this.pending.set(name, pending);
    if (this.execCapSeconds > 0 && ['exec', 'bash'].includes(name)) {
      const remaining = Math.max(1, Math.floor((this.maxMs - this.activeMs) / 1000));
      const requested = Number(args.timeoutSeconds ?? args.timeout);
      const timeoutSeconds = Math.min(this.execCapSeconds, remaining, Number.isFinite(requested) && requested > 0 ? requested : this.execCapSeconds);
      return { params: { ...args, timeoutSeconds, background: false, yieldMs: Math.max(1000, timeoutSeconds * 1000) } };
    }
    return null;
  }

  // Records the outcome of a call that inspect() allowed.
  observe(result, name, error) {
    const starts = this.pending.get(name);
    if (starts?.length) { const ms = Math.max(0, this.now() - starts.shift()); if (!this.untimed.has(name)) this.activeMs += ms; }
    const s = typeof result === 'string' ? result : JSON.stringify(result ?? {});
    const text = typeof result === 'string' ? result : Array.isArray(result?.content) ? result.content.find(c => c?.type === 'text')?.text : undefined;
    const failed = Boolean(error) || Boolean(result?.isError) || result?.details?.ok === false
      || ((!name || TEXT_FAILURE_TOOLS.has(name)) && FAILURE_TEXT.test(s))
      || (Boolean(name) && typeof text === 'string' && text.trimStart().startsWith(`${name} failed:`));
    if (failed) { this.failures++; return false; }
    this.successes++;
    if (EDIT_TOOLS.has(name)) this.revision++;
    if (this.recovery.has(name)) { this.recoveries++; if (this.failures > 0) this.failures--; }
    return true;
  }

  snapshot() {
    return { calls: this.calls, maxCalls: this.maxCalls, failures: this.failures, maxFailures: this.maxFailures, activeMs: this.activeMs, maxMs: this.maxMs, blocked: this.blocked };
  }
}

// Keeps one budget per run id, bounded so a long-lived gateway does not grow.
export class BudgetRegistry {
  constructor(factory, { limit = 256 } = {}) { this.factory = factory; this.limit = limit; this.map = new Map(); }
  get(runId, ctx) {
    if (!runId) return null;
    let b = this.map.get(runId);
    if (!b) {
      b = this.factory(ctx);
      this.map.set(runId, b);
      while (this.map.size > this.limit) this.map.delete(this.map.keys().next().value);
    }
    return b;
  }
  peek(runId) { return this.map.get(runId) ?? null; }
  delete(runId) { this.map.delete(runId); }
}
