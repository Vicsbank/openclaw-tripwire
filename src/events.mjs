// Local decision log: one JSON line per block, approval request or grant.
// Kept on this machine only (mode 0600), rotated at about 1 MB, never sent anywhere.
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

const MAX_BYTES = 1_000_000;
const clip = (s, n) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function createEventLog(path, { now = () => new Date().toISOString(), logger } = {}) {
  let warned = false;
  return function record(type, fields = {}) {
    try {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      if (existsSync(path) && statSync(path).size > MAX_BYTES) renameSync(path, `${path}.1`);
      const entry = { ts: now(), type, ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined).map(([k, v]) => [k, clip(v, 300)])) };
      appendFileSync(path, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
    } catch (error) {
      if (!warned) { warned = true; logger?.warn?.(`tripwire: could not write ${path}: ${error?.message ?? error}`); }
    }
  };
}

export function readEvents(path, { limit = 50 } = {}) {
  const lines = [];
  for (const p of [`${path}.1`, path]) {
    try { lines.push(...readFileSync(p, 'utf8').split('\n').filter(Boolean)); } catch {}
  }
  return lines.slice(-limit).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}
