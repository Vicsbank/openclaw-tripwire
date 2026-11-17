import { definePluginEntry } from 'openclaw/plugin-sdk/plugin-entry';
import { registerTripwire } from './src/tripwire-plugin.mjs';

export default definePluginEntry({
  id: 'tripwire',
  name: 'Tripwire',
  description: 'Deterministic host guard, per-run tool budgets and exec approvals for OpenClaw agents.',
  register: api => { registerTripwire(api); },
});
