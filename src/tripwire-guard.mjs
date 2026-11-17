// Deterministic host guard.
//
// A model-based reviewer can be talked into allowing a command by the
// conversation it reads. These rules run before any model review, for every
// agent in scope, and cannot be argued with. They cover three classes only:
//   1. secrets: keychains, credential stores, private keys, cookies and
//      browser login databases;
//   2. self-escalation: changing exec/plugin/approval policy, this guard,
//      service definitions or shell startup files;
//   3. host-level destruction and system security settings.
// Everything else stays with OpenClaw's own tool policy and approvals.
//
// The guard is a shell-aware pattern matcher, not a sandbox. It looks through
// quoting, `$(...)`, backticks, `sh -c`, AppleScript `do shell script`,
// wrappers such as env/xargs/timeout/sudo, `find -exec`, brace expansion,
// globs, `cd` and the tool's working directory. A determined attacker with
// arbitrary code execution can still write a program that reads a file; use
// an OS sandbox for that threat model.
import { homedir, userInfo } from 'node:os';
import { basename, dirname, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const esc = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const END = `(?=/|['"\\s;|&)<>]|$)`;

// File names of this plugin's own policy code and stored decisions. Writing
// them by name is blocked in any folder, so `cd <plugin> && sed -i ...` fails.
export const GUARD_BASENAMES = Object.freeze([
  'tripwire-guard.mjs', 'tripwire-exec.mjs', 'tripwire-budget.mjs', 'tripwire-plugin.mjs', 'tripwire-grants.json',
]);

// Secret locations relative to the home folder. Reading, copying or sending
// anything inside them is blocked.
export const DEFAULT_SECRET_PATHS = Object.freeze([
  '~/.openclaw/credentials', '~/.openclaw/.env', '~/.ssh', '~/.gnupg', '~/.aws', '~/.azure',
  '~/.config/gcloud', '~/.kube/config', '~/.docker/config.json', '~/.netrc', '~/.npmrc', '~/.pypirc',
  '~/.config/gh/hosts.yml', '~/.git-credentials', '~/.password-store', '~/.local/share/keyrings',
  '~/Library/Keychains',
]);

// Files that define the agent's permissions or the host's startup. Reading is
// fine; writing, moving or deleting them is blocked.
export const DEFAULT_PROTECTED_PATHS = Object.freeze([
  '~/.openclaw/state/openclaw.sqlite', '~/Library/LaunchAgents', '/Library/LaunchDaemons',
  '~/.config/systemd/user', '/etc/systemd', '~/.zshrc', '~/.zprofile', '~/.zshenv', '~/.bash_profile',
  '~/.bashrc', '~/.profile', '/etc/sudoers', '/etc/hosts', '/etc/pf.conf',
]);

// Folders that recursive rm may never remove (nor a glob that expands into them).
export const DEFAULT_KEEP_FOLDERS = Object.freeze([
  '/', '~', '~/.openclaw', '~/.config', '~/.ssh', '~/Documents', '~/Desktop', '~/Downloads', '~/Library',
  '~/Pictures', '~/Movies', '~/Music', '~/Developer', '~/Projects', '~/projects', '~/src', '~/code',
]);

// Askable rules that would switch off or loosen the guard itself. An
// approval for these is always "allow once" and never stored.
const selfEscalation = pluginIds => {
  const ids = pluginIds.map(esc).join('|');
  return [
    /^openclaw\s+(?:approvals\b|exec-policy\s+(?:set|preset)\b|secrets\b|security\b|hooks\b)/,
    new RegExp(`^openclaw\\s+plugins\\s+(?:uninstall|disable|install|update|link)\\b(?:.*\\b(?:${ids})\\b|(?:\\s+-\\S+)*\\s*$)`),
    /^openclaw\s+config\s+(?:set|unset|patch|apply|edit|import)\b.*\b(?:plugins|tools\.exec|approvals|hooks|security)\b/,
    /^launchctl\s+(?:bootout|unload|remove|disable)\b(?:.*\bai\.openclaw\.|\s+(?:(?:gui|user)\/\d+|system)\s*$)/,
    /^systemctl\s+(?:--user\s+)?(?:disable|mask|stop|kill)\b.*\bopenclaw/,
  ];
};

// Command-position rules: [regex on the executable, reason, askable].
const COMMAND_RULES = [
  [/^(?:\/usr\/bin\/)?security$/, 'Keychain access (security) is not allowed for agents. Report the keychain error instead of reading the keychain.', false],
  [/^(?:\S*\/)?(?:sudo|doas|su|login|dscl|dseditgroup|fdesetup|csrutil|spctl|tccutil|systemsetup|networksetup|pmset|nvram|bless|kextload|kmutil|profiles|launchd|visudo|passwd|chpasswd|useradd|usermod|userdel)$/, 'System administration and security settings are owner-only.', true],
  [/^(?:\S*\/)?(?:bw|op|lpass|keepassxc-cli|secret-tool)$/, 'Password manager command-line tools are owner-only.', true],
  [/^(?:\/s?bin\/)?(?:mkfs(?:\.\w+)?|newfs\w*|fsck(?:\.\w+)?|wipefs|fdisk|sfdisk|parted)$/, 'Filesystem formatting and partitioning are owner-only.', true],
];
const SUBCOMMAND_RULES = [
  [/^(?:\S*\/)?openclaw\s+(?:approvals\b|exec-policy\s+(?:set|preset)|plugins\s+(?:uninstall|disable)|security\b|secrets\b|hooks\b|backup\s+(?:enable|disable|delete|prune)|reset\b|uninstall\b)/, 'Changing OpenClaw policy, plugins, secrets or backups from inside an agent turn is owner-only. Describe the change and ask the owner to apply it.'],
  [/^(?:\S*\/)?openclaw\s+config\s+(?:set|unset|patch|apply|edit|import)\b.*\b(?:plugins|tools\.exec|approvals|hooks|security)\b/, 'Changing OpenClaw plugin, exec, hook or approval settings from inside an agent turn is owner-only.'],
  [/^(?:\S*\/)?openclaw\s+plugins\s+(?:install|update|link)\b/, 'Installing or replacing OpenClaw plugins from inside an agent turn is owner-only.'],
  [/^(?:\/bin\/)?launchctl\s+(?:bootout|unload|remove|disable|bootstrap|load|enable|setenv|unsetenv|reboot|config)\b/, 'Only `launchctl kickstart` / `print` / `list` are allowed; loading, unloading or disabling launchd services is owner-only.'],
  [/^(?:\S*\/)?systemctl\s+(?:--user\s+)?(?:disable|mask|enable|edit|set-property|daemon-reexec|poweroff|reboot|halt)\b/, 'Changing systemd units or power state is owner-only.'],
  [/^(?:\/usr\/sbin\/)?diskutil\s+(?:erase\w*|partition\w*|zeroDisk|secureErase|apfs\s+(?:delete|erase|encrypt|decrypt)\w*)/i, 'Disk erasing and partitioning are owner-only.'],
  [/^(?:\/usr\/bin\/)?tmutil\s+(?:delete\w*|disable|thinlocalsnapshots)/, 'Deleting Time Machine data is owner-only.'],
  [/^(?:\/usr\/bin\/)?defaults\s+(?:write|delete|import)\b/, 'Changing macOS preferences with `defaults write` is owner-only.'],
  [/^(?:\/usr\/bin\/)?crontab\s+(?:-r|-e|\S+\.\S+)/, 'Replacing or deleting the crontab is owner-only; use OpenClaw automations.'],
  [/^(?:\S*\/)?killall\b|^(?:\S*\/)?pkill\s+(?:-\S+\s+)*(?:-f\s+)?(?:node|openclaw|Chrome|Google|chromium)\b/i, 'Broad process killing can take down the Gateway or a shared browser. Stop the exact PID you started, or report the blocker.'],
  [/^(?:\S*\/)?(?:shutdown|reboot|halt|poweroff)\b/, 'Shutting down or restarting the machine is owner-only.'],
];
const NEVER_ASKABLE = /^(?:\S*\/)?security$/;
const SHELLS = /^(?:sh|bash|zsh|dash|ksh|mksh|fish)$/;
const KEYWORDS = /^(?:(?:do|then|else|elif|if|while|until|time|!)\s+|[({]\s*)/;
// Wrappers that run another command, with the options of each that take an argument.
const WRAPPERS = { env: /^-[uCSP]$/, xargs: /^-[IJLnPsERS]$|^--(?:max-args|replace|max-procs|max-lines|delimiter|eof|arg-file)$/, nice: /^-n$/, timeout: /^-[sk]$/, gtimeout: /^-[sk]$/, exec: /^-a$/, caffeinate: /^-[tw]$/, sudo: /^-[ugCDhpRrT]$/, doas: /^-[uC]$/, command: null, builtin: null, nohup: null, time: null, stdbuf: null, arch: null, setsid: null, chroot: null, unbuffer: null };
const IN_PLACE = { sed: a => /^-[a-zA-Z]*i/.test(a) || a.startsWith('--in-place'), perl: a => /^-[a-zA-Z]*i/.test(a) };
const ANY_ARG = new Set(['tee', 'truncate', 'rm', 'rmdir', 'unlink', 'chmod', 'chown', 'chflags', 'mv', 'shred']);
const LAST_ARG = new Set(['cp', 'mv', 'install', 'ln', 'rsync', 'ditto']);
const INLINE_WRITE = /writeFile|appendFile|open\([^)]*['"][wa]|\.write\(|write_text|write_bytes/;
const WRITE_VERBS = /(?:>>?|\btee\b|\bsed\s+(?:-[a-zA-Z]*i|--in-place)|\bperl\s+-[a-zA-Z]*i|\b(?:cp|mv|rm|ln|chmod|chown|truncate|install|rsync|ditto|unlink|rmdir|shred)\b|writeFile|appendFile|open\([^)]*['"][wa]|\.write\(|write_text|write_bytes)/;
const BRACE_GROUP = /\{([^{}]*,[^{}]*|(-?\d+|[a-zA-Z])\.\.(-?\d+|[a-zA-Z])(?:\.\.-?\d+)?)\}/;
const UNKNOWN_DIR = Symbol('unknown-dir');
const READ_TOOLS = new Set(['read', 'ls', 'grep', 'find', 'glob', 'view', 'pdf', 'image', 'file_read', 'file_transfer', 'upload']);
const WRITE_TOOLS = new Set(['write', 'edit', 'apply_patch', 'multi_edit', 'file_write', 'delete', 'move', 'copy']);

const compMatch = (pattern, name) => {
  // The shell does not let * ? [ match a leading dot.
  if (name.startsWith('.') && !pattern.startsWith('.')) return false;
  const re = pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\[!/g, '[^');
  try { return new RegExp(`^${re}$`).test(name); } catch { return true; }
};
// Can glob components P name directory D or something inside it?
const globCovers = (P, D) => {
  if (!D.length) return true;
  if (!P.length) return false;
  if (P[0] === '**') return globCovers(P.slice(1), D) || (!D[0].startsWith('.') && globCovers(P, D.slice(1)));
  return compMatch(P[0], D[0]) && globCovers(P.slice(1), D.slice(1));
};
const comps = p => p.split('/').filter(c => c && c !== '.');
const globNames = (P, D) => P.length === D.length && P.every((c, k) => compMatch(c, D[k]));

function braceAlternatives(m) {
  if (m[2] === undefined) return m[1].split(',');
  const step = Math.abs(Number(m[1].split('..')[2] ?? 1)) || 1;
  const num = /^-?\d+$/.test(m[2]);
  if (num !== /^-?\d+$/.test(m[3])) return null;
  const a = num ? Number(m[2]) : m[2].charCodeAt(0), b = num ? Number(m[3]) : m[3].charCodeAt(0);
  if (Math.abs(b - a) / step >= 64) return null;
  const out = [];
  for (let v = a; a <= b ? v <= b : v >= b; v += a <= b ? step : -step) out.push(num ? String(v) : String.fromCharCode(v));
  return out;
}
const braceLeft = w => w.replace(new RegExp(BRACE_GROUP.source, 'g'), '*');

// Quote-aware words of one segment (quotes removed, as the shell would).
export function words(segment) {
  const out = [];
  let current = '', quote = null, started = false;
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (quote) { if (c === quote) quote = null; else current += c; continue; }
    if (c === "'" || c === '"') { quote = c; started = true; continue; }
    if (c === '\\' && i + 1 < segment.length) { current += segment[++i]; started = true; continue; }
    if (/\s/.test(c)) { if (started || current) out.push(current); current = ''; started = false; continue; }
    current += c;
  }
  if (started || current) out.push(current);
  return out;
}

// Strip leading env assignments and transparent wrappers so the real executable is checked.
function commandHead(segment) {
  let s = segment.trim().replace(/^[({]\s*/, '');
  for (let i = 0; i < 8; i++) {
    const before = s;
    s = s.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)\s+)+/, '')
      .replace(/^(?:\S*\/)?(?:env|command|builtin|exec|nohup|time|nice|caffeinate|xargs|setsid)(?:\s+-[a-zA-Z-]+(?:\s+\S+)?)*\s+/, '')
      .replace(/^(?:\S*\/)?(?:timeout|gtimeout)\s+(?:-\S+\s+)*\S+\s+/, '');
    if (s === before) break;
  }
  return s;
}

// Splits one shell string at top-level ; newline && || | &, respecting quotes.
// $(...), <(...), >(...) and `...` bodies are returned separately.
function splitTopLevel(text) {
  const parts = [], bodies = [];
  let cur = '', quote = null;
  const push = () => { if (cur.trim()) parts.push(cur.trim()); cur = ''; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i], next = text[i + 1];
    if (quote === "'") { cur += c; if (c === "'") quote = null; continue; }
    if (c === '\\' && i + 1 < text.length) { cur += c + next; i++; continue; }
    if ((c === '$' || ((c === '<' || c === '>') && !quote)) && next === '(') {
      let depth = 0, j = i + 1, q = null;
      for (; j < text.length; j++) {
        const d = text[j];
        if (q) { if (d === q) q = null; else if (d === '\\' && q === '"') j++; continue; }
        if (d === "'" || d === '"') q = d;
        else if (d === '\\') j++;
        else if (d === '(') depth++;
        else if (d === ')' && --depth === 0) break;
      }
      bodies.push(text.slice(i + 2, j));
      cur += text.slice(i, j + 1); i = j; continue;
    }
    if (c === '`') {
      const j = text.indexOf('`', i + 1), end = j < 0 ? text.length : j;
      bodies.push(text.slice(i + 1, end));
      cur += text.slice(i, end + 1); i = end; continue;
    }
    if (quote === '"') { cur += c; if (c === '"') quote = null; continue; }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (c === '&' && (next === '>' || cur.endsWith('>'))) { cur += c; continue; }
    if (c === ';' || c === '\n' || c === '|' || c === '&') { push(); if (next === c) i++; continue; }
    cur += c;
  }
  push();
  return { parts, bodies };
}

// The -c string of a shell invocation ([exe, ...args]), or null.
function shellBody([exe, ...args]) {
  if (!SHELLS.test(exe)) return null;
  let sawC = false, i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === '--' || a === '-') { i++; break; }
    if (/^--(?:rcfile|init-file|command)$/.test(a)) { if (a === '--command') sawC = true; else i++; continue; }
    if (a.startsWith('--')) continue;
    if (/^[-+][a-zA-Z]+$/.test(a)) {
      if (a[0] === '-' && a.includes('c')) sawC = true;
      if (/[oO]/.test(a)) i++;
      continue;
    }
    break;
  }
  return sawC && i < args.length ? args[i] : null;
}

// The commands one segment runs, each as [base name, ...args]. Looks through
// wrappers and `find -exec` / `-execdir` / `-ok`.
function commandsIn(w, depth = 0) {
  const out = [];
  let i = 0;
  while (i < w.length && depth++ < 8) {
    while (i < w.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(w[i])) i++;
    if (i >= w.length) break;
    const exe = w[i].replace(/^.*\//, '');
    out.push([exe, ...w.slice(i + 1)]);
    if (exe === 'find') {
      for (let k = i + 1; k < w.length; k++) if (/^-(?:exec|execdir|ok|okdir)$/.test(w[k])) out.push(...commandsIn(w.slice(k + 1), depth));
      break;
    }
    if (!(exe in WRAPPERS)) break;
    // `command -v x` / `command -V x` only look the name up.
    if (exe === 'command' && w.slice(i + 1).some((a, k, rest) => /^-[a-zA-Z]*[vV]/.test(a) && rest.slice(0, k).every(b => b.startsWith('-') && b !== '--'))) break;
    i++;
    while (i < w.length && w[i].startsWith('-') && w[i] !== '-') {
      if (w[i] === '--') { i++; break; }
      i += WRAPPERS[exe]?.test(w[i]) ? 2 : 1;
    }
    if ((exe === 'timeout' || exe === 'gtimeout') && i < w.length) i++;
  }
  return out;
}

const segmentWords = seg => {
  let s = seg.trim();
  for (let i = 0; i < 6 && KEYWORDS.test(s); i++) s = s.replace(KEYWORDS, '');
  // A closing `)` or a standalone `}` ends a group; a `}` glued to a word ends a brace expansion.
  for (let i = 0; i < 6; i++) { const t = s.replace(/\s*\)\s*$|(?:^|\s+)\}\s*$/, ''); if (t === s) break; s = t; }
  return words(s);
};

// Every shell string the command runs, each as its ordered list of top-level
// segments: the command itself, $(...) and `...` bodies, sh/bash/zsh -c
// strings and AppleScript `do shell script` strings.
function segmentGroups(command) {
  const groups = [];
  const pending = [String(command ?? '')];
  let guard = 0;
  while (pending.length && guard++ < 64) {
    const t = pending.pop();
    const { parts, bodies } = splitTopLevel(t);
    groups.push(parts);
    pending.push(...bodies);
    for (const m of t.matchAll(/\b(?:sh|bash|zsh|dash|ksh)\s+(?:-[a-zA-Z]+\s+)*?-[a-zA-Z]*c[a-zA-Z]*\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)")/g)) pending.push(m[1] ?? m[2].replace(/\\(["\\$`])/g, '$1'));
    for (const part of parts) for (const cmd of commandsIn(segmentWords(part))) { const body = shellBody(cmd); if (body) pending.push(body); }
    for (const m of t.matchAll(/do\s+shell\s+script\s+(\\*["'])/gi)) {
      const start = m.index + m[0].length, end = t.indexOf(m[1], start);
      pending.push(t.slice(start, end < 0 ? undefined : end).replace(/\\(["'\\])/g, '$1'));
    }
  }
  return groups;
}

// Words that output redirections write to, and the segment without them.
function redirects(seg) {
  const targets = [];
  let rest = '', q = null;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (q) { rest += c; if (c === q) q = null; else if (c === '\\' && q === '"') rest += seg[++i] ?? ''; continue; }
    if (c === "'" || c === '"') { q = c; rest += c; continue; }
    if (c === '\\') { rest += c + (seg[i + 1] ?? ''); i++; continue; }
    if (c !== '>' || seg[i + 1] === '(') { rest += c; continue; }
    let j = i + 1;
    if (seg[j] === '>' || seg[j] === '|') j++;
    if (seg[j] === '&') j++;
    while (/\s/.test(seg[j] ?? '')) j++;
    let k = j, wq = null;
    for (; k < seg.length; k++) {
      const d = seg[k];
      if (wq) { if (d === wq) wq = null; continue; }
      if (d === "'" || d === '"') wq = d;
      else if (/[\s;&|<>()]/.test(d)) break;
    }
    const word = words(seg.slice(j, k))[0] ?? '';
    if (word && !/^\d*-?$/.test(word)) targets.push(word);
    rest = `${rest.replace(/(?:\d+|&)$/, '')} `;
    i = k - 1;
  }
  return { targets, rest };
}

const pathValues = params => {
  const out = [];
  const walk = (value, key = '', depth = 0) => {
    if (depth > 4 || value == null) return;
    if (typeof value === 'string') { if (/path|file|dir|target|dest|src|source/i.test(key)) out.push(value); return; }
    if (Array.isArray(value)) return value.forEach(v => walk(v, key, depth + 1));
    if (typeof value === 'object') for (const [k, v] of Object.entries(value)) walk(v, k, depth + 1);
  };
  walk(params);
  return out;
};

const defaultPluginDir = () => dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Builds a guard for one host. Every option is optional.
 *   home, user           the host's home folder and user name (tests pass fakes)
 *   secretPaths          extra secret locations (added to DEFAULT_SECRET_PATHS)
 *   protectedPaths       extra write-protected locations (added to DEFAULT_PROTECTED_PATHS)
 *   keepFolders          extra folders recursive rm may not remove
 *   protectOpenClawConfig  protect ~/.openclaw/openclaw.json from direct writes (default true)
 *   protectPluginFiles   protect every file of this plugin's folders, not only its policy files (default true)
 *   pluginDirs           this plugin's folders (default: the folder it was loaded from)
 *   stateDir             this plugin's state folder (holds tripwire-grants.json)
 *   pluginIds            plugin ids whose disabling counts as self-escalation (default ['tripwire'])
 *   openclawRoots        OpenClaw state roots besides ~/.openclaw (profiles, OPENCLAW_STATE_DIR)
 *   openclawConfigPath   OpenClaw config file when it lives elsewhere (OPENCLAW_CONFIG_PATH)
 */
export function createHostGuard(options = {}) {
  const HOME = (options.home ?? homedir()).replace(/\/+$/, '') || '/';
  const USER = options.user ?? (() => { try { return userInfo().username; } catch { return basename(HOME); } })();
  const homeRe = `(?:~|\\$HOME|\\$\\{HOME\\}|${esc(HOME)})`;
  const homeWordRe = new RegExp(`^(?:~(?:${esc(USER)})?|\\$HOME|\\$\\{HOME\\})(?=/|$)`);
  const expandHomeWord = w => String(w).replace(homeWordRe, HOME);
  const expandHome = p => String(p).replace(/^~(?=\/|$)/, HOME);
  const absolute = p => posix.normalize(expandHome(String(p).trim())).replace(/\/+$/, '') || '/';
  const pathRegex = p => {
    const s = String(p).trim();
    const m = /^~(\/.*)?$/.exec(s);
    const body = m ? `${homeRe}${esc(m[1] ?? '')}` : s.startsWith(`${HOME}/`) || s === HOME ? `${homeRe}${esc(s.slice(HOME.length))}` : esc(s);
    return new RegExp(`${body}${END}`, 'i');
  };
  const list = (base, extra) => [...new Set([...base, ...(Array.isArray(extra) ? extra : [])].filter(p => typeof p === 'string' && p.trim()))];

  const pluginDirs = [...new Set((options.pluginDirs?.length ? options.pluginDirs : [defaultPluginDir()]).map(absolute))];
  const stateDir = absolute(options.stateDir ?? `${HOME}/.openclaw/state/tripwire`);
  const pluginIds = options.pluginIds?.length ? options.pluginIds : ['tripwire'];
  const SELF_ESCALATION = selfEscalation(pluginIds);

  // OpenClaw's own folders. A --profile install or OPENCLAW_STATE_DIR moves them away from
  // ~/.openclaw, so every built-in ~/.openclaw path is applied to each real state root too.
  const openclawRoots = [...new Set([`${HOME}/.openclaw`, ...(options.openclawRoots ?? [])].map(absolute))];
  const forRoots = paths => paths.flatMap(p => (p.startsWith('~/.openclaw') ? openclawRoots.map(r => r + p.slice('~/.openclaw'.length)) : [p]));
  const configPaths = [...new Set([...openclawRoots.map(r => `${r}/openclaw.json`), ...(options.openclawConfigPath ? [absolute(options.openclawConfigPath)] : [])])];

  const secretList = list(forRoots(DEFAULT_SECRET_PATHS), options.secretPaths);
  // Secrets matched anywhere in the text: browser login stores and private SSH keys.
  const SECRET_PATHS = [
    ...secretList.map(pathRegex),
    /\/(?:Cookies|Login Data|Web Data)(?:-journal)?(?:['"\s]|$)/i,
    /(?:^|[\s/'"=])id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?=['"\s;|&)]|$)/,
  ];
  // Secret locations as literal paths, for globs and relative paths.
  const SECRET_DIRS = secretList.map(p => absolute(p).split('/').filter(Boolean));

  const protectedList = list(forRoots(DEFAULT_PROTECTED_PATHS), options.protectedPaths);
  if (options.protectOpenClawConfig !== false) protectedList.push(...configPaths);
  if (options.protectPluginFiles !== false) protectedList.push(...pluginDirs);
  protectedList.push(stateDir);
  const PROTECTED_WRITE_PATHS = protectedList.map(pathRegex);

  const nameAlt = GUARD_BASENAMES.map(esc).join('|');
  const PROTECTED_NAME = new RegExp(`(?:^|/)(?:${nameAlt})$`, 'i');
  const PROTECTED_NAME_TEXT = new RegExp(`(?:^|[\\s/'"=])(?:${nameAlt})(?=['"\\s;|&)<>]|$)`, 'i');
  const PROTECTED_DIRS = [...pluginDirs, stateDir];
  const dirNameRe = new RegExp(`(?:^|/)(?:${[...new Set(PROTECTED_DIRS.map(d => basename(d)))].map(esc).join('|')})/?$`);
  const GUARD_FILES = PROTECTED_DIRS.flatMap(d => GUARD_BASENAMES.map(f => `${d}/${f}`)).map(p => p.split('/').filter(Boolean));
  const RM_PROTECTED = list(forRoots(DEFAULT_KEEP_FOLDERS), options.keepFolders).map(absolute);

  function pathVariants(word) {
    let variants = [String(word)];
    for (let n = 0; n < 6; n++) {
      let changed = false;
      variants = variants.flatMap(w => {
        const m = BRACE_GROUP.exec(w);
        if (!m) return [w];
        const alts = braceAlternatives(m);
        changed = true;
        if (!alts) return [w.slice(0, m.index) + '*' + w.slice(m.index + m[0].length)];
        return alts.map(alt => w.slice(0, m.index) + alt + w.slice(m.index + m[0].length));
      });
      if (!changed || variants.length > 64) break;
    }
    return variants.map(braceLeft).map(w => {
      const p = expandHomeWord(w);
      const g = p.search(/[*?[]/);
      if (g < 0) return posix.normalize(p);
      const cut = p.lastIndexOf('/', g) + 1;
      return cut ? posix.normalize(p.slice(0, cut)) + p.slice(cut) : p;
    });
  }
  const secretHit = text => SECRET_PATHS.find(re => re.test(text));
  function secretPath(path) {
    if (secretHit(path)) return true;
    if (!path.startsWith('/') || !/[*?[]/.test(path)) return false;
    const P = path.split('/').filter(Boolean);
    return SECRET_DIRS.some(D => globCovers(P, D));
  }
  const protectedHit = text => PROTECTED_WRITE_PATHS.find(re => re.test(text));
  const protectedFileHit = path => protectedHit(path) || PROTECTED_NAME_TEXT.test(path);

  // Directory after one segment: `cd`/`pushd` move it.
  function nextDir(dir, w) {
    if (!/^(?:cd|pushd)$/.test(w[0] ?? '')) return dir;
    const target = w.slice(1).find(a => a === '-' || !a.startsWith('-'));
    if (target === undefined) return w[0] === 'cd' ? HOME : UNKNOWN_DIR;
    const t = expandHomeWord(target);
    if (t === '-' || /[$`]/.test(t) || t.startsWith('~')) return UNKNOWN_DIR;
    if (t.startsWith('/')) return posix.normalize(t);
    if (typeof dir === 'string') return resolve(dir, t);
    return dir === null && !t.split('/').includes('..') ? null : UNKNOWN_DIR;
  }

  // Recursive rm of a kept folder, a folder above one, its contents, or a glob that could expand into one.
  function rmKept([exe, ...args], dir = null) {
    if (exe !== 'rm') return false;
    let recursive = false, opts = true;
    const targets = [];
    for (const a of args) {
      if (opts && a === '--') { opts = false; continue; }
      if (opts && /^--recursive$/.test(a)) { recursive = true; continue; }
      if (opts && /^-[a-zA-Z]+$/.test(a)) { if (/[rR]/.test(a)) recursive = true; continue; }
      if (opts && a.startsWith('--')) continue;
      targets.push(...pathVariants(a));
    }
    if (!recursive) return false;
    return targets.some(raw => {
      let t = raw;
      if (!t.startsWith('/')) {
        if (dir === UNKNOWN_DIR) return true;
        if (typeof dir !== 'string' || t.startsWith('~') || /[$`]/.test(t)) return false;
        t = `${dir}/${t}`;
      }
      const glob = t.search(/[*?[]/);
      if (glob >= 0) {
        if (t.slice(glob).split('/').includes('..')) return true;
        const prefix = posix.normalize(t.slice(0, glob));
        return RM_PROTECTED.some(d => `${d.replace(/\/$/, '')}/`.startsWith(prefix) || d === prefix);
      }
      const clean = posix.normalize(t).replace(/\/+$/, '') || '/';
      return RM_PROTECTED.some(d => d === clean || d.startsWith(`${clean}/`) || clean === '/');
    });
  }

  // Does this command write one of the guard's own files?
  function writesProtected([exe, ...args], dir) {
    const plain = args.filter(a => !a.startsWith('-'));
    if (ANY_ARG.has(exe) || (IN_PLACE[exe] && args.some(IN_PLACE[exe]))) { if (plain.some(a => PROTECTED_NAME.test(a))) return true; }
    if (!LAST_ARG.has(exe) || !plain.length) return false;
    const dest = exe === 'ln' && plain.length === 1 ? '.' : plain.at(-1);
    if (PROTECTED_NAME.test(dest.replace(/\/+$/, ''))) return true;
    if (!plain.slice(0, -1).some(a => PROTECTED_NAME.test(a)) && !(exe === 'ln' && plain.length === 1)) return false;
    const d = expandHomeWord(dest);
    const abs = d.startsWith('/') ? d : typeof dir === 'string' ? resolve(dir, d) : null;
    if (abs === null) return /^\.{1,2}\/?$/.test(d) || dirNameRe.test(d) || /[$`]/.test(d);
    const clean = posix.normalize(abs).replace(/\/+$/, '');
    return PROTECTED_DIRS.includes(clean);
  }

  // Can glob P name D, a folder above D, or a guard file inside D?
  const globTouches = (P, D) => {
    if (!P.length) return true;
    if (!D.length) return P[0] === '**' || (P.length === 1 && GUARD_BASENAMES.some(f => compMatch(P[0], f)));
    if (P[0] === '**') return true;
    return compMatch(P[0], D[0]) && globTouches(P.slice(1), D.slice(1));
  };
  // Recursive rm, rmdir, mv (as source), chmod/chown/chflags of a guard folder or a folder above one.
  function guardDirHit([exe, ...args], dir) {
    const opts = [], plain = [];
    let end = false;
    for (const a of args) { if (!end && a === '--') { end = true; continue; } (!end && /^-./.test(a) ? opts : plain).push(a); }
    const recursive = exe === 'rm' && opts.some(o => o === '--recursive' || /^-[a-zA-Z]*[rR]/.test(o));
    if (exe === 'mv' && plain.length && /[{}]/.test(plain.at(-1)) && pathVariants(plain.at(-1)).some(v => /[*?[]/.test(v) && !/[*?[]/.test(plain.at(-1)))) plain.push('/dev/null');
    const wordList = plain.flatMap(pathVariants);
    let targets = [];
    if (recursive || exe === 'rmdir') targets = wordList;
    else if (exe === 'mv') targets = wordList.slice(0, -1);
    else if (/^(?:chmod|chown|chgrp|chflags)$/.test(exe)) targets = (exe === 'chmod' && opts.some(o => /^-[rwxXst]+$/.test(o)) ? plain : plain.slice(1)).flatMap(pathVariants);
    const fileGlobs = exe === 'rm' || exe === 'unlink' ? wordList : exe === 'mv' || /^(?:chmod|chown|chgrp|chflags)$/.test(exe) ? targets : [];
    const abs = raw => {
      const t = expandHomeWord(raw);
      if (t.startsWith('/')) return t;
      if (/[$`]/.test(t) || dir === UNKNOWN_DIR) return UNKNOWN_DIR;
      if (typeof dir === 'string' && !t.startsWith('~')) return `${dir}/${t}`;
      return null;
    };
    for (const raw of fileGlobs) {
      const t = abs(raw);
      if (typeof t === 'string' && /[*?[]/.test(t) && !t.split('/').includes('..') && GUARD_FILES.some(D => globNames(comps(t), D))) return true;
    }
    return targets.some(raw => {
      const t = abs(raw);
      if (t === UNKNOWN_DIR) return true;
      if (t === null) return dirNameRe.test(raw) || comps(raw).every(c => c === '..');
      const g = t.search(/[*?[]/);
      if (g >= 0) {
        if (t.slice(g).split('/').includes('..')) return true;
        const cut = t.lastIndexOf('/', g) + 1;
        const P = comps(posix.normalize(t.slice(0, cut))).concat(comps(t.slice(cut)));
        return PROTECTED_DIRS.some(d => globTouches(P, comps(d)));
      }
      const clean = posix.normalize(t).replace(/\/+$/, '') || '/';
      return PROTECTED_DIRS.some(d => clean === '/' || d === clean || d.startsWith(`${clean}/`));
    });
  }

  const startDir = cwd => { const d = cwd ? expandHomeWord(cwd) : ''; return d.startsWith('/') ? posix.normalize(d) : null; };

  // Path-like words of each segment, home-expanded and resolved against cd / the workdir.
  function secretWord(groups, cwd) {
    for (const parts of groups) {
      let dir = startDir(cwd);
      for (const part of parts) {
        const w = segmentWords(part);
        for (const raw of w.flatMap(x => [x, ...x.split(/[=:]/).slice(1)])) {
          if (!raw || raw.startsWith('-') || /:\/\//.test(raw)) continue;
          for (const p of pathVariants(raw)) {
            if (secretPath(p)) return true;
            if (typeof dir === 'string' && !p.startsWith('/') && secretPath(resolve(dir, p))) return true;
            if (typeof dir === 'string' && !p.startsWith('/') && /[*?[]/.test(p) && secretPath(`${dir.replace(/\/$/, '')}/${p}`)) return true;
          }
        }
        dir = nextDir(dir, w);
      }
    }
    return false;
  }

  // Returns null, or { reason, askable, selfEscalation? }.
  // Askable rules are owner-only rather than never: with exec approval on, the
  // owner may allow one such command, once. Secrets, protected files and
  // recursive deletion of kept folders are never askable.
  function execVerdict(command, { cwd } = {}) {
    const text = String(command ?? '');
    if (!text.trim()) return null;
    const hard = reason => ({ reason, askable: false, rule: 'hard' });
    const groups = segmentGroups(text);
    if (secretHit(text) || secretHit(text.replace(/["'\\]/g, '')) || secretWord(groups, cwd)) return { ...hard('This command touches a secret store (credentials, keychain, private keys, cookies or login data). Agents never read, copy or transmit secrets; report the blocker instead.'), rule: 'secret' };
    const writeText = text.replace(/\d?>>?\s*\/dev\/null|\d>&\d|&>\s*\/dev\/null/g, ' ');
    const protectedWrite = { ...hard('This command would modify a protected file that defines the agent\'s own permissions or the host\'s startup (OpenClaw config, this guard, service definitions or shell profiles). Describe the change for the owner instead.'), rule: 'protected-write' };
    if (protectedHit(text) && WRITE_VERBS.test(writeText)) return protectedWrite;
    if (PROTECTED_NAME_TEXT.test(text) && INLINE_WRITE.test(text)) return protectedWrite;
    // A hard rule anywhere wins over an askable one found earlier.
    let askable = null;
    for (const parts of groups) {
      let dir = startDir(cwd);
      for (const seg of parts) {
        const { targets, rest } = redirects(seg);
        if (targets.some(t => PROTECTED_NAME.test(t) || protectedFileHit(expandHomeWord(t)))) return protectedWrite;
        const w = segmentWords(rest);
        for (const cmd of commandsIn(w)) {
          if (rmKept(cmd, dir)) return { ...hard('Recursive deletion of the home folder, OpenClaw state or a top-level user folder is never allowed.'), rule: 'rm-kept' };
          if (writesProtected(cmd, dir) || guardDirHit(cmd, dir)) return protectedWrite;
          let c = cmd;
          if (c[0] === 'openclaw') {
            let i = 1;
            while (i < c.length && c[i].startsWith('-')) i += /^--(?:log-level|container|profile)$/.test(c[i]) ? 2 : 1;
            c = ['openclaw', ...c.slice(i)];
          }
          const exe = c[0], line = c.join(' ');
          let hit = null;
          for (const [re, reason, can] of COMMAND_RULES) if (!hit && re.test(exe)) hit = { reason, askable: can && !NEVER_ASKABLE.test(exe), rule: 'command' };
          for (const [re, reason] of SUBCOMMAND_RULES) if (!hit && re.test(line)) hit = { reason, askable: true, rule: 'subcommand', ...(SELF_ESCALATION.some(s => s.test(line)) ? { selfEscalation: true } : {}) };
          if (hit && !hit.askable) return hit;
          if (hit && (!askable || (hit.selfEscalation && !askable.selfEscalation))) askable = hit;
        }
        dir = nextDir(dir, w);
      }
    }
    return askable;
  }

  function inspectFileTool(toolName, params = {}) {
    const reading = READ_TOOLS.has(toolName);
    const writing = WRITE_TOOLS.has(toolName);
    if (!reading && !writing) return null;
    let paths = pathValues(params).map(expandHome);
    if (toolName === 'apply_patch') {
      const patch = String(params.input ?? params.patch ?? '');
      paths = paths.concat([...patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm), ...patch.matchAll(/^\*\*\* Move to: (.+)$/gm)].map(m => expandHome(m[1].trim())));
    }
    for (const p of paths) {
      if (secretHit(p) || pathVariants(p).some(secretPath)) return { reason: 'This path is a secret store (credentials, keychain, private keys, cookies or login data). Agents never read or modify it.', askable: false, rule: 'secret' };
      if (writing && (protectedFileHit(p) || (toolName === 'delete' && guardDirHit(['rmdir', p], null)))) return { reason: 'This file defines the agent\'s own permissions or the host\'s startup. Modifying it is owner-only; describe the change instead.', askable: false, rule: 'protected-write' };
    }
    return null;
  }

  // Returns null or { reason, askable, rule, selfEscalation?, block } for a tool call.
  function verdict(toolName, params = {}) {
    let name = toolName, args = params ?? {};
    if (name === 'tool_call' && typeof args.id === 'string') { name = args.id; args = args.args ?? args.arguments ?? {}; }
    let v = null;
    if (['exec', 'bash', 'process', 'shell'].includes(name)) v = execVerdict(args.command ?? args.cmd ?? args.input ?? '', { cwd: args.workdir ?? args.cwd });
    else v = inspectFileTool(name, args);
    return v ? { ...v, block: { block: true, blockReason: `Tripwire host guard: ${v.reason} Do not try a different command or tool to achieve the same thing.` } } : null;
  }

  return {
    verdict,
    execVerdict,
    inspectFileTool,
    commandSegments: command => segmentGroups(command).flat().map(commandHead),
    settings: Object.freeze({ home: HOME, openclawRoots, configPaths, pluginDirs, stateDir, secretPaths: secretList, protectedPaths: protectedList, keepFolders: RM_PROTECTED }),
  };
}

// Commands that switch off certificate checks would expose credentials.
const INSECURE_TLS = [
  /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/i,
  /rejectUnauthorized\s*:\s*false/,
  /\bcurl\b[^\n|;&]*\s(?:-[A-Za-z]*k[A-Za-z]*|--insecure)(?=\s|$)/,
  /\bwget\b[^\n|;&]*--no-check-certificate/,
  /verify\s*=\s*False\b/,
  /PYTHONHTTPSVERIFY\s*=\s*['"]?0/,
  /GIT_SSL_NO_VERIFY\s*=\s*['"]?(?:1|true)/i,
];
export const insecureTls = (name, args = {}) => ['exec', 'bash', 'shell'].includes(name) && INSECURE_TLS.some(re => re.test(String(args.command ?? '') + String(args.code ?? '')));
