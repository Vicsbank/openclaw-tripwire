# Tripwire for OpenClaw

Deterministic safety rails for OpenClaw agents that run on your own machine.

- **Host guard.** Blocks secret reads, writes to files that control the agent's own permissions, and destructive system commands. These are fixed rules, so no prompt can talk them out of it.
- **Tool budget.** Stops a run that is looping: too many tool calls, too much tool time, too many failures, or the exact same call again.
- **Exec approval** (optional). Routine shell commands run at once. Anything risky asks you through OpenClaw's own approval buttons, on any channel. "Allow always" is remembered.

Tripwire has no runtime dependencies and needs no API keys.

```text
agent wants to run a tool
        │
        ▼
 ┌─────────────┐  secret / protected file / rm -rf ~     ┌────────┐
 │ host guard  │ ──────────────────────────────────────▶ │ block  │
 └─────────────┘  sudo / launchctl bootout / …  ──▶ ask once (or block if approval is off)
        │
        ▼
 ┌─────────────┐  60 calls · 15 min tool time · 8 failures · exact repeat
 │ tool budget │ ──────────────────────────────────────▶ stop with a reason the model can act on
 └─────────────┘
        │  exec only
        ▼
 ┌──────────────┐ read-only or granted ─▶ run
 │ exec approval│ review model says fine ─▶ run
 └──────────────┘ otherwise ─▶ approval buttons (allow once / allow always / deny)
```

## Requirements

- OpenClaw **2026.11.3** or newer (`openclaw --version`)
- Node.js 22 or newer (the version that runs your Gateway)
- macOS or Linux. The guard's rules know both; Windows hosts are not supported yet.

## Install

```bash
openclaw plugins install clawhub:openclaw-tripwire --accept-capabilities
```

Or from npm (`--force` confirms a source outside ClawHub review):

```bash
openclaw plugins install npm:openclaw-tripwire --force --accept-capabilities
```

`--accept-capabilities` is required. Tripwire registers *trusted tool policies*, which run before every other plugin's hooks, and OpenClaw asks for explicit consent before installing a plugin that does. Without the flag the install stops and tells you to rerun it.

The install enables the plugin. Apply it to the running Gateway:

```bash
openclaw plugins reload tripwire
```

If your Gateway runs with `plugins.reload` off, restart it instead (`openclaw gateway restart`).

### Check that it works

```bash
openclaw tripwire status
```

```text
✓ Host guard on for every agent.
✓ Tool budget on: 60 calls, 900 s of tool time, 8 failures per run.
✓ Exec approval off (owner-only commands are simply blocked).
✓ Self-test passed (7 sample commands).
```

Try a command without running it:

```bash
openclaw tripwire test cat ~/.ssh/id_ed25519
```

```text
BLOCK  (host guard, rule secret)
This command touches a secret store (credentials, keychain, private keys, cookies or login data). …
```

That's all. With the defaults, the host guard and the tool budget protect every agent.

## Turn on exec approval (optional)

With approval off, owner-only commands such as `sudo` or `launchctl bootout` are simply blocked. Turn it on to get a button instead, and to have a model check every other shell command:

```bash
openclaw config set plugins.entries.tripwire.config.execApproval.enabled true
openclaw config set plugins.entries.tripwire.hooks.allowConversationAccess true
openclaw plugins reload tripwire
```

The second line lets the reviewer see what you asked for, so it can tell "the command you asked for" from "something the agent decided on its own". Approval works without it; the reviewer then sees only the command.

What happens to a shell command once approval is on:

| Command | Result |
|---|---|
| Read-only (`ls`, `cat`, `git status`, `rg`, …) | Runs immediately |
| Covered by an "allow always" grant | Runs immediately |
| The review model calls it routine (build, test, commit, …) | Runs immediately |
| Anything else (force push, upload, deletes, installs, …) | Asks you: **Allow once / Allow always / Deny** |
| Owner-only system command (`sudo`, `defaults write`, …) | Asks you: **Allow once / Deny** |
| Secret, protected file, `rm -rf ~` | Always blocked, never asked |

Approvals reach you wherever OpenClaw sends plugin approvals: buttons in Telegram, Discord or Slack, the Control UI, or `/approve` in chat. A run with no one to ask (a cron job with no delivery target) is blocked, never run unasked.

Prefer no model at all? Use `"mode": "ask"`: anything that isn't read-only or granted asks you.

## Configure

All options live under `plugins.entries.tripwire.config` in `~/.openclaw/openclaw.json`. Every one is optional. A typical setup:

```json5
{
  plugins: {
    entries: {
      tripwire: {
        enabled: true,
        hooks: { allowConversationAccess: true },   // only needed for execApproval mode "review"
        config: {
          hostGuard: {
            secretPaths: ["~/.config/my-app/token", "/srv/secrets"],
          },
          toolBudget: { maxCalls: 80, maxSeconds: 1200 },
          execApproval: { enabled: true, mode: "review", language: "en" },
        },
      },
    },
  },
}
```

See [docs/configuration.md](docs/configuration.md) for every option, and [examples/](examples/) for complete configs.

## Commands

| Command | What it does |
|---|---|
| `openclaw tripwire status [--json]` | Checks the setup, explains anything missing, runs the guard self-test, shows the last 24 hours |
| `openclaw tripwire test <command…> [--cwd dir] [--tool read\|write\|edit\|delete]` | Shows what Tripwire would decide. Nothing is run |
| `openclaw tripwire grants list` | Lists "allow always" grants |
| `openclaw tripwire grants remove <value>` / `clear` | Removes one grant, or all of them |
| `openclaw tripwire log [-n 20]` | Recent blocks, budget stops and approvals from the local log |

## What the host guard covers

**Secrets** (never read, copied or sent): `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.password-store`, `~/.local/share/keyrings`, `~/Library/Keychains`, `~/.openclaw/credentials`, `~/.openclaw/.env`, browser cookie and login databases, private SSH key files anywhere, and the macOS `security` tool. Add your own with `hostGuard.secretPaths`.

**Protected files** (readable, never written by the agent): `~/.openclaw/openclaw.json`, OpenClaw's state database, launchd and systemd unit folders, shell startup files, `/etc/sudoers`, `/etc/hosts`, and Tripwire's own files and state. Add your own with `hostGuard.protectedPaths`.

**Self-escalation** (owner-only, and approval is always "once"): changing OpenClaw approvals, exec policy, secrets, hooks or plugin settings; disabling or replacing Tripwire; unloading OpenClaw's own services.

**System commands** (owner-only): `sudo`/`su`, user and disk management, `defaults write`, `launchctl` load/unload, `systemctl enable/disable/mask`, crontab replacement, `killall`, shutdown. Password manager CLIs (`bw`, `op`, …) are owner-only too.

**Never allowed:** recursive deletion of your home folder, `~/.openclaw`, or top-level folders such as `~/Documents` and `~/Developer` (add more with `hostGuard.keepFolders`). Switching off TLS checks (`curl -k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, …) is blocked too.

The guard reads commands the way a shell would. It sees through quoting, `$(…)`, backticks, `sh -c`, AppleScript `do shell script`, `env`/`xargs`/`timeout`/`sudo` wrappers, `find -exec`, brace expansion, globs, `cd`, and the tool's working directory. It also checks the file tools (`read`, `write`, `edit`, `apply_patch`, …).

**It is not a sandbox.** An agent that can run arbitrary code can still write a program that reads a file. Tripwire stops the common and accidental cases, and makes the deliberate ones visible. If you need a hard boundary, run the agent in OpenClaw's sandbox mode or a container. See [SECURITY.md](SECURITY.md).

## Upgrade and uninstall

```bash
openclaw plugins update tripwire
openclaw plugins uninstall tripwire
```

Grants and the decision log stay in `~/.openclaw/state/tripwire/` until you delete that folder.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `openclaw tripwire: unknown command` | The plugin is not loaded. Run `openclaw plugins list`, then `openclaw plugins enable tripwire`. |
| `plugins inspect` warns *typed hook "before_prompt_build" blocked* | Set `plugins.entries.tripwire.hooks.allowConversationAccess` to `true`, or ignore it: approval works without it. |
| A command you need is blocked | Run `openclaw tripwire test <command>` to see the rule. If it's a project-specific secret or folder rule, change your config. If it's a false positive, please open an issue with the command. |
| Approvals never arrive | Check that your channel can show plugin approvals (`/approve` works in chat). Runs with no delivery target can't be asked and are blocked. |
| The agent stops with "Tripwire budget" | Raise `toolBudget.maxCalls` / `maxSeconds`, or add slow tools to `toolBudget.untimedTools`. |
| `execApproval.model` is ignored | Set `plugins.entries.tripwire.llm.allowModelOverride: true` (and add the model to `llm.allowedModels` if you restrict it). `openclaw tripwire status` checks this. |

## Develop

```bash
git clone https://github.com/Vicsbank/openclaw-tripwire.git
cd openclaw-tripwire
npm test            # unit and integration tests: no network, no OpenClaw needed
npm run test:e2e    # end-to-end against your installed OpenClaw (see below)
```

`npm run test:e2e` does what a new user does. It packs the checkout with `npm pack` and installs the tarball into a throw-away OpenClaw profile (`npm-pack:`, `--accept-capabilities`). Then it runs real agent turns against a scripted local model (`test/e2e/mock-model.mjs`: no network, no API key, no cost) and checks every tool result:

- secrets, protected files, self-escalation and TLS switches are blocked;
- the budget refuses repeats;
- granted commands run;
- unapproved commands do not;
- the review model is reached through `api.runtime.llm.complete`.

Afterwards it deletes the profile. Your real `~/.openclaw` is never touched. Set `KEEP_E2E=1` to keep the profile for debugging.

## License

MIT. See [LICENSE](LICENSE).
