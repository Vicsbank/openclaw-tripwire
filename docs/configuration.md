# Configuration

Every option lives under `plugins.entries.tripwire.config` and is optional. Unknown keys are rejected, so a typo shows up in `openclaw config validate` instead of being ignored silently.

After a change, run `openclaw plugins reload tripwire` (or restart the Gateway) and `openclaw tripwire status`.

| Option | Type | Default | Meaning |
|---|---|---|---|
| `dataDir` | string | `<OpenClaw state>/state/tripwire` | Where grants and the decision log are kept. Default <OpenClaw state>/state/tripwire. |

## hostGuard

Deterministic rules that run before every tool call.

| Option | Type | Default | Meaning |
|---|---|---|---|
| `hostGuard.enabled` | boolean | `true` | Turn the host guard on. Default true. |
| `hostGuard.agents` | string[] | — | Agent ids to guard. Empty (default) guards every agent. |
| `hostGuard.secretPaths` | string[] | — | Extra secret files or folders (~ allowed). Added to the built-in list (~/.ssh, ~/.aws, ~/.openclaw/credentials, keychains, …). |
| `hostGuard.protectedPaths` | string[] | — | Extra files or folders the agent may read but never write, move or delete. |
| `hostGuard.keepFolders` | string[] | — | Extra folders that recursive rm may never remove. |
| `hostGuard.protectOpenClawConfig` | boolean | `true` | Block direct writes to ~/.openclaw/openclaw.json and openclaw config set on plugin/exec/hook/approval settings. Default true. |
| `hostGuard.protectPluginFiles` | boolean | `true` | Block agent writes anywhere in this plugin folder, not only its policy files. Default true. |
| `hostGuard.blockInsecureTls` | boolean | `true` | Block commands that switch off TLS certificate checks (curl -k, NODE_TLS_REJECT_UNAUTHORIZED=0, …). Default true. |

## toolBudget

Per-run limits that stop an agent that is looping.

| Option | Type | Default | Meaning |
|---|---|---|---|
| `toolBudget.enabled` | boolean | `true` | Turn the budget on. Default true. |
| `toolBudget.agents` | string[] | — | Agent ids to limit. Empty (default) limits every agent. |
| `toolBudget.maxCalls` | integer | `60` | Tool calls per run. Default 60. |
| `toolBudget.maxSeconds` | integer | `900` | Seconds spent inside tools per run (model thinking time does not count). Default 900. |
| `toolBudget.maxFailures` | integer | `8` | Failed tool calls per run. Default 8. |
| `toolBudget.refuseRepeats` | boolean | `true` | Refuse an exact repeat of a call that already ran in the run. Re-reads after a successful edit are allowed. Default true. |
| `toolBudget.execTimeoutCapSeconds` | integer | `0` | If above 0, every exec runs in the foreground with at most this timeout. Default 0 (off). |
| `toolBudget.statefulTools` | string[] | — | Tools whose identical calls are new evidence (counted, never refused as repeats). browser, computer and process are always included. |
| `toolBudget.untimedTools` | string[] | — | Slow tools with their own timeouts; their time does not count toward maxSeconds. |
| `toolBudget.recoveryTools` | string[] | — | Sign-in or recovery tools. A successful call forgives one failure and lets a failed call run once more. |

## execApproval

Review host shell commands and ask the owner through OpenClaw plugin approvals.

| Option | Type | Default | Meaning |
|---|---|---|---|
| `execApproval.enabled` | boolean | `false` | Turn exec approval on. Default false. |
| `execApproval.mode` | `review` \| `ask` | `"review"` | review: a model allows routine commands and asks you about the rest. ask: every command that is not read-only or granted asks you. |
| `execApproval.agents` | string[] | — | Agent ids to review. Empty (default) reviews every agent. |
| `execApproval.model` | string | — | Review model (provider/model). Default: the host default model. Setting it needs llm.allowModelOverride. |
| `execApproval.language` | `en` \| `zh-CN` | `"en"` | Language of approval prompts and review reasons. |
| `execApproval.askTimeoutSeconds` | integer | `240` | How long an approval waits before the command is blocked. Default 240. |
| `execApproval.reviewTimeoutSeconds` | integer | `20` | Time limit for one model review; on timeout the owner is asked. Default 20. |
| `execApproval.maxAsksPerRun` | integer | `3` | Approvals one run may request before further commands are blocked. Default 3. |
| `execApproval.readOnlyCommands` | string[] | — | Extra command names that are read-only and never need review (e.g. your own status CLIs). |

## Settings outside `config`

These live next to `config` in `plugins.entries.tripwire`, not inside it:

| Setting | When you need it |
|---|---|
| `hooks.allowConversationAccess: true` | `execApproval.mode` is `"review"` and you want the reviewer to see the owner's request. Without it the reviewer sees only the command. |
| `llm.allowModelOverride: true` | You set `execApproval.model`. Without an explicit model the host's default model reviews, and nothing extra is needed. |
| `llm.allowedModels: [...]` | You restrict which models plugins may use. It must then include `execApproval.model`. |

## Paths

`secretPaths`, `protectedPaths` and `keepFolders` accept absolute paths and `~/…`. A folder covers everything inside it. Globs are not needed (and not accepted) in config: the guard already expands the globs and braces the agent writes and checks the result against your folders.

## Examples

- [examples/minimal.json5](../examples/minimal.json5): defaults, nothing to configure
- [examples/with-approval.json5](../examples/with-approval.json5): exec approval with a model reviewer
- [examples/strict.json5](../examples/strict.json5): ask for everything that is not read-only, tighter budget, extra secrets
