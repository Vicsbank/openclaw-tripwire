# Security model

## What Tripwire is for

Tripwire is for an OpenClaw agent that has real access to your machine: shell, files, browser. It assumes the model is usually helpful but can be wrong, confused, or steered by text it reads (a web page, an e-mail, a file). It stops the actions that would hurt most when that happens:

- reading or sending your secrets;
- changing the rules the agent runs under, including Tripwire itself;
- destroying data or system configuration;
- looping and burning time and money.

Its rules are deterministic code. Conversation text cannot change them, and a model never decides whether a hard rule applies.

## What Tripwire is not

- **Not a sandbox.** The guard matches what a command *says*, very carefully, but it does not watch what a program *does*. An agent that writes and runs its own program can still open a file. For a hard boundary, use OpenClaw's sandbox mode, a container, or a separate OS user. Tripwire still helps there: it makes such attempts stand out, and it blocks the accidental cases.
- **Not a replacement for OpenClaw's exec approvals.** It runs alongside them. When both are on, a command must pass both.
- **Not network filtering.** It blocks switching off TLS checks, but not where data is sent. In review mode, the reviewer is told to ask before uploads and third-party sends.

## Order of checks

1. **Host guard** (trusted tool policy, before ordinary plugin hooks). Hard rules block. Owner-only rules ask once when exec approval is on, and block otherwise.
2. **Tool budget** (trusted tool policy). Blocks with a reason once a run is over its limits.
3. **Exec approval** (`before_tool_call` hook). Read-only and granted commands run. In review mode a model judges the rest. Anything not clearly fine asks you through OpenClaw plugin approvals.

If the review model fails, times out or answers nonsense, Tripwire asks you. If no approval surface can reach you, OpenClaw blocks the call. Nothing fails open.

## Stored data

- `tripwire-grants.json`: your "allow always" decisions (command prefixes such as `git push`, or exact commands). File mode 0600. The agent cannot write it.
- `events.jsonl`: a local log of blocks, budget stops and approval requests. It includes the command text, clipped to 300 characters, so you can see what was stopped. File mode 0600. It rotates at about 1 MB and is never sent anywhere.

Both live in `~/.openclaw/state/tripwire/` (or your `dataDir`).

## Reporting a vulnerability

A bypass is a command or tool call that reads a covered secret, writes a protected file, or removes a kept folder without being blocked. Please report bypasses privately through GitHub's "Report a vulnerability" button on the repository's Security tab rather than in a public issue. Include the exact tool call (tool name and arguments) and your OpenClaw version.

False positives (a harmless command that is blocked) are welcome as normal issues.
