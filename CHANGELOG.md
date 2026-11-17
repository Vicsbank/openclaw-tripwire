# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-16

First public release, extracted from a private OpenClaw setup where these rules have run in production since 2026-11-09.

### Added
- Host guard as a trusted tool policy: secret stores, protected files, self-escalation, destructive and system commands, recursive deletion of kept folders, TLS-check switches. Shell-aware: quoting, substitutions, `sh -c`, AppleScript, wrappers, `find -exec`, braces, globs, `cd` and the tool workdir.
- Tool budget as a trusted tool policy: calls, tool time, failures and exact repeats per run; re-reads after a successful edit are allowed; stateful, untimed and recovery tools are configurable.
- Exec approval through OpenClaw's native plugin approvals, with `review` (model) and `ask` (no model) modes, persistent "allow always" grants, and English and Simplified Chinese prompts.
- `openclaw tripwire` CLI: `status` (setup checks and self-test), `test` (dry run), `grants`, `log`.
- Local decision log.
- Works with OpenClaw profiles and `OPENCLAW_STATE_DIR` / `OPENCLAW_CONFIG_PATH`: the config, credentials and state of the active install are protected, not only `~/.openclaw`.
- End-to-end test (`npm run test:e2e`) that installs the packed tarball into a throw-away profile and drives real agent turns with a scripted local model.
