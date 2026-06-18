# OpenClaw Skill Wrappers

These are self-contained OpenClaw-facing skills adapted from Anthropic's
upstream security workflows. The vendored upstream files are provenance and
review material; synced skills must be usable without `../../upstream` paths.

Use `scripts/sync-openclaw-security-skills.mjs` to copy these wrappers into an
OpenClaw skills directory for review or installation. The script requires an
explicit destination and refuses overwrites unless `--force` is provided.

The wrappers do not grant extra tools by themselves. They translate the
upstream Claude Code assumptions into OpenClaw operating rules:

- use `rg`, `sed`, `git`, and bounded file reads for static analysis,
- use `apply_patch` only for files inside the security-stack repo,
- do not execute target code during static skills,
- do not use Claude Code `Task` or `AskUserQuestion` as literal tool names,
- use Codex subagents only after the Pi resource guard passes,
- keep dynamic harness execution off-Pi/containerized.
