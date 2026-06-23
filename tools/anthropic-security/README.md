# Anthropic Security Upstream Adapter

This directory is the source-referenced OpenClaw compatibility lane for
Anthropic's security workflows.

The goal is not to replace Anthropic's implementation or claim parity with the
autonomous Python/Docker/gVisor reference harness. The current goal is to adapt
the upstream skills into OpenClaw workflow wrappers, preserve provenance, and
connect those workflows to local-first reporting, scoped writes, redaction, and
explicit operator approval boundaries.

## Upstream Sources

- `anthropics/defending-code-reference-harness`
  - imported commit: `9e0f6c6cd54fc3b8ce79708e8208d862634a2624`
  - imported paths:
    - `.claude/skills/`
    - selected `docs/` safety and pipeline references
- `anthropics/claude-code-security-review`
  - imported commit: `0c6a49f1fa56a1d472575da86a94dbc1edb78eda`
  - imported path:
    - `.claude/commands/security-review.md`

## Imported Skill Contracts

Anthropic's defending-code repo provides the source workflow:

- `quickstart`
- `threat-model`
- `vuln-scan`
- `triage`
- `patch`
- `customize`
- `_lib/checkpoint.py`

The OpenClaw project should adapt these contracts, prompts, schemas, and safety
rules rather than inventing unrelated workflows. Upstream drift must be checked
explicitly before making strong alignment claims.

## OpenClaw Compatibility Work

Compatibility work should focus on:

- installing or exposing these skills in an OpenClaw-friendly location,
- translating Claude Code tool names and permissions into OpenClaw capabilities,
- keeping all static skills read/write-only within the target/report scope,
- preserving Anthropic checkpoint state behavior,
- keeping autonomous execution behind an approved off-Pi/container lane,
- producing local report artifacts suitable for OpenClaw scheduling and
  chat summaries without leaking private evidence.

The deterministic JavaScript scanner CLIs in this repo are local OpenClaw
support tooling. They are useful, but they are separate from Anthropic's
autonomous vulnerability-discovery loop.

## OpenClaw Skill Wrappers

The installable OpenClaw-facing wrappers live under:

`tools/anthropic-security/openclaw-skills/`

They are self-contained OpenClaw skill wrappers inspired by Anthropic's
workflow. The vendored upstream files remain in this repo for provenance and
review, not as runtime files required by synced skills. To copy the wrappers
into a skills directory for review:

```bash
node scripts/sync-openclaw-security-skills.mjs \
  --install-dir /path/to/openclaw/skills/preview \
  --force
```

The sync script requires an explicit destination and does not modify live
OpenClaw skills unless an operator deliberately points it at that directory.

## Not Yet Done

This import now includes self-contained OpenClaw wrappers, but it does not
automatically install or enable them. Follow-up PRs should wire the wrappers
into the chosen OpenClaw runtime/skill distribution path while keeping the
upstream provenance visible in review.
