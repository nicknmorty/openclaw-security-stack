# OpenClaw Security Stack

Status: public working v1, Anthropic security adapter merged
Started: 2026-05-26
Owner: OpenClaw security maintainers
Collaborators: public contributors
Repository workflow: PR-first public collaboration

## Purpose

This repo is the OpenClaw security tooling lane. Its job is to help operators
review OpenClaw repos and runtime-adjacent code without leaking private data,
silently changing security policy, or generating noisy unactionable reports.

The current direction is to adapt Anthropic's published security skills and
reference harness into native OpenClaw skills. We are not reinventing those
workflows from scratch.

## Quick Start

One command runs every scanner against a target and writes a consolidated,
redacted, local-only report and chat-ready digest:

```bash
# ad-hoc single target
node scripts/security-scan.mjs --target /path/to/repo --label my-repo

# or configure targets once
cp security-scan.config.example.json security-scan.config.json   # edit targets
node scripts/security-scan.mjs

# optional: acknowledge accepted findings so the digest stays low-noise
cp security-suppressions.example.json security-suppressions.json
node scripts/security-scan.mjs --suppressions security-suppressions.json
```

The orchestrator runs `threat-model -> static-scan -> supply-chain ->
runtime-health`, turns each findings stream into a redacted report with `new` /
`persistent` / `resolved` state, and writes `runs/summary/SUMMARY.md` +
`SUMMARY.json` plus `runs/summary/DIGEST.txt`. All output is local-only and
redacted by default. Lanes are portable/generic and avoid hardcoded host
identity.

Start with the operator runbook for real use:

- [Security stack v1 operator runbook](runbooks/v1-operator-runbook.md)
- [v1 acceptance checklist](docs/V1_ACCEPTANCE.md)

Run tests with:

```bash
for f in scripts/test-*.mjs; do node "$f"; done
bash -n scripts/security-secret-guard.sh scripts/oauth-containment-audit.sh scripts/redact-sensitive-output.sh
git diff --check
```

## Current State

Merged PR #8 replaced the scratch-built tool line with an Anthropic-aligned
adapter:

- vendored Anthropic security skill/reference files for provenance and review,
- self-contained OpenClaw-native skills derived from those workflows,
- an adapter manifest mapping upstream skills to OpenClaw lanes,
- an explicit-destination sync script for preview/install copies,
- tests that verify required upstream files, wrapper safety language, manifest
  coverage, and install-layout behavior.

The skills are not installed live yet. They are staged in this repo for review
and controlled rollout. The v1 scanner CLIs are usable directly from this repo.

## Security Workflow

The adapted workflow follows the Anthropic defending-code shape:

```text
quickstart -> threat model -> vuln scan -> triage -> patch -> customize/sandbox plan
```

OpenClaw-specific constraints:

- static review skills must not execute target code,
- patch work emits review-only drafts and must not silently edit target repos,
- dynamic or sandboxed verification stays off-Pi/containerized until explicitly
  approved,
- secrets, auth stores, OpenClaw memory, and home directories must not be
  mounted into scanner sandboxes,
- Chat summaries must be redacted and should not include private evidence.

## Main Components

- `tools/anthropic-security/upstream/` - vendored Anthropic source material for
  provenance and review.
- `tools/anthropic-security/openclaw-skills/` - self-contained OpenClaw skill
  wrappers adapted from Anthropic workflows.
- `tools/anthropic-security/openclaw-adapter.json` - machine-readable mapping
  from upstream skills/commands to OpenClaw lanes and wrappers.
- `scripts/sync-openclaw-security-skills.mjs` - copies wrappers to an explicit
  skills directory; refuses overwrites unless `--force`.
- `scripts/test-anthropic-security-adapter.mjs` - verifies adapter integrity,
  wrapper safety contracts, license presence, and sync behavior.
- `scripts/security-threat-model.mjs` and `scripts/security-static-scan.mjs` -
  local static helper CLIs.
- `scripts/security-supply-chain.mjs`, `scripts/security-runtime-health.mjs`,
  and `scripts/security-scan.mjs` - supply-chain posture, portable runtime
  health, and the v1 orchestrator.
- `scripts/security-report.mjs` and `scripts/security-digest.mjs` - redacted
  stateful reports and low-noise digest rendering.
- `scripts/security-secret-guard.sh`, `scripts/oauth-containment-audit.sh`, and
  `scripts/redact-sensitive-output.sh` - sanitized local guard helpers for
  secret-boundary checks, OAuth/token containment, and redacted diagnostics.
  See [Security guard scripts](docs/SECURITY_GUARD_SCRIPTS.md) for the exact
  files they can create, delete, strip, or chmod and why those actions reduce
  credential exposure.

## Usage

Preview the staged OpenClaw skills without touching live skills:

```bash
node scripts/sync-openclaw-security-skills.mjs \
  --install-dir /tmp/openclaw-security-skills-preview
```

Overwrite an existing preview directory:

```bash
node scripts/sync-openclaw-security-skills.mjs \
  --install-dir /tmp/openclaw-security-skills-preview \
  --force
```

Run the repo checks:

```bash
for f in scripts/test-*.mjs; do node "$f"; done
bash -n scripts/security-secret-guard.sh scripts/oauth-containment-audit.sh scripts/redact-sensitive-output.sh
git diff --check
```

## Project Map

- [Contributing / PR policy](CONTRIBUTING.md)
- [Anthropic security adaptation](docs/ANTHROPIC_SECURITY_ADAPTATION.md)
- [Anthropic security adapter](tools/anthropic-security/README.md)
- [Defending Code harness scope](docs/DEFENDING_CODE_HARNESS_SCOPE.md)
- [Security guard scripts](docs/SECURITY_GUARD_SCRIPTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Security stack v1 operator runbook](runbooks/v1-operator-runbook.md)
- [v1 acceptance checklist](docs/V1_ACCEPTANCE.md)
- [OpenClaw hardening vectors](vectors/openclaw-hardening.md)
- [Security audit cadence](runbooks/security-audit-cadence.md)
- [Threat model helper](tools/threat-model/README.md)
- [Static scan helper](tools/static-scan/README.md)
- [Supply-chain helper](tools/supply-chain/README.md)
- [Runtime-health helper](tools/runtime-health/README.md)
- [Report helper](tools/report/README.md)
- [Digest helper](tools/digest/README.md)
- [Suppressions helper](tools/suppressions/README.md)

## Directory Map

- `docs/` - design notes, adaptation records, security model, and review scope.
- `tools/` - security tool modules, adapters, wrappers, and provenance sources.
- `scripts/` - verification scripts and operator entrypoints.
- `tests/fixtures/` - lightweight fixtures for local checks.
- `vectors/` - security vectors and hardening maps.
- `runbooks/` - operator procedures and recurring audit cadence.
- `runs/` - local scan outputs. Keep untracked, private, and redacted before sharing.
- `state/` - local state used for diffing new/persistent/resolved findings; keep real state untracked.

## Next Work

1. Decide the live OpenClaw skills distribution path for these wrappers.
2. Install/sync the wrappers only after explicit review and approval.
3. Add optional CVE/advisory intelligence for supply-chain findings.
4. Dogfood `anthropic-quickstart`, `anthropic-threat-model`, and
   `anthropic-vuln-scan` on selected OpenClaw repos.
5. Decide whether the local bootstrap CLIs become support commands, fixtures,
   or are retired in favor of the skill workflows.
