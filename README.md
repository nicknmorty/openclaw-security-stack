# OpenClaw Security Stack

Status: public preview, Anthropic security adapter merged
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
and controlled rollout.

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
  local static helper CLIs from the earlier bootstrap phase. Keep them as
  support/reference until replaced or wrapped by the Anthropic-aligned skills.

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
node scripts/test-anthropic-security-adapter.mjs
node scripts/test-security-threat-model.mjs
node scripts/test-security-static-scan.mjs
git diff --check
```

## Project Map

- [Contributing / PR policy](CONTRIBUTING.md)
- [Backlog](BACKLOG.md)
- [Anthropic security adaptation](docs/ANTHROPIC_SECURITY_ADAPTATION.md)
- [Anthropic security adapter](tools/anthropic-security/README.md)
- [Defending Code harness scope](docs/DEFENDING_CODE_HARNESS_SCOPE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Premortem](docs/PREMORTEM.md)
- [OpenClaw hardening vectors](vectors/openclaw-hardening.md)
- [Security audit cadence](runbooks/security-audit-cadence.md)
- [Threat model helper](tools/threat-model/README.md)
- [Static scan helper](tools/static-scan/README.md)

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
3. Dogfood `anthropic-quickstart`, `anthropic-threat-model`, and
   `anthropic-vuln-scan` on selected OpenClaw repos.
4. Decide whether the local bootstrap CLIs become support commands, fixtures,
   or are retired in favor of the skill workflows.
5. Add redacted report state/diffing for `new`, `persistent`, and `resolved`
   findings.
