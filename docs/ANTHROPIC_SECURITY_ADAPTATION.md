# Anthropic Security Adaptation

Status: adapter merged in PR #8
Date: 2026-06-05

## Correction

This project should adapt Anthropic's security skill and reference-harness
workflow for OpenClaw compatibility. It should not reimplement the same
workflow from scratch.

The prior scratch-built PRs for triage, variant finding, patch drafting, and
dynamic verification were closed as superseded. Their shape may still be useful
as local report glue, but the replacement work should stay anchored to
Anthropic's upstream workflow.

## Upstream Provenance

Primary upstream:

- `anthropics/defending-code-reference-harness`
  - skills: `quickstart`, `threat-model`, `vuln-scan`, `triage`, `patch`,
    `customize`
  - helper: `_lib/checkpoint.py`
  - docs: sandbox, pipeline, patching, customization

Secondary upstream:

- `anthropics/claude-code-security-review`
  - `/security-review` slash command
  - PR diff-aware review methodology and false-positive rules

## OpenClaw Adaptation Target

The installable OpenClaw skills must be self-contained. They should not require
the vendored upstream files after sync; upstream paths and commits are kept as
review/provenance metadata.

OpenClaw compatibility should preserve the upstream workflow:

```text
threat model -> static scan -> triage -> patch -> sandboxed pipeline/customize
```

Adaptation work should focus on:

- translating Claude Code skill/tool permissions into OpenClaw tool
  availability and safety gates,
- preserving upstream output contracts such as `THREAT_MODEL.md`,
  `VULN-FINDINGS.json`, `TRIAGE.json`, and `PATCHES/`,
- preserving checkpoint/resume behavior,
- adding OpenClaw-safe report locations and redacted chat summaries,
- keeping dynamic execution behind approved off-Pi/container isolation.

## Completed Rework

PR #8 completed the initial correction:

1. Imported upstream skill sources under `tools/anthropic-security/upstream/`.
2. Added a machine-readable OpenClaw adapter manifest.
3. Added OpenClaw skill wrappers that translate Claude Code tool assumptions into
   OpenClaw-safe operating rules.
4. Added a sync script that copies wrappers to an explicit install directory
   without touching live skills by default.
5. Added tests that fail if required upstream files, wrappers, or safety language are
   missing.

## Remaining Work

1. Wire the wrappers into the chosen live OpenClaw skills distribution path.
2. Dogfood the OpenClaw-native skills on selected target repos.
3. Decide whether the earlier local threat-model/static-scan CLIs remain support
   commands, become fixtures, or are retired behind the skill workflows.
4. Reopen tool-specific work only after each PR is anchored to an upstream skill
   or command.

## Non-Goals

- Do not port the autonomous C/C++ pipeline to run on the Pi.
- Do not silently apply patches to target repos.
- Do not mount OpenClaw secrets, memory, auth stores, or home directories into
  scanner sandboxes.
- Do not treat static findings as verified vulnerabilities.
