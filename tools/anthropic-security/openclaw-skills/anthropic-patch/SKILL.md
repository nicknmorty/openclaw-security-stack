---
name: anthropic-patch
description: Generate inert candidate fixes for verified security findings.
---

# Anthropic Patch - OpenClaw Native Skill

This skill adapts Anthropic's defending-code `patch` workflow for OpenClaw.
It is self-contained for runtime use.

## When To Use

Use after triage has produced verified or needs-manual-test findings that need
candidate fixes.

## Safety

- Never apply diffs automatically.
- Never edit target source while generating patches.
- No `git apply`, `patch`, build, install, tests, Docker, or target execution
  in static mode.
- Write only inert artifacts under `PATCHES/`, `PATCHES.json`,
  `PATCHES.md`, or an explicitly requested security-stack run directory.
- Dynamic/pipeline patch validation must use approved off-Pi/container
  isolation.

## Static Patch Workflow

1. Ingest `TRIAGE.json`, `VULN-FINDINGS.json`, or generic finding JSON.
2. Prefer triaged true positives. Warn if input is unverified scanner output.
3. Resolve cited files under the repo.
4. For each selected finding, read the cited code and surrounding function.
5. Identify root cause before drafting a fix.
6. Search for sibling variants and account for them in the rationale.
7. Draft the smallest unified diff that fixes the root cause.
8. Include a regression test in the diff when an appropriate test location
   exists; otherwise explain why not.
9. Add independent reviewer notes: rationale, variants checked, bypass
   considered, and test note.

## Output

Write inert patch artifacts:

- `PATCHES/bug_NN/patch.diff`
- `PATCHES/bug_NN/patch_result.json`
- `PATCHES.json`
- `PATCHES.md`

There is no apply flag.
