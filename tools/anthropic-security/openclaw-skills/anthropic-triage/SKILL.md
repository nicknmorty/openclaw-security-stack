---
name: anthropic-triage
description: Verify, dedupe, rank, and route security scanner findings.
---

# Anthropic Triage - OpenClaw Skill Wrapper

This skill adapts Anthropic's defending-code `triage` workflow for OpenClaw.
It is self-contained for runtime use.

## When To Use

Use on `VULN-FINDINGS.json`, scanner output, pipeline results, or markdown
security reports when findings need verification and prioritization.

## Safety

- Do not execute target code.
- Do not build, install, fuzz, run tests, or reach the network.
- Verification is by source reading and adversarial reasoning.
- Use checkpoint files for large batches; do not pass target-derived payloads
  through shell heredocs.

## Workflow

1. Parse arguments: findings path, optional repo path, vote count, auto mode,
   false-positive rules, and fresh/resume behavior.
2. Ingest findings from JSON, JSONL, markdown, or pipeline result directories.
3. Normalize fields without guessing missing data.
4. Resolve cited files under the repo. Unlocatable findings become manual-test
   items, not confident true positives.
5. Deduplicate by root cause before expensive verification.
6. Verify each canonical finding with adversarial checks. Use sequential review
   by default on the Pi; use Codex subagents only after resource guard passes.
7. Apply false-positive rules, exploitability scoring, owner/component routing,
   and severity ranking.
8. Write `TRIAGE.json` and `TRIAGE.md`.

## Output Contract

Triage output should distinguish:

- true positive,
- false positive,
- duplicate,
- needs manual test,
- unlocatable or insufficient evidence.

Include rationale, evidence, owner/component hint, severity, confidence, and
duplicate relationships.

## User Context

If not in auto mode and context is unclear, ask only the questions that affect
ranking: environment/trust boundary, worst-case attacker, scoring standard, and
noise tolerance.
