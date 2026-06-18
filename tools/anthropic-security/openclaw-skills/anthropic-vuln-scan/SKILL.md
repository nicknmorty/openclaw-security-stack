---
name: anthropic-vuln-scan
description: Run an Anthropic-style static vulnerability scan in OpenClaw.
---

# Anthropic Vulnerability Scan - OpenClaw Native Skill

This skill adapts Anthropic's defending-code `vuln-scan` workflow for OpenClaw.
It is self-contained for runtime use; upstream files are provenance only.

## When To Use

Use after `anthropic-threat-model`, or when asked to statically review code for
security vulnerabilities.

## Safety

- Never execute target code.
- No build, install, tests, Docker, fuzzing, or network probing.
- Prefer bounded read-only commands: `rg --files`, `rg -n`, `sed`, `wc`,
  `head`, `file`, `git diff`, and `git log`.
- Do not follow symlinks or `..` outside the target.
- Findings are static candidates, not verified vulnerabilities.

## Workflow

1. Resolve the target directory and count source files.
2. Read `THREAT_MODEL.md` if present. Use its entry points and threats as
   focus areas.
3. If no threat model exists, do quick recon and propose 3-10 focus areas such
   as message ingestion, route handlers, file parsing, auth decisions, tool
   execution, memory writes, plugin loading, and secret/config handling.
4. For each focus area, review source for concrete exploit paths.
5. On small targets or low Pi headroom, scan sequentially. Use Codex subagents
   only after the Pi resource guard passes.
6. Keep all findings, but score confidence. Triage removes false positives.
7. Write `VULN-FINDINGS.json` and `VULN-FINDINGS.md`.

## Reporting Bar

Report plausible exploit paths with file and line evidence. Skip:

- test, fixture, generated, docs, or notebook-only findings,
- pure best-practice gaps with no attack story,
- env vars or CLI flags as attacker-controlled input unless the system model
  makes that true,
- generic rate limiting, resource exhaustion, open redirect, regex injection,
  log spoofing, missing audit logs, or outdated dependency noise,
- framework-escaped XSS unless raw HTML escape hatches are used.

## Finding Shape

Each finding should include:

- `id`
- `file`
- `line`
- `category`
- `severity`
- `confidence`
- `title`
- `description`
- `exploit_scenario`
- `recommendation`
- optional `confidence_reason`

## Output

Report counts, top findings by confidence, and the next step:

`anthropic-triage <target>/VULN-FINDINGS.json --repo <target>`
