---
name: anthropic-security-review
description: Perform Anthropic-style diff-aware security review in OpenClaw.
---

# Anthropic Security Review - OpenClaw Skill Wrapper

This skill adapts Anthropic's Claude Code `/security-review` command for
OpenClaw. It is self-contained for runtime use.

## When To Use

Use when asked for a security review of a branch, PR, or pending diff.

## Safety

- Read-only review.
- Use only git/file inspection commands such as `git status`, `git diff`,
  `git log`, `git show`, `rg`, and file reads.
- Do not write files, run tests, install dependencies, execute target code, or
  reach the network unless explicitly asked for separate investigation.

## Method

1. Capture branch status, changed file list, commits, and merge-base diff.
2. Understand repository security context and existing secure patterns.
3. Review only security risk introduced by the diff.
4. Focus on concrete, high-confidence vulnerabilities with real exploitation
   potential.
5. Apply false-positive filtering before reporting.

## Reportable Categories

- Injection: SQL, command, XXE, template, NoSQL, path traversal.
- Auth/authz: bypass, privilege escalation, session flaws.
- Code execution: unsafe deserialization, eval, unsafe dynamic execution.
- Data exposure: secrets, PII, sensitive data in logs/responses.
- Crypto: weak algorithms, bad randomness, certificate validation bypass.
- XSS only when framework escaping is bypassed.

## Do Not Report

- Theoretical hardening gaps.
- Missing rate limits, generic DoS, resource exhaustion.
- Log spoofing, open redirects, regex injection.
- Outdated third-party dependencies.
- Test/docs-only issues.
- Client-side auth gaps where backend validation is the real boundary.

## Output

If issues are found, report markdown findings with file, line, severity,
category, description, exploit scenario, and fix recommendation. If no
high-confidence issues are found, say that clearly.
