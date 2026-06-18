# Contributing

## Collaboration Model
This project uses pull requests for public collaboration and review.

Product changes should be proposed through pull requests so maintainers can
review design, safety, and implementation together. Direct pushes to `main` are
reserved for bootstrap, emergency maintainer repair, or explicitly approved
administrative changes.

Simple operating rule:

1. branch for changes
2. open a pull request with a threat/risk note and test evidence
3. get review from whoever owns the affected lane before merge

## Pull Request Expectations
Every product PR should include:

- the problem being solved
- the files or subsystem changed
- the affected security lane and intended reviewer
- a threat/risk note
- the verification performed
- any security, privacy, path, or secret-handling impact
- follow-up work that should remain open

Security-sensitive changes require explicit maintainer review before merge. This includes:

- access, permission, auth, or ownership changes
- automation that writes files, edits config, restarts services, or remediates findings
- changes that collect, transmit, or expose private logs, paths, memory content, or credentials
- dependency, package, skill, plugin, or supply-chain enforcement changes

## Default Engineering Rules
- Prefer read-only detection before remediation.
- Keep reports local-first and redacted by default.
- Do not include secrets or private corpus data in fixtures.
- Use synthetic fixtures for public-facing tests and examples.
- Make risky behavior opt-in and documented.

## Branch Policy
The default branch should stay protected. Use pull requests for normal product
changes and keep `main` releasable.

- feature and product work happens on branches
- merge through pull request review
- affected lane owners review before merge
- use maintainer review for security-sensitive changes
- keep `main` releasable and reviewable
