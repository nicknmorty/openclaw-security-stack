# Bumblebee

Status: candidate input source

## Fit
Bumblebee belongs in the supply-chain exposure lane.

It answers:

```text
Do I currently have a known-bad package/version somewhere?
```

It does not prove:
- that malicious code executed
- that a host is compromised
- that all package risk has been found
- that runtime posture is safe

## Security Stack Role
Treat Bumblebee-style findings as one background sensor feeding the broader security stack.

Candidate workflow:
1. Inventory project manifests and lockfiles.
2. Match exact package/version exposure intel.
3. Normalize findings into the stack report schema.
4. Classify as `new`, `persistent`, or `resolved`.
5. Redact paths/package context before group summaries when needed.

## V0 Questions
- Is Bumblebee a direct dependency, an optional adapter, or just a pattern to emulate?
- Which ecosystems matter first: npm, Python, both, or more?
- How should acknowledged package-exposure findings be suppressed without hiding real regressions?

