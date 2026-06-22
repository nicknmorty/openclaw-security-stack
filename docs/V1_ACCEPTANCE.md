# v1 Acceptance Checklist

Status: accepted candidate
Updated: 2026-06-22

## Release Definition

Working v1 means a portable operator can run one local read-only command against
a target, receive redacted stateful reports, suppress accepted noise without
losing state, and share a low-noise digest with a trusted review channel.

Public release, cron integration, CVE/advisory intelligence, dynamic sandboxed
testing, and automated remediation are explicitly out of scope for v1.

## Required Criteria

- [x] One front-door command runs the stack:
  `node scripts/security-scan.mjs`.
- [x] Four read-only lanes are wired by default: threat-model, static-scan,
  supply-chain, runtime-health.
- [x] Reports are local-only and redacted by default.
- [x] Findings use stable fingerprints and `new` / `persistent` / `resolved`
  state.
- [x] Per-tool state is namespaced so scanners do not resolve each other's
  findings.
- [x] Suppressions acknowledge accepted findings by fingerprint or rule, with
  optional expiry.
- [x] Suppressions are view-layer only and do not delete scan state.
- [x] Acknowledged findings are excluded from active severity totals.
- [x] The orchestrator writes a low-noise `runs/summary/DIGEST.txt`.
- [x] Static-scan severity/confidence has a first tuning pass: strong vs weak
  taint, weak downgrade, confidence penalty, and benign error-property
  denoising.
- [x] Runtime-health checks skip gracefully when host tools or permissions are
  unavailable.
- [x] Operator setup and triage are documented in
  `runbooks/v1-operator-runbook.md`.
- [x] No scanner performs automated remediation or policy changes.
- [x] Public repo remains untouched.

## Verification Evidence

Local suite on 2026-06-22:

```text
ok test-anthropic-security-adapter
ok test-security-digest
ok test-security-report
ok test-security-runtime-health
ok test-security-scan
ok test-security-static-scan-tuning
ok test-security-static-scan
ok test-security-supply-chain
ok test-security-suppressions
ok test-security-threat-model
ALL_GREEN
```

Dogfood scan on 2026-06-22:

```text
Active: new 35 / persistent 0 / acknowledged 22 / resolved 0
Severity (active): HIGH 0 / MEDIUM 4 / LOW 31
Tools: 4 ran ok
```

The dogfood run used:

```bash
node scripts/security-scan.mjs \
  --target . \
  --label openclaw-security-stack \
  --out-root /tmp/openclaw-security-stack-dogfood \
  --suppressions security-suppressions.example.json \
  --quiet
```

## v1 Known Limits

- Findings are review candidates, not proof of exploitability.
- Supply-chain posture is deterministic and does not include advisory lookup.
- Runtime-health is a portable baseline, not a full host hardening audit.
- Scheduling/cron wiring is intentionally separate from this repo.
- Wider distribution requires the normal public-release gate and maintainer
  approval.

## Release Gate

This checklist is sufficient to tag a private working v1 after the docs change
lands and the suite is green on the tagged commit.
