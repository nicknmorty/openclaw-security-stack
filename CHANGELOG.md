# Changelog

All notable public changes to OpenClaw Security Stack are documented here.

This project uses pragmatic release notes rather than a strict package-manager
versioning contract for now. Scanner findings are review candidates, not
automated remediation.

## v1.0.0 - 2026-06-22

Working public v1 of the local-first scanner stack.

### Added

- Root MIT license for original project code.
- Third-party notices for vendored/adapted Anthropic MIT and Apache-2.0
  upstream material.
- One-command scan orchestrator: `node scripts/security-scan.mjs`.
- Four read-only lanes behind the orchestrator:
  - `threat-model`
  - `static-scan`
  - `supply-chain`
  - `runtime-health`
- Redacted report core with stable finding fingerprints and stateful
  `new` / `persistent` / `resolved` grouping.
- Per-tool report state namespacing so scanner lanes do not cross-resolve each
  other's findings.
- Supply-chain posture scanner for npm and Python manifests/lockfiles:
  unpinned deps, missing lockfiles, non-registry dependency sources, and
  unpinned Python requirements.
- Portable runtime-health scanner for listening sockets, SSH config, SSH
  private-key permissions, opt-in sensitive-file permissions, and firewall
  presence, with graceful skips when host tools or permissions are unavailable.
- Acknowledge/ignore workflow through `security-suppressions.json`, supporting
  exact fingerprints, match rules, and optional expiry.
- Low-noise digest output at `runs/summary/DIGEST.txt`.
- Public-safe operator docs:
  - `runbooks/v1-operator-runbook.md`
  - `docs/V1_ACCEPTANCE.md`
- Public-safe examples:
  - `security-scan.config.example.json`
  - `security-suppressions.example.json`
  - `reference/security/identity-denylist.example.json`
- Tests for reporting, suppressions, digest rendering, orchestrator behavior,
  supply-chain scanning, runtime-health scanning, and static-scan tuning.

### Changed

- Static scan now uses tiered taint confidence:
  strong source hints keep base severity, weak source hints downgrade one notch
  and reduce confidence.
- Static scan denoises common exception-property idioms such as `err.message`
  and `error.stack` before taint classification.
- README now presents the v1 scanner command as the public front door.
- Local operator config and state files are explicitly ignored:
  - `security-scan.config.json`
  - `security-suppressions.json`
  - `reference/security/identity-denylist.json`
  - `runs/`
  - `state/`

### Verification

- Full public test suite passed with `scripts/test-*.mjs`.
- Guard shell scripts passed syntax checks.
- Public dogfood scan ran all four lanes successfully.
- Custom identity/environment scan passed.
- `gitleaks` passed against both the working tree and committed history.

### Known Limits

- Supply-chain findings are deterministic posture checks, not CVE/advisory
  intelligence.
- Static findings are candidates for review, not proof of exploitability.
- Runtime-health is a portable baseline, not a complete host hardening audit.
- No automated remediation.
- Scheduling/cron wiring is intentionally left to operators.

## v0 - 2026-06-17

Initial public preview of the OpenClaw security tooling lane.

### Added

- Public project shell with generic README, contributing policy, architecture
  notes, security model, and recurring audit cadence.
- Anthropic-aligned security adapter materials:
  - adapter manifest
  - self-contained OpenClaw-facing skill wrappers
  - explicit-destination sync script
  - adapter integrity tests
- Bootstrap helper CLIs:
  - `scripts/security-threat-model.mjs`
  - `scripts/security-static-scan.mjs`
- Public-safe guard helpers:
  - `scripts/security-secret-guard.sh`
  - `scripts/oauth-containment-audit.sh`
  - `scripts/redact-sensitive-output.sh`
- Guard-script documentation describing which files the scripts may create,
  delete, strip, or chmod when run with explicit remediation flags.
- Initial fixtures and tests for adapter integrity, threat-model helper,
  static-scan helper, and guard scripts.

### Security And Privacy

- Public tree was sanitized from the private development overlay.
- Private status docs, generated reports, local state, deployment-specific
  hardening notes, and local runtime details were excluded.
- Examples used generic placeholders rather than real operator data.

### Known Limits

- v0 was a public preview, not a complete scanner stack.
- Reporting, stateful finding diffs, supply-chain posture, runtime-health,
  suppressions, and digest output arrived in v1.
