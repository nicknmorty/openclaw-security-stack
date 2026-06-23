# Security Stack v1 Operator Runbook

Status: v1 front-door runbook
Updated: 2026-06-22

## Purpose

Run the OpenClaw security stack against a repo or host-adjacent project, review
new findings, acknowledge accepted noise, and share only the low-noise redacted
digest when appropriate.

The v1 scanner is read-only. It does not patch files, change host policy, edit
cron, restart services, or call external advisory APIs. Its findings are review
candidates, not verified vulnerabilities.

## What It Runs

The orchestrator entry point is:

```bash
node scripts/security-scan.mjs
```

By default it runs these lanes:

- `threat-model`: static project inventory and threat surface notes.
- `static-scan`: deterministic code-pattern candidate findings.
- `supply-chain`: npm/Python manifest and lockfile posture checks.
- `runtime-health`: local host posture checks such as listening sockets, SSH
  config, SSH key permissions, opt-in sensitive file permissions, and firewall
  presence.

`runtime-health` is host posture, not target-repo code analysis. It runs by
default in v1 to give runtime-adjacent context, so omit it explicitly for
repo-only scans.

## First-Time Setup

From the repo root:

```bash
cp security-scan.config.example.json security-scan.config.json
cp security-suppressions.example.json security-suppressions.json
```

Edit `security-scan.config.json` with real target paths and labels. Keep this
file private because target paths can identify local machines or projects.

Edit `security-suppressions.json` only after reviewing findings. The example
contains patterns showing the two supported suppression styles:

- `fingerprint`: acknowledge exactly one finding.
- `match`: acknowledge a category of accepted findings by fields such as
  `lane`, `category`, `file`, `severity`, or `title`.

Suppressions are view-layer only. Removing a suppression resurfaces the finding
without changing scanner state.

## Run A Scan

Use configured targets:

```bash
node scripts/security-scan.mjs --suppressions security-suppressions.json
```

Run one ad-hoc target:

```bash
node scripts/security-scan.mjs \
  --target /path/to/repo \
  --label my-repo \
  --suppressions security-suppressions.json
```

Run selected lanes only:

```bash
node scripts/security-scan.mjs \
  --target /path/to/repo \
  --label my-repo \
  --scanners static-scan,supply-chain
```

Run repo-only lanes without host posture:

```bash
node scripts/security-scan.mjs \
  --target /path/to/repo \
  --label my-repo \
  --scanners threat-model,static-scan,supply-chain
```

## Read The Output

The main output files are under `runs/`:

- `runs/summary/DIGEST.txt`: short redacted digest suitable for chat review.
- `runs/summary/SUMMARY.md`: consolidated human-readable scan summary.
- `runs/summary/SUMMARY.json`: machine-readable scan summary.
- `runs/report/<target>/<tool>/REPORT.md`: per-lane report.
- `runs/report/<target>/<tool>/REPORT.json`: per-lane structured report.

Start with `DIGEST.txt`. It shows active `new`, `persistent`,
`acknowledged`, and `resolved` counts, active severity totals, and the top new
findings. Acknowledged findings are excluded from active severity counts.

Then review `SUMMARY.md` and the relevant per-lane `REPORT.md` files for
details and fingerprints.

## Triage Loop

1. Review HIGH findings first, then MEDIUM, then LOW.
2. Check whether each finding is new, persistent, acknowledged, or resolved.
3. For real risk, open normal project work with the report evidence.
4. For accepted noise, add a narrow suppression rule with a reason.
5. Re-run the scan and confirm the digest now highlights only active signal.

Prefer exact `fingerprint` suppressions for one-off findings. Use `match`
rules for intentional posture that repeats every run, such as expected LAN
services reported by `runtime-health`.

Use `expires` for temporary acknowledgements:

```json
{
  "id": "temporary-example",
  "fingerprint": "f-example-fingerprint",
  "reason": "Accepted until the migration is complete",
  "by": "operator",
  "expires": "2026-12-31"
}
```

## Sharing Rules

Safe default for chat: paste `runs/summary/DIGEST.txt`.

Do not share full `REPORT.json`, raw target files, local config files, private
identity denylist files, or unsanitized `runs/` archives. Reports are redacted
by default, but operators still own final review before external sharing.

If a digest mentions a private filename or project label that should not leave a
trusted channel, edit the label/config and rerun before sharing.

## Verification

Run the local test suite before treating changes as shippable:

```bash
for f in scripts/test-*.mjs; do node "$f"; done
```

Dogfood an end-to-end scan into a temporary output root:

```bash
node scripts/security-scan.mjs \
  --target . \
  --label openclaw-security-stack \
  --out-root /tmp/openclaw-security-stack-dogfood \
  --suppressions security-suppressions.example.json \
  --quiet
sed -n '1,80p' /tmp/openclaw-security-stack-dogfood/summary/DIGEST.txt
```

Expected v1 behavior:

- All test scripts pass.
- The orchestrator writes `DIGEST.txt`, `SUMMARY.md`, and `SUMMARY.json`.
- Each enabled lane either reports findings or records a graceful skip/error.
- Suppressed findings appear as `acknowledged` and do not inflate active
  severity totals.
- The scan remains local and read-only.

## Known v1 Limits

- Supply-chain checks are deterministic posture checks, not CVE/advisory intel.
- Static findings are candidates, not proof of exploitability.
- Runtime-health is best-effort and skips unavailable host tools gracefully.
- Runtime-health is host posture and should be interpreted separately from
  target-repo findings.
- Anthropic-inspired workflow wrappers are staged, but this release is not a
  full implementation of Anthropic's autonomous reference harness.
- No automated remediation.
- No cron wiring in this repo; scheduling is an operator integration concern.
