# Security Report Tool (V0 reporting core)

Turns a `security-stack.findings.v1` file (produced by `security-static-scan`)
into a redacted, local-only report that tracks findings as **new**,
**persistent**, or **resolved** across runs.

## What it does

- Reads a findings file.
- Computes a stable fingerprint per finding (lane + category + file + title) so
  the same underlying issue keeps one identity even as line numbers drift.
- Diffs against saved prior state to assign `new` / `persistent` / `resolved`.
- Redacts the result (home paths, secrets/tokens, phone numbers, chat IDs, and
  private-only annotation blocks).
- Writes `REPORT.md`, `REPORT.json`, and `STATE.json` under
  `runs/report/<target>/` (git-ignored, local only).

## Safety contract

- Read-only with respect to the scanned target. **Detection before
  remediation** — it never fixes anything.
- Output is redacted by default and written only to the local `runs/` tree.
- `--no-redact` exists for debugging only and must never be shared.

## Usage

```bash
node scripts/security-report.mjs --findings runs/static-scan/<target>/VULN-FINDINGS.json
```

Options:

| Flag | Meaning |
| --- | --- |
| `--findings <path>` | Input findings file (required) |
| `--state <path>` | Prior/next state file (default `<out-dir>/STATE.json`) |
| `--out-dir <path>` | Report output dir (default `runs/report/<target>`) |
| `--label <name>` | Human label for the report |
| `--identity-file <p>` | Private identity denylist JSON (terms/patterns) |
| `--no-redact` | Debug only; skip redaction |
| `--quiet` | Suppress stdout summary |

## Redaction

Generic patterns (home paths, secrets, phone numbers, routing/chat IDs) are
built in and require no configuration. Site-specific literals (real names,
usernames, exact IDs) come from a private denylist file that is **not**
committed:

1. `cp reference/security/identity-denylist.example.json reference/security/identity-denylist.json`
2. Fill in `terms` / `patterns`.
3. Pass `--identity-file reference/security/identity-denylist.json` or set
   `SECURITY_STACK_IDENTITY_FILE`.

The redaction module (`scripts/lib/redact.mjs`) embeds no personal literals, so
it stays safe to publish verbatim.

## Tests

```bash
node scripts/test-security-report.mjs
```
