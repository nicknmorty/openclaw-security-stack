# Acknowledge / Ignore (Suppressions)

Lets an operator acknowledge accepted findings so reports surface true signal
instead of known/expected noise (e.g. home/LAN services listening on all
interfaces).

## How it works

- View-layer only. Suppressions never change scan state, so:
  - removing a suppression immediately resurfaces the finding, and
  - resolved-detection keeps working normally.
- Acknowledged findings move to an `acknowledged` group and are excluded from
  `new` / `persistent` counts and from the active severity totals.

## Matching

Each suppression matches by **either**:

- `fingerprint`: exact finding fingerprint (copy it from a `REPORT.json`), or
- `match`: a rule — any subset of `lane`, `category`, `file`, `severity`,
  `title`. All specified fields must match (case-insensitive). An empty rule
  never matches.

Optional fields: `id`, `reason`, `by`, and `expires` (ISO date — after it the
suppression auto-deactivates and the finding returns).

## Usage

```bash
cp security-suppressions.example.json security-suppressions.json   # edit rules
# the report/orchestrator auto-load ./security-suppressions.json, or pass it:
node scripts/security-report.mjs --findings <findings.json> --suppressions security-suppressions.json
node scripts/security-scan.mjs --target . --suppressions security-suppressions.json
```

Example rule (silence expected non-loopback listeners):

```json
{ "schema_version": "security-stack.suppressions.v1",
  "suppressions": [
    { "match": { "lane": "runtime-health", "category": "listening-non-loopback" },
      "reason": "Home/LAN services are expected to bind to all interfaces" }
  ] }
```

The real `security-suppressions.json` is gitignored (it can carry host-specific
notes); commit only the example, or point `--suppressions` at a path your team
chooses to version.

## Tests

```bash
node scripts/test-security-suppressions.mjs
```
