# Security Scan Orchestrator (v1 entry point)

One command that runs the configured scanners against one or more targets and
produces a consolidated, redacted, local-only report.

## Pipeline

```
threat-model -> static-scan (consumes the threat model) -> supply-chain
  -> per-tool redacted report (new / persistent / resolved state)
  -> runs/summary/SUMMARY.md + SUMMARY.json (consolidated)
```

## Usage

```bash
# ad-hoc single target
node scripts/security-scan.mjs --target /path/to/repo --label my-repo

# choose scanners
node scripts/security-scan.mjs --target . --scanners static-scan,supply-chain

# config-driven (preferred for recurring targets)
cp security-scan.config.example.json security-scan.config.json
node scripts/security-scan.mjs
```

Options: `--config <file>`, `--out-root <dir>`, `--identity-file <p>`,
`--no-redact` (debug only), `--quiet`.

## Config

```json
{
  "redact": true,
  "outRoot": "runs",
  "identityFile": "reference/security/identity-denylist.json",
  "targets": [
    { "label": "my-repo", "path": "/abs/or/rel/path", "scanners": ["threat-model", "static-scan", "supply-chain"] }
  ]
}
```

The real `security-scan.config.json` is gitignored because target paths can be
private; commit only `security-scan.config.example.json`.

## Safety

- Read-only with respect to scanned targets. Detection before remediation.
- All output local-only under `<out-root>/` and redacted by default.
- One scanner failing is recorded in the summary and does not abort the run.

## Tests

```bash
node scripts/test-security-scan.mjs
```
