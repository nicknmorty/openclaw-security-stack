# Security Guard Scripts

This repo includes sanitized, public-safe versions of the local guard scripts
used to keep OpenClaw-adjacent auth and token state out of reports, shell
snapshots, and public artifacts.

## Scripts

- `scripts/security-secret-guard.sh` checks for plaintext auth profile entries,
  literal model API keys, unresolved toxic-path manifests, and optional
  `trufflehog` findings.
- `scripts/oauth-containment-audit.sh` checks local OAuth/token storage
  permissions and can optionally fix file and directory modes.
- `scripts/redact-sensitive-output.sh` redacts common bearer-token and OAuth
  fields from stdin.

## Safety Model

The public scripts are read-only by default. Actions that mutate local auth or
token state require an explicit flag:

- `scripts/security-secret-guard.sh --remediate`
- `scripts/oauth-containment-audit.sh --fix`

Reports are written under `runs/security-secret-guard/` by default, which is
ignored by git. Raw scanner JSON is not persisted.

## Example

```bash
OPENCLAW_STATE_DIR="$HOME/.openclaw" \
  scripts/security-secret-guard.sh

OPENCLAW_STATE_DIR="$HOME/.openclaw" \
  scripts/oauth-containment-audit.sh
```

Use `reference/security/oauth-toxic-paths.example.txt` as a starting point for
local scanner deny/exclude lists. Keep real environment paths, reports, and
secret-bearing state out of public commits.
