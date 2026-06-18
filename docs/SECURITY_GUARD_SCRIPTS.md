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

The public scripts do not mutate auth/config state by default. They do create
local report files under `runs/` unless you override the report directory.
Actions that change local auth or token state require an explicit flag:

- `scripts/security-secret-guard.sh --remediate`
- `scripts/oauth-containment-audit.sh --fix`

Reports are written under `runs/security-secret-guard/` by default, which is
ignored by git. Raw scanner JSON is not persisted.

## What Mutates

`scripts/security-secret-guard.sh` always creates a timestamped report directory
with `summary.tsv` and `remediation.tsv`. This gives operators an audit trail
without committing secret-bearing evidence.

With `--remediate`, `scripts/security-secret-guard.sh` can mutate:

- Deletes unsupported plaintext stores under `OPENCLAW_STATE_DIR`, including
  `*/codex-home/auth.json`, `*/codex-home/logs_*.sqlite*`,
  `*/codex-home/state_*.sqlite*`, and `*/shell_snapshots/*`.
- Deletes `$HOME/.codex/auth.json` when present.
- Strips `oauth_token:` lines from `$HOME/.config/gh/hosts.yml`.

These removals are useful because those files can contain OAuth/session
material, captured shell text, or plaintext tokens that are easy to sweep into
backups, scanner output, support bundles, or accidental commits. Removing or
stripping them pushes operators toward env-backed, managed, or re-login auth
flows instead of letting long-lived credentials sit in broad report paths.

With `--fix`, `scripts/oauth-containment-audit.sh` can mutate:

- Creates `OAUTH_CONTAINMENT_DIR`, `$HOME/.config/openclaw`, and `$HOME/.codex`
  when they are missing.
- Changes those directories, `OPENCLAW_STATE_DIR/agents`, and agent state
  directories to mode `700`.
- Changes `auth-profiles.json`, `auth-state.json`,
  `$HOME/.config/openclaw/auth-profile-secret-key`, and
  `$HOME/.codex/auth.json` to mode `600` when those files exist.

These fixes are useful because OAuth refresh material, auth state, and token
wrapping keys should not be group- or world-readable. The script makes the
intended containment boundary explicit and repeatable, which reduces local
credential exposure and gives scanner/report tooling clearer paths to exclude.

`scripts/redact-sensitive-output.sh` does not write files or change state. It
only transforms stdin to stdout, replacing common bearer-token and OAuth fields
with `[REDACTED]`.

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
