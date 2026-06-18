# Architecture

## Shape
The stack should start as a set of read-only local scanners plus a report composer.

```text
inputs -> scanners -> normalized findings -> state diff -> redacted reports
```

## Inputs
- Project package manifests and lockfiles.
- OpenClaw config, plugin, skill, MCP, and connector inventories.
- Host runtime state: ports, processes, cron/systemd, SSH, firewall posture.
- Local threat-intel catalogs or package exposure lists.
- Hardening vectors from `vectors/openclaw-hardening.md`.

## Scanners
Each scanner should return normalized findings, not prose.

Minimum finding fields:
- `id`
- `lane`
- `title`
- `severity`
- `confidence`
- `evidence`
- `first_seen`
- `last_seen`
- `status`
- `redaction_level`

## State Diff
The report layer should compare the current scan to previous local state and classify findings:
- `new`
- `persistent`
- `resolved`

## Reports
Reports should be generated locally in two forms:
- JSON for tools.
- Markdown for humans.

Chat or group summaries should be short and redacted. Full raw evidence stays local unless an authorized operator explicitly asks to share it.

## Future Integration Points
- OpenClaw local observability dashboard.
- Host healthcheck runbooks.
- Scheduled cron/task runner.
- Native `openclaw security audit --deep` baseline.
- Manual approval workflow for remediation.
