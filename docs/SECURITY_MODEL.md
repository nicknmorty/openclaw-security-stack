# Security Model

## Default Boundary
This project is local-first and detection-first. It should not change host security posture, OpenClaw access, file permissions, firewall rules, secrets, agent bindings, or project dependencies without explicit approval.

## Data Handling
- Keep raw scan output local.
- Redact secrets and private identifiers before summaries leave the host.
- Do not commit raw reports from `runs/` unless they are synthetic or reviewed.
- Do not store secrets in project files.
- Reference secret names only; real secret values belong in a private environment file outside the repo.

## Approval-Gated Actions
Require explicit maintainer confirmation before:
- security policy changes
- access changes
- tool permission changes
- firewall or SSH changes
- automated remediation
- deleting/quarantining files
- external reporting or sharing raw evidence

## Safe V0 Actions
Allowed without extra confirmation when requested by an authorized operator:
- create project docs and scaffolding
- run read-only inventory commands
- generate local redacted draft reports
- propose runbooks and scanner designs

## Non-Negotiables
- Operator/admin access must remain available by default.
- No destructive commands as part of scans.
- No external telemetry.
- No package installation from untrusted sources without review.
- No claims of host safety from a partial scanner.
