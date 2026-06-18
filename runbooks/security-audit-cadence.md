# Security Audit Cadence

Status: active runbook

## Purpose
Define a low-noise recurring review loop for OpenClaw security posture.

## On Demand
Use after security-relevant changes:
- tool permissions
- agent bindings
- gateway routes
- node pairing
- plugins/skills/MCP/webhooks
- auth, allowlists, or secrets handling

Checks:
- Review changed files/configs.
- Confirm operator/admin access remains available.
- Confirm no new external exposure.
- Confirm secrets are referenced, not copied.
- Capture decisions in project docs or incident notes when needed.

## Daily Candidate
Read-only, low-cost checks:
- package exposure delta
- running processes/listening ports delta
- scheduled job delta
- plugin/skill/MCP inventory delta
- new high-risk config changes

Report only meaningful `new`, `persistent`, and `resolved` deltas.

## Weekly Candidate
Example scheduled job:
- Cron: weekly during a low-traffic window
- Target: isolated agent session
- Output: redacted local summaries in `runs/` and local state files
- No remediation, config changes, restarts, or raw secret/private data output

Broader review:
- sender allowlist and pairing review
- SSH keys and node permissions
- memory authority lane write review
- audit log sampling
- dependency/source review for installed security tools

## Before Major Changes
Run a short premortem and review:
- what trust boundary changes
- what can write, send, execute, or expose data
- what rollback exists
- what evidence would prove the change is safe enough

## Incident Mode
If a check suggests compromise or dangerous exposure:
1. Stop expanding automation.
2. Preserve local evidence.
3. Avoid posting raw private details to group chat.
4. Stabilize exposure.
5. Document in the correct incident lane.
6. Repair and verify before closing.
