# OpenClaw Hardening Vectors

Status: planning input
Source: derived from OpenClaw hardening review notes.

This is the working map of OpenClaw security areas to turn into checks, docs, and eventually scanner modules.

## Vectors
- Gateway/control UI exposure.
- Auth, pairing, and sender allowlists.
- Secrets/OAuth surfaces.
- Dangerous tools and approvals.
- Sandbox/filesystem isolation.
- Prompt injection and tool chaining.
- Memory poisoning.
- Browser/node permissions.
- Plugins, skills, webhooks, and supply chain.
- Audit logs and incident response.
- Recurring OpenClaw security audit checks.

## Useful Framing
OpenClaw security is trust-boundary management. The first job is to make trust boundaries visible and reviewable before building active enforcement.

## Candidate Outputs
- Hardening checklist by vector.
- Read-only scanner candidates by vector.
- A native `openclaw security audit --deep` baseline proposal.
- Report schema that maps findings to vector, severity, confidence, and action.
