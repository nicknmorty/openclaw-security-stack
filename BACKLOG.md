# Backlog

## V0 - Inventory And Reporting
- Decide whether scratch-built local CLIs should remain support commands, become fixtures, or be retired behind Anthropic-derived skills.
- Exercise OpenClaw-safe tool/agent gates in live wrapper dogfood runs.
- Wire OpenClaw security skill wrappers into the chosen live skill distribution path.
- Convert the hardening map into prioritized scanner candidates.
- Define scoped project roots and host roots.
- Add a small CLI wrapper around `scripts/security-threat-model.mjs` if this graduates into a packaged command.
- Draft report schema for `new`, `persistent`, and `resolved` findings.
- Create local state format for previous scan comparison.
- Add redaction helper for secrets, home paths, tokens, phone numbers, and private chat IDs.
- Add sample report fixture using fake findings.
- Generate Anthropic-style threat-model artifacts for the first target repos.
- Add scanner report state diffing for `new`, `persistent`, and `resolved`.
- Dogfood `anthropic-triage` to verify, dedupe, and rank scanner output.
- Decide whether variant finding belongs in a follow-up OpenClaw skill or report helper after upstream-aligned triage lands.
- Add a shared schema module once triage begins consuming both threat-model and static-scan output.

## Supply Chain Exposure
- Inventory npm projects and lockfiles.
- Inventory Python projects and lockfiles.
- Evaluate Bumblebee-style package/version intel source options.
- Evaluate whether Bumblebee should be a dependency, optional adapter, or pattern reference.
- Map exact package/version findings to severity and confidence.
- Add ignore/acknowledge workflow for accepted findings.

## Runtime Health
- Map gateway/control UI exposure checks.
- Map sandbox/filesystem isolation checks.
- Map browser/node permission checks.
- Baseline listening ports and bound addresses.
- Baseline cron/systemd/OpenClaw scheduled tasks.
- Baseline SSH keys, authorized users, and risky permission changes.
- Track OpenClaw plugin, skill, MCP, and connector inventory drift.
- Add host-resource guard so scans do not overload the Pi.

## Agent Safety
- Evaluate `garak` for prompt-injection, jailbreak, and data-leak testing.
- Evaluate Microsoft Agent Governance Toolkit as policy/audit middleware reference.
- Evaluate Claude Code Damage Control as a command-blocking pattern reference.
- Preserve Anthropic's defending-code reference harness as the provenance source for threat modeling, static scan, adversarial triage, patch drafting, and sandboxed verification.
- Expand static scan rules for OpenClaw-specific tool chaining, memory poisoning, and message metadata/content separation.
- Map sender allowlist, auth, pairing, and approval drift checks.
- Map prompt-injection and tool-chaining risk checks.
- Map memory poisoning checks.
- Detect changes to tool permission config.
- Detect high-risk memory or authority-lane writes.
- Detect prompt-injection-prone docs/config surfaces.
- Track new external-action capabilities.
- Add policy gate checks for security/access/destructive changes.

## Reporting And Operations
- Evaluate GoLinHound for Linux/SSH attack-path discovery.
- Scope a native `openclaw security audit --deep` posture baseline proposal.
- Map audit-log and incident-response needs.
- Add recurring operations checklist for security posture review.
- Generate local Markdown and JSON reports.
- Add low-noise Telegram summary format.
- Add scheduled mode proposal.
- Add manual runbook.
- Decide what can be shared in team channels without leaking private data.
