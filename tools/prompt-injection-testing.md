# Prompt Injection Testing

Status: candidate tooling lane

## Threat Shape
The agent threat model is:

```text
untrusted content -> treated as instructions -> amplified by tools
```

Testing should focus on whether untrusted text can cross from read/summarize workflows into mutate/send/execute workflows.

## Candidate Controls To Test
- Per-task tool allowlists.
- Read/summarize mode versus mutate/send/execute mode.
- Cross-tool anti-exfiltration policy.
- Memory write firewall.
- Sandbox by default.
- Isolated browser profiles.
- Audit trails for tool chains and approvals.

## Candidate Tools And References
- `garak` for prompt-injection, jailbreak, and data-leak testing.
- Microsoft Agent Governance Toolkit as a policy/audit middleware reference.
- Claude Code Damage Control as a command-blocking pattern reference.

These are references to evaluate, not approved dependencies.

## V0 Test Ideas
- Untrusted document tries to trigger file writes.
- Webpage content tries to send a message externally.
- Tool output tries to escalate into shell execution.
- Retrieved memory tries to override authority policy.
- Browser profile contains sensitive state that untrusted content tries to exfiltrate.

