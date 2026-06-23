---
name: anthropic-quickstart
description: Orient users to the OpenClaw-adapted Anthropic security workflow.
---

# Anthropic Quickstart - OpenClaw Skill Wrapper

This skill adapts Anthropic's defending-code `quickstart` flow for OpenClaw.
It is self-contained for runtime use.

## When To Use

Use when a user asks how to start with the Anthropic security workflow inside
OpenClaw.

## OpenClaw Flow

1. Build or refresh a threat model:
   `anthropic-threat-model bootstrap <target>`
2. Run a static vulnerability scan:
   `anthropic-vuln-scan <target>`
3. Triage the findings:
   `anthropic-triage <target>/VULN-FINDINGS.json --repo <target>`
4. Generate inert candidate patches:
   `anthropic-patch <target>/TRIAGE.json --repo <target>`
5. Use `anthropic-customize` only when a target needs the autonomous harness
   ported.

## Safety Summary

- Threat model, scan, triage, security review, and static patch drafting are
  read/write-only local workflows.
- The autonomous pipeline executes target code and must stay behind approved
  off-Pi/container isolation.
- Do not mount OpenClaw secrets, memory, auth stores, SSH keys, or home dirs
  into scanner or agent environments.

## Output

Give the user the next safe step, the expected artifacts, and the sandbox
boundary if they ask about dynamic execution.
