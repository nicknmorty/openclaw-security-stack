# Defending Code Harness Scope

Status: scoped reference adaptation
Date: 2026-06-05
Source: Anthropic `defending-code-reference-harness`

## Why It Matters

Anthropic's reference harness is useful to this project because it treats AI
security work as a repeatable loop instead of a one-shot scan:

```text
threat model -> sandbox -> discover -> verify -> triage -> patch -> rescan
```

The C/C++ ASAN harness is not a direct fit for OpenClaw, but the workflow
contract is a strong fit. OpenClaw's security project needs low-noise,
local-first findings with clear trust boundaries, repeatable evidence, and no
automatic remediation. The harness gives us implementation patterns for each
of those needs.

## Reference Pieces To Reuse

- Threat model first: generate a repo-local `THREAT_MODEL.md` before scanning.
- Static discovery: partition the codebase into attack-surface focus areas and
  run scoped review agents against each area.
- Adversarial verification: verify findings in a fresh context that is trying
  to disprove the scanner, not agree with it.
- Dedupe by root cause: collapse repeated symptoms, repeated call sites, and
  missing global controls into one actionable finding.
- Severity from exploitability: rank by reachability, attacker control,
  authentication, preconditions, data impact, and blast radius.
- Patch as inert artifact: generate candidate diffs only after triage, never
  apply them automatically.
- Variant analysis: after a real bug or secret exposure, search for the same
  pattern and same class elsewhere.
- Durable checkpoints: long scans write phase state so rate limits or context
  loss do not lose progress.
- Sandbox split: build/setup may use network; autonomous attack/PoC phases
  must run in isolated environments with egress restricted to the model API.
- Engagement context: every scanner run should carry explicit authorization,
  target scope, out-of-scope systems, and no-secret/no-exfiltration rules.

## Implementation Candidates

### 1. `security threat-model`

Create or refresh a `THREAT_MODEL.md` for an OpenClaw repo, host lane, or
agent subsystem.

Inputs:
- repo path or subsystem path
- existing architecture docs, past incidents, hardening map entries
- optional owner interview notes

Outputs:
- `THREAT_MODEL.md`
- normalized threat rows for scanners
- open questions requiring operator or subsystem-owner input

The scanner should be read-only except for writing the local artifact.

### 2. Static Agent Vulnerability Scan

Build a read-only scanner that uses the threat model to partition a target into
focus areas and return normalized findings.

Good first OpenClaw focus areas:
- message ingestion and callback handling
- tool permission and approval resolution
- memory writes and authority-lane updates
- plugin/skill discovery and install paths
- gateway/node pairing and auth boundaries
- secret/config loading and redaction paths

Outputs should match the security-stack finding shape:

```json
{
  "id": "agent-safety-001",
  "lane": "agent-safety",
  "title": "Finding title",
  "severity": "high|medium|low",
  "confidence": 0.0,
  "evidence": [],
  "redaction_level": "local|shareable-redacted",
  "status": "new|persistent|resolved"
}
```

### 3. Adversarial Triage Tool

Create a triage command that ingests raw findings from our scanners, existing
security audit output, and future agent scans.

Responsibilities:
- normalize inputs
- verify each finding against source/config evidence
- dedupe by root cause
- apply OpenClaw-specific false-positive rules
- rank by exploitability and owner impact
- write `TRIAGE.json` and `TRIAGE.md`

Important default: precision for chat-facing summaries, recall for local
backlog artifacts.

### 4. Patch Draft Generator

Create inert patch proposals only after triage has marked a finding as true
positive or needs manual testing.

Rules:
- write patches under `PATCHES/`
- never apply directly to target source
- require a regression test or static guard where possible
- include a reviewer checklist for "too broad", "symptom-only", "breaks
  legitimate flow", and "missed variants"

This should stay manual-review only until the rest of the stack is mature.

### 5. Variant Finder

After a confirmed issue, generate a scoped same-pattern and same-class scan.

Examples:
- one secret-bearing shell snapshot path implies scanning all agent
  `shell_snapshots` paths
- one unsafe JSON status output implies scanning nearby status/report commands
  for credential-bearing fields
- one tool-permission drift bug implies scanning every agent/runtime config
  resolution path

This is a strong fit because it amplifies known-good human findings
instead of trying to discover everything from scratch.

### 6. Sandboxed Dynamic Verifier

Adapt the autonomous harness idea only for targets where executing code is
necessary and safe.

Near-term scope:
- not on the Pi by default
- PC node or disposable container only
- no credential mounts
- no host networking
- no MCP tools or external write tools
- allow egress only to model API if an agent is running inside

Potential targets:
- toy vulnerable targets for validating the pipeline
- isolated OpenClaw parser/formatter modules with fake fixtures
- plugin sandbox experiments

### 7. Security Run State And Checkpoints

Use the harness checkpoint idea for long local scans.

State layout:
- `runs/<timestamp>/raw/`
- `runs/<timestamp>/normalized-findings.json`
- `runs/<timestamp>/TRIAGE.json`
- `runs/<timestamp>/TRIAGE.md`
- `state/security-findings.json`

The project already wants `new`, `persistent`, and `resolved`; checkpoints make
that state durable and resumable without dumping logs into chat.

## Proposed Phases

### Phase A: Reference Extraction

- Add this scope note.
- Add a compact design doc for finding schema and triage contract.
- Add backlog entries for threat model, static scan, triage, patch draft, and
  variant finder lanes.

### Phase B: Static-Only Prototype

- Implement a read-only threat-model helper.
- Implement a scanner adapter that emits normalized JSON.
- Implement adversarial triage over existing static findings.
- Produce local Markdown + JSON reports only.

### Phase C: OpenClaw-Specific Lanes

- Agent permission drift scanner.
- Prompt-injection surface scanner.
- Memory/authority-write scanner.
- Secret/config/redaction scanner.
- Plugin/skill inventory drift scanner.

### Phase D: Controlled Dynamic Verification

- Create one fake vulnerable target.
- Run the reference sandbox pattern off-Pi.
- Decide whether gVisor, Firecracker, or plain disposable VM isolation is the
  right lane for the target environment.

### Phase E: Patch And Rescan Loop

- Generate inert patch drafts for true positives.
- Require review and tests before apply.
- Run variant scan after each accepted fix.
- Feed confirmed findings back into `THREAT_MODEL.md` and false-positive rules.

## What Not To Reuse Directly

- Do not run the autonomous C/C++ pipeline against OpenClaw on the Pi.
- Do not mount private agent homes, `.env`, auth stores, SSH keys, or memory files
  into any agent-run sandbox.
- Do not connect scanner agents to messaging, GitHub write APIs, cloud storage,
  MCP servers, or live Gateway controls.
- Do not treat static findings as verified vulnerabilities.
- Do not auto-apply generated patches.

## Source Links

- https://github.com/anthropics/defending-code-reference-harness
- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/blog-post.md
- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/pipeline.md
- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/security.md
- https://github.com/anthropics/defending-code-reference-harness/blob/main/docs/customizing.md
