---
name: anthropic-threat-model
description: Build an Anthropic-style threat model for an OpenClaw target.
---

# Anthropic Threat Model - OpenClaw Skill Wrapper

This skill adapts Anthropic's defending-code `threat-model` workflow for
OpenClaw. It is self-contained for runtime use; upstream repo paths are
provenance only and are not required after install.

## When To Use

Use when asked to threat model a repo, subsystem, plugin, agent lane, host
surface, or codebase before vulnerability scanning.

## Safety

- Static analysis only.
- Do not build, run, fuzz, install dependencies, or probe live services.
- Stay inside the target checkout and explicitly supplied docs.
- Write only `THREAT_MODEL.md` or an explicitly requested local report path.
- If owner input is required, ask concise direct questions.

## Modes

- `bootstrap`: derive from code, docs, git history, and supplied reports.
- `interview`: walk the owner through the threat model questions.
- `bootstrap-then-interview`: draft from code, then refine with the owner.

If mode is unclear, recommend `bootstrap-then-interview` when both code and an
owner are available; otherwise use `bootstrap`.

## Workflow

1. Confirm the target directory exists and is readable.
2. Identify system context from README, docs, manifests, architecture notes,
   and top-level source layout.
3. Identify assets: secrets, auth state, user data, memory/authority records,
   host process integrity, service availability, and supply-chain integrity.
4. Identify entry points and trust boundaries: network routes, messaging
   callbacks, CLI/file inputs, deserialization, DB/query boundaries, tool
   execution, plugins/skills/connectors, memory writes, and deploy/IAM config.
5. Mine local history and supplied vulnerability reports for evidence. Public
   advisory lookup is allowed only when explicitly requested and only against
   public advisory sources.
6. Generalize concrete bugs into durable threats. A threat should survive after
   one vulnerable line is patched.
7. Write `THREAT_MODEL.md` with the schema below.

## Required Schema

`THREAT_MODEL.md` must contain these sections in order:

```markdown
# Threat Model: <system name>

## 1. System context
## 2. Assets
## 3. Entry points & trust boundaries
## 4. Threats
## 5. Deprioritized
## 6. Open questions
## 7. Provenance
## 8. Recommended mitigations
```

Use these table contracts:

Assets:

```markdown
| asset | description | sensitivity |
|---|---|---|
```

Entry points:

```markdown
| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
```

Threats:

```markdown
| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
```

Recommended mitigations:

```markdown
| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
```

## Output

After writing the model, report:

- path to `THREAT_MODEL.md`,
- top five threats by impact and likelihood,
- open questions that need the owner,
- any claims that could not be verified in code.
