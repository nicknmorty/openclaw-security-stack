# Static Scan Tool

`scripts/security-static-scan.mjs` is the second OpenClaw security-stack tool.
It consumes a target repo plus optional `threat-model.json` and emits static
candidate findings for triage.

This is not an autonomous exploit finder and does not verify vulnerabilities.
It is the deterministic scanner contract that later agent-assisted review
and adversarial triage can build on.

## Usage

```bash
node scripts/security-threat-model.mjs <target-dir> --name "<system>" --force
node scripts/security-static-scan.mjs <target-dir> \
  --threat-model runs/threat-model/<system>/threat-model.json \
  --name "<system>" \
  --force
```

Default outputs:

- `runs/static-scan/<system>/VULN-FINDINGS.json`
- `runs/static-scan/<system>/VULN-FINDINGS.md`

## Safety

- Reads source/config files only.
- Does not build, execute, fuzz, install dependencies, or contact target
  infrastructure.
- Writes only the requested report artifacts.
- Labels every item as `verdict: "candidate"` for later triage.
- Skips test, fixture, and example paths by default; pass `--include-tests`
  when intentionally scanning a fixture target.
- Keeps shareable Markdown on target labels, basenames, and commit ids instead
  of absolute local paths. JSON keeps absolute local paths only under
  `local_private`.

## Finding Shape

Each candidate includes:

- `id`
- `lane`
- `category`
- `title`
- `severity`
- `confidence`
- `status`
- `verdict`
- `redaction_level`
- `file`
- `line`
- `surface`
- `threat_ids`
- `evidence`
- `description`
- `exploit_scenario`
- `recommendation`
- `scanner`

Each evidence item includes `path`, `line`, `role`, and `snippet_redacted`.
Current JSON schema version: `security-stack.findings.v1`.

## Rule Families

- unsafe command/tool execution
- path traversal and broad file access
- secret exposure at logs/responses/files/process boundaries
- durable memory/authority poisoning
- dynamic code evaluation
- raw query construction
- outbound request steering
- raw HTML injection
- dependency/build script exposure
- mutating route authentication review
