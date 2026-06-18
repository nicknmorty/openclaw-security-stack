# Threat Model Tool

`scripts/security-threat-model.mjs` is a static, read-only bootstrapper for
OpenClaw security-stack threat models. It adapts the artifact contract and
workflow shape from Anthropic's `defending-code-reference-harness`, but keeps
the first OpenClaw implementation dependency-free and local.

## Usage

```bash
node scripts/security-threat-model.mjs <target-dir> --name "<system name>"
```

Default outputs:

- `runs/threat-model/<system>/THREAT_MODEL.md`
- `runs/threat-model/<system>/threat-model.json`

Use `--out`, `--json-out`, and `--force` for deterministic fixture or CI paths.

## Safety

- Reads source/config files only.
- Does not build, execute, fuzz, install dependencies, or contact target
  infrastructure.
- Writes only the requested output artifacts.
- Produces a bootstrap threat model for owner review, not a vulnerability
  verdict.
- Keeps shareable Markdown on target labels, basenames, and commit ids instead
  of absolute local paths. JSON keeps the absolute path only under
  `local_private.local_target_path`.
- Does not scan real `.env` files. It may scan `.env.example`, `.env.sample`,
  and `.env.template` files as configuration templates.

## Output Contract

The Markdown output keeps the Anthropic-compatible section headings:

1. System context
2. Assets
3. Entry points & trust boundaries
4. Threats
5. Deprioritized
6. Open questions
7. Provenance
8. Recommended mitigations

The JSON output exposes the same rows for future scanner and triage tools.
Current JSON schema version: `security-stack.threat-model.v1`.
