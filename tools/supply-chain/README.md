# Supply-Chain Inventory Scanner (V0)

Read-only inventory of package manifests and lockfiles, plus a small set of
deterministic posture rules. Emits a `security-stack.findings.v1` document so
output flows straight through `scripts/security-report.mjs`.

## What it does

- Walks a target directory (skipping `node_modules`, `.git`, `runs`, build/cache
  dirs) and inventories npm and Python package files.
- Records an inventory of each project: manifest, lockfile presence, declared
  dependency counts.
- Emits deterministic **posture** findings (V0):
  - `unpinned-dependencies` (LOW) — npm manifest declares deps but has no lockfile.
  - `non-registry-dependency-source` (MEDIUM) — npm dep points at git/url/owner-repo.
  - `unpinned-python-requirement` (LOW) — `requirements*.txt` entries without `==` pins.

## What it is NOT (V0)

- No CVE/advisory matching, no installs, no network, no dependency resolution,
  no exploitability claims. Advisory intel (Bumblebee-style) is a separate,
  later backlog item. Findings here are honest posture observations only.

## Safety

- Read-only. Detection before remediation.
- Host-resource guard: `--max-entries` caps how many filesystem entries are
  visited (default 20000) so scans stay light on constrained hosts. Truncation
  is reported in the summary.
- Output is local-only under `runs/supply-chain/<target>/`.

## Usage

```bash
node scripts/security-supply-chain.mjs --target <root> [--label <name>] [--max-entries <n>]
# then turn it into a redacted, diffed report:
node scripts/security-report.mjs --findings runs/supply-chain/<target>/SUPPLY-CHAIN-FINDINGS.json
```

## Tests

```bash
node scripts/test-security-supply-chain.mjs
```
