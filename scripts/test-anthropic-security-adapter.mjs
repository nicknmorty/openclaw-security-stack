#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const adapterPath = path.join(repoRoot, "tools/anthropic-security/openclaw-adapter.json");
const adapter = JSON.parse(fs.readFileSync(adapterPath, "utf8"));

assert.equal(adapter.schema_version, "openclaw-security-stack.anthropic-adapter.v1");
assert.equal(adapter.upstreams.length, 2);
assert.ok(
  adapter.upstreams.some((upstream) => upstream.name === "anthropics/defending-code-reference-harness"),
  "expected defending-code upstream",
);
assert.ok(
  adapter.upstreams.some((upstream) => upstream.name === "anthropics/claude-code-security-review"),
  "expected claude-code-security-review upstream",
);

const requiredFiles = [
  "tools/anthropic-security/upstream/defending-code/.claude/skills/threat-model/SKILL.md",
  "tools/anthropic-security/upstream/defending-code/.claude/skills/vuln-scan/SKILL.md",
  "tools/anthropic-security/upstream/defending-code/.claude/skills/triage/SKILL.md",
  "tools/anthropic-security/upstream/defending-code/.claude/skills/patch/SKILL.md",
  "tools/anthropic-security/upstream/defending-code/.claude/skills/customize/SKILL.md",
  "tools/anthropic-security/upstream/defending-code/.claude/skills/quickstart/SKILL.md",
  "tools/anthropic-security/upstream/defending-code/.claude/skills/_lib/checkpoint.py",
  "tools/anthropic-security/upstream/defending-code/docs/security.md",
  "tools/anthropic-security/upstream/defending-code/docs/agent-sandbox.md",
  "tools/anthropic-security/upstream/defending-code/docs/pipeline.md",
  "tools/anthropic-security/upstream/defending-code/docs/patching.md",
  "tools/anthropic-security/upstream/defending-code/LICENSE",
  "tools/anthropic-security/upstream/claude-code-security-review/.claude/commands/security-review.md",
  "tools/anthropic-security/upstream/claude-code-security-review/LICENSE",
  "tools/anthropic-security/openclaw-skills/anthropic-threat-model/SKILL.md",
  "tools/anthropic-security/openclaw-skills/anthropic-vuln-scan/SKILL.md",
  "tools/anthropic-security/openclaw-skills/anthropic-triage/SKILL.md",
  "tools/anthropic-security/openclaw-skills/anthropic-patch/SKILL.md",
  "tools/anthropic-security/openclaw-skills/anthropic-security-review/SKILL.md",
  "tools/anthropic-security/openclaw-skills/anthropic-customize/SKILL.md",
  "tools/anthropic-security/openclaw-skills/anthropic-quickstart/SKILL.md",
  "scripts/sync-openclaw-security-skills.mjs",
];

for (const rel of requiredFiles) {
  assert.ok(fs.existsSync(path.join(repoRoot, rel)), `missing imported upstream file: ${rel}`);
}

const vulnScan = fs.readFileSync(
  path.join(repoRoot, "tools/anthropic-security/upstream/defending-code/.claude/skills/vuln-scan/SKILL.md"),
  "utf8",
);
assert.match(vulnScan, /Static vulnerability review/);
assert.match(vulnScan, /Never execute target code/);
assert.match(vulnScan, /VULN-FINDINGS\.json/);

const triage = fs.readFileSync(
  path.join(repoRoot, "tools/anthropic-security/upstream/defending-code/.claude/skills/triage/SKILL.md"),
  "utf8",
);
assert.match(triage, /Adversarial triage/);
assert.match(triage, /TRIAGE\.json/);
assert.match(triage, /Do not execute target code/);

const patch = fs.readFileSync(
  path.join(repoRoot, "tools/anthropic-security/upstream/defending-code/.claude/skills/patch/SKILL.md"),
  "utf8",
);
assert.match(patch, /never applies a diff/i);
assert.match(patch, /PATCHES\//);
assert.match(patch, /Never write into `--repo`/);

const securityDoc = fs.readFileSync(
  path.join(repoRoot, "tools/anthropic-security/upstream/defending-code/docs/security.md"),
  "utf8",
);
assert.match(securityDoc, /gVisor/);
assert.match(securityDoc, /Never mount credential-bearing paths/);

const securityReview = fs.readFileSync(
  path.join(repoRoot, "tools/anthropic-security/upstream/claude-code-security-review/.claude/commands/security-review.md"),
  "utf8",
);
assert.match(securityReview, /MINIMIZE FALSE POSITIVES/);
assert.match(securityReview, /FALSE POSITIVE FILTERING/);

assert.deepEqual(adapter.supersedes.closed_prs, [3, 4, 5, 6, 7]);

for (const mapping of adapter.skill_map) {
  assert.ok(mapping.openclaw_skill_path, `missing OpenClaw wrapper path for ${mapping.openclaw_lane}`);
  assert.ok(
    fs.existsSync(path.join(repoRoot, mapping.openclaw_skill_path)),
    `missing wrapper ${mapping.openclaw_skill_path}`,
  );
}

const wrapperNames = [
  "anthropic-threat-model",
  "anthropic-vuln-scan",
  "anthropic-triage",
  "anthropic-patch",
  "anthropic-security-review",
  "anthropic-customize",
  "anthropic-quickstart",
];

const mappedWrapperNames = adapter.skill_map
  .map((mapping) => path.basename(path.dirname(mapping.openclaw_skill_path)))
  .sort();
assert.deepEqual(
  mappedWrapperNames,
  [...wrapperNames].sort(),
  "adapter skill_map must include exactly the installable OpenClaw wrappers",
);

for (const name of wrapperNames) {
  const wrapper = fs.readFileSync(
    path.join(repoRoot, `tools/anthropic-security/openclaw-skills/${name}/SKILL.md`),
    "utf8",
  );
  assert.match(wrapper, /OpenClaw Skill Wrapper/);
  assert.doesNotMatch(
    wrapper,
    /\.\.\/\.\.\/upstream/,
    `${name} must be self-contained after sync and not depend on vendored upstream paths`,
  );
  assert.doesNotMatch(
    wrapper,
    /Source Of Truth|Use the upstream/,
    `${name} must treat upstream as provenance, not runtime source text`,
  );
  assert.doesNotMatch(
    wrapper,
    /^allowed-tools:/m,
    `${name} must not expose Claude Code allowed-tools as active OpenClaw contract`,
  );
}

const installDir = fs.mkdtempSync(path.join(os.tmpdir(), "oc-security-skills-"));
const syncResult = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/sync-openclaw-security-skills.mjs"),
    "--install-dir",
    installDir,
  ],
  { encoding: "utf8" },
);
assert.equal(syncResult.status, 0, syncResult.stderr);
for (const name of wrapperNames) {
  const installedPath = path.join(installDir, name, "SKILL.md");
  assert.ok(fs.existsSync(installedPath), `sync did not install ${name}`);
  const installed = fs.readFileSync(installedPath, "utf8");
  assert.doesNotMatch(installed, /\.\.\/\.\.\/upstream/);
  assert.doesNotMatch(installed, /Source Of Truth|Use the upstream/);
}

const overwriteResult = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/sync-openclaw-security-skills.mjs"),
    "--install-dir",
    installDir,
  ],
  { encoding: "utf8" },
);
assert.notEqual(overwriteResult.status, 0, "expected sync without --force to refuse overwrite");

console.log("anthropic-security-adapter tests passed");
