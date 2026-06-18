#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "oc-threat-model-"));
const markdownOut = path.join(tmpRoot, "THREAT_MODEL.md");
const jsonOut = path.join(tmpRoot, "threat-model.json");

const result = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/security-threat-model.mjs"),
    path.join(repoRoot, "tests/fixtures/sample-web-service"),
    "--name",
    "Sample Web Service",
    "--out",
    markdownOut,
    "--json-out",
    jsonOut,
  ],
  { encoding: "utf8" },
);

assert.equal(result.status, 0, result.stderr);

const markdown = fs.readFileSync(markdownOut, "utf8");
const model = JSON.parse(fs.readFileSync(jsonOut, "utf8"));

for (const heading of [
  "## 1. System context",
  "## 2. Assets",
  "## 3. Entry points & trust boundaries",
  "## 4. Threats",
  "## 5. Deprioritized",
  "## 6. Open questions",
  "## 7. Provenance",
  "## 8. Recommended mitigations",
]) {
  assert.match(markdown, new RegExp(heading.replace(".", "\\.")));
}

assert.ok(model.threats.length >= 3, "expected multiple inferred threats");
assert.ok(
  model.threats.some((threat) => threat.surface.includes("HTTP routes")),
  "expected HTTP route threat",
);
assert.ok(
  model.threats.some((threat) => threat.asset.includes("secrets")),
  "expected secret-related threat",
);
assert.equal(model.schema_version, "security-stack.threat-model.v1");
assert.equal(model.tool, "security-threat-model");
assert.equal(model.target_label, "Sample Web Service");
assert.equal(model.target_basename, "sample-web-service");
assert.ok(model.local_private.local_target_path.endsWith("sample-web-service"));
assert.doesNotMatch(markdown, /\/home\/|\/tmp\/|\/root\//, "markdown should not expose absolute paths");

const overwrite = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/security-threat-model.mjs"),
    path.join(repoRoot, "tests/fixtures/sample-web-service"),
    "--name",
    "Sample Web Service",
    "--out",
    markdownOut,
    "--json-out",
    jsonOut,
  ],
  { encoding: "utf8" },
);
assert.notEqual(overwrite.status, 0, "expected overwrite without --force to fail");

const unknownOption = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/security-threat-model.mjs"),
    path.join(repoRoot, "tests/fixtures/sample-web-service"),
    "--not-real",
  ],
  { encoding: "utf8" },
);
assert.notEqual(unknownOption.status, 0, "expected unknown option to fail");

const envRoot = fs.mkdtempSync(path.join(os.tmpdir(), "oc-threat-env-"));
fs.writeFileSync(path.join(envRoot, ".env"), "REAL_TOKEN=do-not-scan\n");
fs.writeFileSync(path.join(envRoot, ".env.example"), "API_TOKEN=example-value\n");
const envMarkdownOut = path.join(envRoot, "out.md");
const envJsonOut = path.join(envRoot, "out.json");
runThreatModel(envRoot, "Env Policy Fixture", envMarkdownOut, envJsonOut);
const envModel = JSON.parse(fs.readFileSync(envJsonOut, "utf8"));
const envText = JSON.stringify(envModel);
assert.doesNotMatch(envText, /REAL_TOKEN|do-not-scan/, "real .env values must not be scanned");
assert.equal(envModel.file_count, 1, "only the env template should be eligible for scanning");

console.log("security-threat-model tests passed");

function runThreatModel(target, name, out, jsonOut) {
  const result = spawnSync(
    process.execPath,
    [
      path.join(repoRoot, "scripts/security-threat-model.mjs"),
      target,
      "--name",
      name,
      "--out",
      out,
      "--json-out",
      jsonOut,
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
}
