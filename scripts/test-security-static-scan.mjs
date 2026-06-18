#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);

function run(args) {
  const result = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result;
}

function scanFixture(fixtureName, displayName) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `oc-static-scan-${fixtureName}-`));
  const threatJson = path.join(tmpRoot, "threat-model.json");
  const threatMd = path.join(tmpRoot, "THREAT_MODEL.md");
  const findingsJson = path.join(tmpRoot, "VULN-FINDINGS.json");
  const findingsMd = path.join(tmpRoot, "VULN-FINDINGS.md");
  const target = path.join(repoRoot, "tests/fixtures", fixtureName);

  run([
    path.join(repoRoot, "scripts/security-threat-model.mjs"),
    target,
    "--name",
    displayName,
    "--out",
    threatMd,
    "--json-out",
    threatJson,
  ]);

  run([
    path.join(repoRoot, "scripts/security-static-scan.mjs"),
    target,
    "--name",
    displayName,
    "--threat-model",
    threatJson,
    "--out",
    findingsJson,
    "--md-out",
    findingsMd,
  ]);

  assert.ok(fs.existsSync(findingsMd), "expected Markdown output");
  return JSON.parse(fs.readFileSync(findingsJson, "utf8"));
}

const webReport = scanFixture("sample-web-service", "Sample Web Service");
assert.equal(webReport.schema_version, "security-stack.findings.v1");
assert.equal(webReport.tool, "security-static-scan");
assert.equal(webReport.summary.target_label, "Sample Web Service");
assert.equal(webReport.summary.target_basename, "sample-web-service");
assert.ok(webReport.summary.local_private.local_target_path.endsWith("sample-web-service"));
const webCategories = new Set(webReport.findings.map((finding) => finding.category));
assert.ok(webCategories.has("path-traversal"), "expected path traversal candidate");
assert.ok(webCategories.has("secret-exposure"), "expected secret exposure candidate");
assert.ok(webReport.findings.every((finding) => finding.verdict === "candidate"));
assert.ok(
  webReport.findings.every((finding) =>
    ["id", "lane", "category", "title", "severity", "confidence", "evidence", "threat_ids", "redaction_level", "status"].every((field) =>
      Object.hasOwn(finding, field),
    ),
  ),
  "expected stable required finding fields",
);
assert.ok(
  webReport.findings.every((finding) =>
    finding.evidence.every((item) =>
      Object.hasOwn(item, "path") &&
      Object.hasOwn(item, "line") &&
      Object.hasOwn(item, "role") &&
      Object.hasOwn(item, "snippet_redacted"),
    ),
  ),
  "expected stable required evidence fields",
);

const agentReport = scanFixture("sample-agent-tool", "Sample Agent Tool");
const agentCategories = new Set(agentReport.findings.map((finding) => finding.category));
assert.ok(agentCategories.has("command-execution"), "expected command execution candidate");
assert.ok(agentCategories.has("memory-poisoning"), "expected memory poisoning candidate");
assert.ok(
  agentReport.findings.some((finding) => finding.threat_ids.length > 0),
  "expected threat-model links",
);

const docsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "oc-docs-only-"));
fs.writeFileSync(
  path.join(docsRoot, "README.md"),
  "Example text mentions exec(message), process.env.API_TOKEN, and memory.write(message), but this is docs only.\n",
);
const docsOut = path.join(docsRoot, "findings.json");
const docsMd = path.join(docsRoot, "findings.md");
run([
  path.join(repoRoot, "scripts/security-static-scan.mjs"),
  docsRoot,
  "--name",
  "Docs Only",
  "--out",
  docsOut,
  "--md-out",
  docsMd,
]);
const docsReport = JSON.parse(fs.readFileSync(docsOut, "utf8"));
assert.equal(docsReport.findings.length, 0, "docs-only matches should not become findings");

const overwrite = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/security-static-scan.mjs"),
    path.join(repoRoot, "tests/fixtures/sample-agent-tool"),
    "--name",
    "Sample Agent Tool",
    "--out",
    docsOut,
    "--md-out",
    docsMd,
  ],
  { encoding: "utf8" },
);
assert.notEqual(overwrite.status, 0, "expected overwrite without --force to fail");

const unknownOption = spawnSync(
  process.execPath,
  [
    path.join(repoRoot, "scripts/security-static-scan.mjs"),
    path.join(repoRoot, "tests/fixtures/sample-agent-tool"),
    "--not-real",
  ],
  { encoding: "utf8" },
);
assert.notEqual(unknownOption.status, 0, "expected unknown option to fail");

console.log("security-static-scan tests passed");
