#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "oc-security-guards-"));
const stateDir = path.join(tmpRoot, "state");
const reportDir = path.join(tmpRoot, "reports");
const containmentDir = path.join(tmpRoot, "oauth");
const agentDir = path.join(stateDir, "agents/example/agent");
fs.mkdirSync(agentDir, { recursive: true });
fs.writeFileSync(
  path.join(agentDir, "auth-profiles.json"),
  JSON.stringify({ profiles: { bad: { type: "api_key", key: "sk-example-not-real" } } }),
);
fs.writeFileSync(
  path.join(agentDir, "models.json"),
  JSON.stringify({ providers: { bad: { apiKey: "literal-example-key" } } }),
);
fs.mkdirSync(path.join(agentDir, "codex-home"), { recursive: true });
const unsupportedStore = path.join(agentDir, "codex-home/auth.json");
fs.writeFileSync(unsupportedStore, "{}\n");

const guard = spawnSync(
  "bash",
  [path.join(repoRoot, "scripts/security-secret-guard.sh")],
  {
    encoding: "utf8",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_WORKSPACE: repoRoot,
      SECURITY_SECRET_GUARD_REPORT_DIR: reportDir,
      HOME: tmpRoot,
    },
  },
);
assert.equal(guard.status, 2, guard.stdout + guard.stderr);
assert.match(guard.stdout, /security-secret-guard findings=/);
assert.match(guard.stdout, /OpenClawAuthProfile/);
assert.ok(fs.existsSync(unsupportedStore), "default guard mode must not delete unsupported stores");

fs.mkdirSync(containmentDir, { recursive: true, mode: 0o755 });
fs.chmodSync(containmentDir, 0o755);
fs.chmodSync(agentDir, 0o755);
fs.chmodSync(path.join(agentDir, "auth-profiles.json"), 0o644);

const audit = spawnSync(
  "bash",
  [path.join(repoRoot, "scripts/oauth-containment-audit.sh")],
  {
    encoding: "utf8",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_WORKSPACE: repoRoot,
      OAUTH_CONTAINMENT_DIR: containmentDir,
      HOME: tmpRoot,
    },
  },
);
assert.notEqual(audit.status, 0, audit.stdout + audit.stderr);
assert.match(audit.stdout, /fail\tdir-mode-755/);
assert.equal((fs.statSync(containmentDir).mode & 0o777).toString(8), "755");

const fix = spawnSync(
  "bash",
  [path.join(repoRoot, "scripts/oauth-containment-audit.sh"), "--fix"],
  {
    encoding: "utf8",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_WORKSPACE: repoRoot,
      OAUTH_CONTAINMENT_DIR: containmentDir,
      HOME: tmpRoot,
    },
  },
);
assert.equal(fix.status, 0, fix.stdout + fix.stderr);
assert.equal((fs.statSync(containmentDir).mode & 0o777).toString(8), "700");
assert.equal((fs.statSync(path.join(agentDir, "auth-profiles.json")).mode & 0o777).toString(8), "600");

const redactor = spawnSync(
  "bash",
  [path.join(repoRoot, "scripts/redact-sensitive-output.sh")],
  { input: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"refresh_token":"secret-value"\n', encoding: "utf8" },
);
assert.equal(redactor.status, 0, redactor.stderr);
assert.doesNotMatch(redactor.stdout, /abcdefghijklmnopqrstuvwxyz|secret-value/);
assert.match(redactor.stdout, /\[REDACTED\]/);

console.log("security guard script tests passed");
