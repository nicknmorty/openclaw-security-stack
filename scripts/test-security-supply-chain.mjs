#!/usr/bin/env node
// Tests for the supply-chain inventory scanner and its handoff into the
// report core. Dependency-free (node:assert).

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkManifests, analyze } from './security-supply-chain.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const fixtureRoot = path.join(repoRoot, 'tests', 'fixtures', 'supply-chain');

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok - ${name}\n`);
}

test('walkManifests finds manifests and skips noise dirs', () => {
  const { files } = walkManifests(fixtureRoot);
  const names = files.map((f) => path.relative(fixtureRoot, f));
  assert.ok(names.includes('sample-npm/package.json'));
  assert.ok(names.includes('sample-py/requirements.txt'));
  assert.ok(names.includes('sample-py-locked/requirements.txt'));
});

test('walkManifests honors max-entries guard (truncates)', () => {
  const { truncated } = walkManifests(fixtureRoot, 1);
  assert.equal(truncated, true);
});

test('analyze inventories npm + python projects', () => {
  const { files } = walkManifests(fixtureRoot);
  const { inventory } = analyze(files, fixtureRoot);
  assert.equal(inventory.npm.length, 1, 'one npm project');
  assert.equal(inventory.python.length, 2, 'two python projects');
  assert.equal(inventory.npm[0].dependency_count, 4);
  assert.equal(inventory.npm[0].lockfile, null);
});

test('analyze flags unpinned deps and non-registry sources', () => {
  const { files } = walkManifests(fixtureRoot);
  const { findings } = analyze(files, fixtureRoot);
  const cats = findings.map((f) => f.category).sort();
  const nonRegistry = findings.filter((f) => f.category === 'non-registry-dependency-source');
  const unpinnedNpm = findings.filter((f) => f.category === 'unpinned-dependencies');
  const unpinnedPy = findings.filter((f) => f.category === 'unpinned-python-requirement');
  assert.equal(nonRegistry.length, 2, 'git+https and owner/repo sources flagged');
  assert.equal(unpinnedNpm.length, 1, 'npm manifest w/o lock flagged once');
  assert.equal(unpinnedPy.length, 1, 'py unpinned reqs flagged once');
  assert.ok(nonRegistry.every((f) => f.severity === 'MEDIUM'));
  assert.ok(unpinnedNpm.every((f) => f.severity === 'LOW'));
  // locked python project must not produce a finding
  assert.ok(!findings.some((f) => f.file.includes('sample-py-locked')));
  // every finding carries supply-chain lane + new status (report-core ready)
  assert.ok(findings.every((f) => f.lane === 'supply-chain' && f.status === 'new'));
  assert.ok(cats.length === 4);
});

test('scanner output flows through the report core (pipeline)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-'));
  const node = process.execPath;
  const scan = path.join(repoRoot, 'scripts', 'security-supply-chain.mjs');
  const report = path.join(repoRoot, 'scripts', 'security-report.mjs');

  execFileSync(node, [scan, '--target', fixtureRoot, '--out-dir', tmp, '--quiet'], { cwd: repoRoot });
  const findingsFile = path.join(tmp, 'SUPPLY-CHAIN-FINDINGS.json');
  const doc = JSON.parse(fs.readFileSync(findingsFile, 'utf8'));
  assert.equal(doc.schema_version, 'security-stack.findings.v1');
  assert.equal(doc.summary.finding_count, 4);

  const reportDir = path.join(tmp, 'report');
  execFileSync(node, [report, '--findings', findingsFile, '--out-dir', reportDir, '--quiet'], { cwd: repoRoot });
  const rep = JSON.parse(fs.readFileSync(path.join(reportDir, 'REPORT.json'), 'utf8'));
  assert.equal(rep.counts.new, 4, 'all four findings are new on first report');
  assert.equal(rep.source_tool, 'security-supply-chain');

  fs.rmSync(tmp, { recursive: true, force: true });
});

process.stdout.write(`\n${passed} tests passed\n`);
