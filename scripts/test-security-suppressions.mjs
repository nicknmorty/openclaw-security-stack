#!/usr/bin/env node
// Tests for the suppression (acknowledge/ignore) engine + report integration.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { matchSuppression, applySuppressions, isExpired } from './lib/suppressions.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const fixtures = path.join(repoRoot, 'tests', 'fixtures', 'report');

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok - ${name}\n`); }

const NOW = '2026-06-01T00:00:00Z';

test('matchSuppression matches exact fingerprint', () => {
  const f = { fingerprint: 'f-abc', lane: 'x' };
  assert.ok(matchSuppression(f, [{ fingerprint: 'f-abc' }], NOW));
  assert.equal(matchSuppression(f, [{ fingerprint: 'f-zzz' }], NOW), null);
});

test('matchSuppression matches rule (all specified fields)', () => {
  const f = { lane: 'runtime-health', category: 'listening-non-loopback', severity: 'MEDIUM' };
  assert.ok(matchSuppression(f, [{ match: { lane: 'runtime-health', category: 'listening-non-loopback' } }], NOW));
  assert.equal(matchSuppression(f, [{ match: { lane: 'runtime-health', category: 'other' } }], NOW), null);
  // empty match rule never matches
  assert.equal(matchSuppression(f, [{ match: {} }], NOW), null);
});

test('isExpired / expired suppressions do not match', () => {
  assert.equal(isExpired({ expires: '2020-01-01' }, NOW), true);
  assert.equal(isExpired({ expires: '2999-01-01' }, NOW), false);
  assert.equal(isExpired({}, NOW), false);
  const f = { fingerprint: 'f-abc' };
  assert.equal(matchSuppression(f, [{ fingerprint: 'f-abc', expires: '2020-01-01' }], NOW), null);
});

test('applySuppressions splits active vs acknowledged without mutating source', () => {
  const findings = [
    { fingerprint: 'f-1', lane: 'a', status: 'new' },
    { fingerprint: 'f-2', lane: 'runtime-health', category: 'listening-non-loopback', status: 'persistent' },
  ];
  const snapshot = JSON.stringify(findings);
  const { active, acknowledged } = applySuppressions(findings, [{ match: { lane: 'runtime-health' } }], NOW);
  assert.equal(active.length, 1);
  assert.equal(active[0].fingerprint, 'f-1');
  assert.equal(acknowledged.length, 1);
  assert.equal(acknowledged[0].status, 'acknowledged');
  assert.equal(acknowledged[0].suppression.matched_by, 'rule');
  assert.equal(JSON.stringify(findings), snapshot, 'source not mutated');
});

test('report CLI applies suppressions and reduces active counts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supp-'));
  const cli = path.join(repoRoot, 'scripts', 'security-report.mjs');
  // run1 fixture has 2 findings: runtime path-traversal + agent prompt-injection.
  const suppFile = path.join(tmp, 'supp.json');
  fs.writeFileSync(suppFile, JSON.stringify({
    suppressions: [{ match: { category: 'path-traversal' }, reason: 'accepted in fixture' }],
  }));
  execFileSync(process.execPath, [cli, '--findings', path.join(fixtures, 'findings-run1.json'),
    '--out-dir', tmp, '--suppressions', suppFile, '--quiet'], { cwd: repoRoot });
  const rep = JSON.parse(fs.readFileSync(path.join(tmp, 'REPORT.json'), 'utf8'));
  assert.equal(rep.counts.acknowledged, 1, 'path-traversal acknowledged');
  assert.equal(rep.counts.new, 1, 'only the non-suppressed finding remains new');
  assert.equal(rep.findings.acknowledged.length, 1);
  assert.ok(rep.findings.acknowledged[0].suppression, 'acknowledged finding carries suppression info');
  // markdown shows an Acknowledged section
  const md = fs.readFileSync(path.join(tmp, 'REPORT.md'), 'utf8');
  assert.ok(/Acknowledged findings \(1\)/.test(md));
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('no suppressions -> acknowledged is zero (back-compat)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'supp0-'));
  const cli = path.join(repoRoot, 'scripts', 'security-report.mjs');
  execFileSync(process.execPath, [cli, '--findings', path.join(fixtures, 'findings-run1.json'),
    '--out-dir', tmp, '--quiet'], { cwd: tmp });
  const rep = JSON.parse(fs.readFileSync(path.join(tmp, 'REPORT.json'), 'utf8'));
  assert.equal(rep.counts.acknowledged, 0);
  assert.equal(rep.counts.new, 2);
  fs.rmSync(tmp, { recursive: true, force: true });
});

process.stdout.write(`\n${passed} tests passed\n`);
