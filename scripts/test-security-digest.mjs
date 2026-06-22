#!/usr/bin/env node
// Tests for the shareable digest: pure renderer, collector, and end-to-end via
// the orchestrator (DIGEST.txt) and the standalone CLI.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildDigest, collectNewFindings } from './lib/digest.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const fixtureRoot = path.join(repoRoot, 'tests', 'fixtures', 'supply-chain');

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok - ${name}\n`); }

test('buildDigest lists new findings sorted by severity and truncates to topN', () => {
  const text = buildDigest({
    generated: '2026-01-01T00:00:00Z',
    totals: { new: 3, persistent: 1, acknowledged: 5, resolved: 0 },
    by_severity: { HIGH: 1, MEDIUM: 2, LOW: 0 },
    toolStatuses: [{ label: 'x', tool: 'static-scan', ok: true }],
    newFindings: [
      { severity: 'LOW', title: 'low one', tool: 't', target: 'x' },
      { severity: 'HIGH', title: 'high one', file: 'a.js', line: 9, tool: 't', target: 'x' },
      { severity: 'MEDIUM', title: 'med one', tool: 't', target: 'x' },
    ],
  }, { topN: 2 });
  const idxHigh = text.indexOf('high one');
  const idxMed = text.indexOf('med one');
  assert.ok(idxHigh > 0 && idxMed > 0 && idxHigh < idxMed, 'HIGH listed before MEDIUM');
  assert.ok(text.includes('+1 more new'), 'truncation note present');
  assert.ok(text.includes('acknowledged 5'), 'shows acknowledged count');
  assert.ok(text.includes('a.js:9'), 'shows file:line');
});

test('buildDigest reports clean state and failed tools', () => {
  const clean = buildDigest({ totals: { new: 0 }, by_severity: {}, newFindings: [], toolStatuses: [{ tool: 'x', ok: true }] });
  assert.ok(clean.includes('No new findings'));
  const failed = buildDigest({ totals: {}, newFindings: [], toolStatuses: [{ tool: 'static-scan', label: 'r', ok: false, error: 'boom' }] });
  assert.ok(/failed/.test(failed) && failed.includes('static-scan@r'));
});

test('collectNewFindings filters by severity and pulls context', () => {
  const reports = [{
    source_tool: 'runtime-health', target_label: 'host',
    findings: { new: [{ severity: 'HIGH', title: 'a' }, { severity: 'LOW', title: 'b' }] },
  }];
  const all = collectNewFindings(reports);
  assert.equal(all.length, 2);
  assert.equal(all[0].tool, 'runtime-health');
  const high = collectNewFindings(reports, { severities: ['HIGH'] });
  assert.equal(high.length, 1);
  assert.equal(high[0].title, 'a');
});

test('orchestrator writes DIGEST.txt and standalone CLI reproduces it', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'digest-'));
  const scan = path.join(repoRoot, 'scripts', 'security-scan.mjs');
  const digestCli = path.join(repoRoot, 'scripts', 'security-digest.mjs');
  execFileSync(process.execPath, [scan, '--target', fixtureRoot, '--label', 'fx',
    '--scanners', 'supply-chain', '--out-root', tmp, '--quiet'], { cwd: repoRoot });

  const digestPath = path.join(tmp, 'summary', 'DIGEST.txt');
  assert.ok(fs.existsSync(digestPath), 'orchestrator wrote DIGEST.txt');
  const orchDigest = fs.readFileSync(digestPath, 'utf8');
  assert.ok(orchDigest.includes('Security digest'));
  assert.ok(/New findings|No new findings/.test(orchDigest));
  assert.ok(!orchDigest.includes('example-user'), 'digest must not leak username');

  // standalone CLI over the same runs root produces a digest too
  const cliOut = execFileSync(process.execPath, [digestCli, '--runs', tmp], { cwd: repoRoot, encoding: 'utf8' });
  assert.ok(cliOut.includes('Security digest'));
  assert.ok(cliOut.includes('Active:'));
  fs.rmSync(tmp, { recursive: true, force: true });
});

process.stdout.write(`\n${passed} tests passed\n`);
