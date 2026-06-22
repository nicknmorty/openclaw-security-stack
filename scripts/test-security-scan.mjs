#!/usr/bin/env node
// Tests for the security-scan orchestrator: config loading, summary building,
// and an end-to-end run that produces a consolidated redacted SUMMARY.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadConfig, buildSummary, ALL_SCANNERS } from './security-scan.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const fixtureRoot = path.join(repoRoot, 'tests', 'fixtures', 'supply-chain');

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok - ${name}\n`); }

test('loadConfig builds ad-hoc config from --target', () => {
  const cfg = loadConfig({ target: fixtureRoot, label: 'fx', scanners: ['supply-chain'], redact: true });
  assert.equal(cfg.targets.length, 1);
  assert.equal(cfg.targets[0].label, 'fx');
  assert.deepEqual(cfg.targets[0].scanners, ['supply-chain']);
});

test('loadConfig defaults scanners to all', () => {
  const cfg = loadConfig({ target: fixtureRoot, redact: true });
  assert.deepEqual(cfg.targets[0].scanners, ALL_SCANNERS);
});

test('buildSummary aggregates counts and severities', () => {
  const perTarget = [{
    label: 'x',
    tools: [
      { tool: 'supply-chain', ok: true, counts: { new: 2, persistent: 1, resolved: 0, total_current: 3 },
        report: { findings: { new: [{ severity: 'MEDIUM' }, { severity: 'LOW' }], persistent: [{ severity: 'LOW' }] } } },
      { tool: 'static-scan', ok: false, error: 'boom' },
    ],
  }];
  const s = buildSummary(perTarget, { now: '2026-01-01T00:00:00Z' });
  assert.equal(s.totals.new, 2);
  assert.equal(s.totals.persistent, 1);
  assert.equal(s.by_severity.MEDIUM, 1);
  assert.equal(s.by_severity.LOW, 2);
  assert.equal(s.targets[0].tools[1].ok, false);
  assert.equal(s.targets[0].tools[1].error, 'boom');
});

test('end-to-end orchestrator run produces consolidated redacted summary', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-'));
  const cli = path.join(repoRoot, 'scripts', 'security-scan.mjs');
  execFileSync(process.execPath, [cli, '--target', fixtureRoot, '--label', 'fixture-supply',
    '--scanners', 'supply-chain', '--out-root', tmp, '--quiet'], { cwd: repoRoot });

  const summaryPath = path.join(repoRoot, tmp, 'summary', 'SUMMARY.json');
  // out-root is resolved relative to repoRoot inside the orchestrator for the
  // summary write; handle both absolute and relative tmp.
  const resolved = fs.existsSync(summaryPath) ? summaryPath : path.join(tmp, 'summary', 'SUMMARY.json');
  const summary = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  assert.equal(summary.schema_version, 'security-stack.scan-summary.v1');
  assert.equal(summary.targets.length, 1);
  const sc = summary.targets[0].tools.find((t) => t.tool === 'supply-chain');
  assert.ok(sc.ok, 'supply-chain scanner ran');
  assert.ok(sc.counts.new >= 1, 'fixture produced findings');

  // Redaction proof: no home username should leak into the summary.
  const blob = fs.readFileSync(resolved, 'utf8') + fs.readFileSync(resolved.replace('.json', '.md'), 'utf8');
  assert.ok(!blob.includes('example-user'), 'no home username in summary');

  fs.rmSync(tmp, { recursive: true, force: true });
});

process.stdout.write(`\n${passed} tests passed\n`);
