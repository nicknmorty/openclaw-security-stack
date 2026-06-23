#!/usr/bin/env node
// Tests for the V0 reporting core: redaction helper, finding-state diff engine,
// and the security-report CLI end to end. Dependency-free (node:assert).

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { redactString, redactValue, makeRedactor } from './lib/redact.mjs';
import { fingerprintFinding, diffFindings, loadState } from './lib/finding-state.mjs';
import { buildReport } from './security-report.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const fixtures = path.join(repoRoot, 'tests', 'fixtures', 'report');

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok - ${name}\n`);
}

// --- redaction ----------------------------------------------------------

test('redactString hides home/user path segment', () => {
  const out = redactString('read /home/somebody/projects/x/y.js now');
  assert.ok(!out.includes('somebody'), 'username must be removed');
  assert.ok(out.includes('~/projects/x/y.js'), `expected ~ rewrite, got: ${out}`);
});

test('redactString hides phone numbers', () => {
  assert.ok(!redactString('call +1 (555) 010-0123 today').match(/010-0123/));
  const e164 = '+1' + '555' + '010' + '0123';
  assert.ok(!redactString(`e164 ${e164} here`).includes(e164));
});

test('redactString hides chat/routing ids', () => {
  assert.ok(redactString('telegram:' + '123' + '456' + '7890').includes('[REDACTED_CHAT_ID]'));
  assert.ok(redactString('group -100' + '123' + '456' + '7890 here').includes('[REDACTED_CHAT_ID]'));
});

test('redactString hides secrets and bearer tokens', () => {
  const fakeGhToken = 'gh' + 'p_' + 'abcdefghijklmnopqrstuvwxyzABCDEFGH';
  assert.ok(redactString('Authorization: Bearer abcdefghijklmnop1234').includes('[REDACTED_SECRET]'));
  assert.ok(redactString(`access_token=${fakeGhToken}`).includes('[REDACTED_SECRET]'));
  assert.ok(!redactString(`bare ${fakeGhToken} token`).includes(fakeGhToken.slice(0, 20)));
});

test('redactValue drops private-only keys and redacts deep', () => {
  const input = {
    summary: { local_private: { local_target_path: '/home/x/p' }, target_label: 'ok' },
    nested: [{ access_token: 'shhh', note: 'see /home/x/p/file.js' }],
  };
  const out = redactValue(input);
  assert.equal(out.summary.local_private, undefined, 'local_private must be dropped');
  assert.equal(out.summary.target_label, 'ok');
  assert.equal(out.nested[0].access_token, '[REDACTED_SECRET]');
  assert.ok(!JSON.stringify(out).includes('/home/x'), 'no home paths should remain');
});

test('redactValue does not mutate the source object', () => {
  const input = { local_private: { p: 1 }, note: '/home/y/z' };
  const snapshot = JSON.stringify(input);
  redactValue(input);
  assert.equal(JSON.stringify(input), snapshot, 'source must be untouched');
});

test('makeRedactor applies extra identity terms', () => {
  const r = makeRedactor({ extraTerms: ['SecretCodename'] });
  assert.ok(r.string('the SecretCodename project').includes('[REDACTED]'));
});

// --- fingerprint + diff --------------------------------------------------

test('fingerprint is stable when only the line moves', () => {
  const a = { lane: 'x', category: 'c', file: 'f.js', title: 't', line: 10 };
  const b = { ...a, line: 999, confidence: 0.9, id: 'F-099' };
  assert.equal(fingerprintFinding(a), fingerprintFinding(b));
});

test('fingerprint differs when category/file/title differ', () => {
  const base = { lane: 'x', category: 'c', file: 'f.js', title: 't' };
  assert.notEqual(fingerprintFinding(base), fingerprintFinding({ ...base, category: 'd' }));
  assert.notEqual(fingerprintFinding(base), fingerprintFinding({ ...base, file: 'g.js' }));
});

test('diffFindings assigns new on first run', () => {
  const cur = [{ lane: 'x', category: 'c', file: 'f.js', title: 't' }];
  const d = diffFindings(cur, undefined, { now: '2026-01-01T00:00:00Z' });
  assert.equal(d.counts.new, 1);
  assert.equal(d.counts.persistent, 0);
  assert.equal(d.counts.resolved, 0);
  assert.equal(d.findings[0].status, 'new');
  assert.equal(d.findings[0].first_seen, '2026-01-01T00:00:00Z');
});

test('diffFindings tracks persistent and resolved across runs', () => {
  const run1 = [
    { lane: 'x', category: 'c', file: 'f.js', title: 'keep' },
    { lane: 'y', category: 'd', file: 'g.js', title: 'gone' },
  ];
  const d1 = diffFindings(run1, undefined, { now: '2026-01-01T00:00:00Z' });
  const run2 = [
    { lane: 'x', category: 'c', file: 'f.js', title: 'keep' },
    { lane: 'z', category: 'e', file: 'h.js', title: 'fresh' },
  ];
  const d2 = diffFindings(run2, d1.nextState, { now: '2026-02-02T00:00:00Z' });
  assert.equal(d2.counts.new, 1, 'fresh is new');
  assert.equal(d2.counts.persistent, 1, 'keep is persistent');
  assert.equal(d2.counts.resolved, 1, 'gone is resolved');
  const keep = d2.findings.find((f) => f.title === 'keep');
  assert.equal(keep.status, 'persistent');
  assert.equal(keep.first_seen, '2026-01-01T00:00:00Z', 'first_seen carried forward');
  assert.equal(d2.resolved[0].title, 'gone');
});

test('buildReport groups findings by status', () => {
  const doc = { tool: 't', schema_version: 's', summary: { target_label: 'L' } };
  const diff = {
    findings: [
      { status: 'new', title: 'a' },
      { status: 'persistent', title: 'b' },
    ],
    resolved: [{ status: 'resolved', title: 'c' }],
    counts: { new: 1, persistent: 1, resolved: 1, total_current: 2 },
  };
  const r = buildReport(doc, diff, {});
  assert.equal(r.findings.new.length, 1);
  assert.equal(r.findings.persistent.length, 1);
  assert.equal(r.findings.resolved.length, 1);
  assert.equal(r.target_label, 'L');
});

// --- end-to-end CLI ------------------------------------------------------

test('CLI produces redacted report and round-trips state', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrep-'));
  const cli = path.join(repoRoot, 'scripts', 'security-report.mjs');
  const run = (findings) =>
    execFileSync(process.execPath, [cli, '--findings', findings, '--out-dir', tmp, '--quiet'], {
      cwd: repoRoot,
      encoding: 'utf8',
    });

  // First run: everything new.
  run(path.join(fixtures, 'findings-run1.json'));
  const report1 = JSON.parse(fs.readFileSync(path.join(tmp, 'REPORT.json'), 'utf8'));
  assert.equal(report1.counts.new, 2, 'run1: two new');
  assert.equal(report1.counts.persistent, 0);
  assert.equal(report1.counts.resolved, 0);

  // Redaction proof on the serialized report.
  const blob1 = fs.readFileSync(path.join(tmp, 'REPORT.json'), 'utf8')
    + fs.readFileSync(path.join(tmp, 'REPORT.md'), 'utf8');
  assert.ok(!blob1.includes('example-user'), 'home username must not leak');
  assert.ok(!blob1.includes('010-0123'), 'phone must not leak');
  assert.ok(!blob1.includes('example-secret'), 'token must not leak');
  assert.ok(!blob1.includes('local_private'), 'private block must be dropped');

  // State file written.
  const state = loadState(path.join(tmp, 'STATE.json'));
  assert.equal(Object.keys(state.findings).length, 2, 'state tracks two findings');

  // Second run: one persists, one resolves, one new.
  run(path.join(fixtures, 'findings-run2.json'));
  const report2 = JSON.parse(fs.readFileSync(path.join(tmp, 'REPORT.json'), 'utf8'));
  assert.equal(report2.counts.persistent, 1, 'run2: path-traversal persists');
  assert.equal(report2.counts.new, 1, 'run2: dependency finding is new');
  assert.equal(report2.counts.resolved, 1, 'run2: prompt-injection resolved');

  fs.rmSync(tmp, { recursive: true, force: true });
});

test('CLI redacts persisted state with the same identity denylist as reports', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrep-id-'));
  const cli = path.join(repoRoot, 'scripts', 'security-report.mjs');
  const findingsPath = path.join(tmp, 'findings.json');
  const identityPath = path.join(tmp, 'identity.json');
  const term = 'ProjectNebulaX';
  fs.writeFileSync(findingsPath, JSON.stringify({
    schema_version: 'security-stack.findings.v1',
    tool: 'identity-fixture',
    summary: { target_label: `${term} target`, target_basename: 'identity-fixture' },
    findings: [{
      lane: 'agent-safety',
      category: 'identity-redaction',
      title: `${term} appears in evidence`,
      severity: 'MEDIUM',
      confidence: 0.9,
      file: 'notes.md',
      evidence: `${term} should be hidden`,
    }],
  }));
  fs.writeFileSync(identityPath, JSON.stringify({ terms: [term] }));

  execFileSync(process.execPath, [cli, '--findings', findingsPath, '--out-dir', tmp, '--identity-file', identityPath, '--quiet'], {
    cwd: repoRoot,
    encoding: 'utf8',
  });

  const combined = fs.readFileSync(path.join(tmp, 'REPORT.json'), 'utf8')
    + fs.readFileSync(path.join(tmp, 'REPORT.md'), 'utf8')
    + fs.readFileSync(path.join(tmp, 'STATE.json'), 'utf8');
  assert.ok(!combined.includes(term), 'identity term must be absent from report and state outputs');
  assert.ok(combined.includes('[REDACTED]'), 'redaction marker should be present');
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('different source tools do not cross-resolve under default out-dir', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrep-ns-'));
  const cli = path.join(repoRoot, 'scripts', 'security-report.mjs');
  const mk = (tool) => {
    const p = path.join(tmp, `${tool}.json`);
    fs.writeFileSync(p, JSON.stringify({
      schema_version: 'security-stack.findings.v1',
      tool,
      summary: { target_basename: 'shared-target', target_label: 'Shared' },
      findings: [{ lane: 'x', category: tool, file: 'a.js', title: `from ${tool}` }],
    }));
    return p;
  };
  // Run cwd=tmp so default runs/report/<target>/<tool> lands inside tmp.
  const run = (p) => execFileSync(process.execPath, [cli, '--findings', p, '--quiet'], { cwd: tmp, encoding: 'utf8' });
  run(mk('tool-a'));
  run(mk('tool-b'));
  const repA = JSON.parse(fs.readFileSync(path.join(tmp, 'runs', 'report', 'shared-target', 'tool-a', 'REPORT.json'), 'utf8'));
  const repB = JSON.parse(fs.readFileSync(path.join(tmp, 'runs', 'report', 'shared-target', 'tool-b', 'REPORT.json'), 'utf8'));
  assert.equal(repA.counts.new, 1);
  assert.equal(repA.counts.resolved, 0, 'tool-a must not be resolved by tool-b run');
  assert.equal(repB.counts.new, 1);
  assert.equal(repB.counts.resolved, 0, 'tool-b must not be resolved by tool-a run');
  fs.rmSync(tmp, { recursive: true, force: true });
});

process.stdout.write(`\n${passed} tests passed\n`);
