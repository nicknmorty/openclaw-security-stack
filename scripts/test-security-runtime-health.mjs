#!/usr/bin/env node
// Tests for the runtime-health lane: pure analyzers, doc assembly, and an
// end-to-end run through the report core. Dependency-free (node:assert).

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  analyzeListeningSockets, analyzeSshConfig, analyzeKeyPerms,
  analyzeSensitiveFiles, analyzeFirewall, buildFindingsDoc,
} from './security-runtime-health.mjs';
import { fingerprintFinding } from './lib/finding-state.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok - ${name}\n`); }

test('analyzeListeningSockets flags non-loopback only and dedupes', () => {
  const ss = [
    'tcp   LISTEN 0 4096  127.0.0.1:8188   0.0.0.0:*',
    'tcp   LISTEN 0 511   0.0.0.0:80       0.0.0.0:*',
    'tcp   LISTEN 0 511   [::]:443         [::]:*',
    'tcp   LISTEN 0 511   0.0.0.0:80       0.0.0.0:*',
    'tcp   LISTEN 0 128   ::1:5432         [::]:*',
  ].join('\n');
  const f = analyzeListeningSockets(ss);
  assert.equal(f.length, 2, 'only :80 and :443 exposed (dedup, loopback excluded)');
  assert.ok(f.every((x) => x.category === 'listening-non-loopback' && x.severity === 'MEDIUM'));
});

test('listening socket fingerprints include protocol/address/port identity', () => {
  const ss = [
    'tcp   LISTEN 0 511   0.0.0.0:22       0.0.0.0:*',
    'tcp   LISTEN 0 511   0.0.0.0:443      0.0.0.0:*',
    'udp   UNCONN 0 0      0.0.0.0:443      0.0.0.0:*',
  ].join('\n');
  const f = analyzeListeningSockets(ss).map((finding) => ({
    lane: 'runtime-health',
    ...finding,
  }));
  assert.equal(f.length, 3);
  assert.deepEqual(
    f.map((x) => x.fingerprint_key).sort(),
    ['tcp:0.0.0.0:22', 'tcp:0.0.0.0:443', 'udp:0.0.0.0:443'],
  );
  assert.equal(new Set(f.map((x) => fingerprintFinding(x))).size, 3);
});

test('analyzeSshConfig flags root login + password auth, ignores comments', () => {
  const cfg = '#PermitRootLogin no\nPermitRootLogin yes\nPasswordAuthentication yes\n';
  const f = analyzeSshConfig(cfg);
  const cats = f.map((x) => x.category).sort();
  assert.deepEqual(cats, ['ssh-password-auth', 'ssh-permit-root-login']);
  assert.equal(f.find((x) => x.category === 'ssh-permit-root-login').severity, 'HIGH');
});

test('analyzeSshConfig is quiet for hardened config', () => {
  const cfg = 'PermitRootLogin prohibit-password\nPasswordAuthentication no\n';
  assert.equal(analyzeSshConfig(cfg).length, 0);
});

test('analyzeKeyPerms flags loose modes only', () => {
  assert.equal(analyzeKeyPerms([{ file: '~/.ssh/id_ed25519', mode: 0o600 }]).length, 0);
  const f = analyzeKeyPerms([{ file: '~/.ssh/id_rsa', mode: 0o644 }]);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'HIGH');
});

test('analyzeSensitiveFiles flags group/other-readable', () => {
  assert.equal(analyzeSensitiveFiles([{ path: '/x/.env', mode: 0o600 }]).length, 0);
  assert.equal(analyzeSensitiveFiles([{ path: '/x/.env', mode: 0o640 }]).length, 1);
});

test('analyzeFirewall: quiet when active or undetermined, flags when none', () => {
  assert.equal(analyzeFirewall({ ufwActive: true, iptablesRules: 0 }).length, 0);
  assert.equal(analyzeFirewall({ ufwActive: null, iptablesRules: null }).length, 0);
  assert.equal(analyzeFirewall({ ufwActive: false, iptablesRules: 0 }).length, 1);
});

test('buildFindingsDoc assigns ids/lane, sorts by severity, counts', () => {
  const doc = buildFindingsDoc([
    { category: 'a', severity: 'LOW', title: 'low' },
    { category: 'b', severity: 'HIGH', title: 'high' },
  ], { label: 'h', checksRun: ['x'] });
  assert.equal(doc.schema_version, 'security-stack.findings.v1');
  assert.equal(doc.tool, 'security-runtime-health');
  assert.equal(doc.findings[0].severity, 'HIGH', 'sorted high first');
  assert.ok(doc.findings.every((f) => f.lane === 'runtime-health' && /^RH-\d{3}$/.test(f.id)));
  assert.equal(doc.summary.by_severity.HIGH, 1);
  assert.equal(doc.summary.by_severity.LOW, 1);
});

test('end-to-end runtime-health run flows through the report core', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rh-'));
  const emptySsh = path.join(tmp, 'ssh-empty');
  fs.mkdirSync(emptySsh);
  const node = process.execPath;
  const scan = path.join(repoRoot, 'scripts', 'security-runtime-health.mjs');
  const report = path.join(repoRoot, 'scripts', 'security-report.mjs');
  const outDir = path.join(tmp, 'rh-out');

  execFileSync(node, [scan, '--label', 'test-host', '--ssh-dir', emptySsh, '--out-dir', outDir, '--quiet'], { cwd: repoRoot });
  const doc = JSON.parse(fs.readFileSync(path.join(outDir, 'RUNTIME-HEALTH-FINDINGS.json'), 'utf8'));
  assert.equal(doc.schema_version, 'security-stack.findings.v1');
  assert.equal(doc.tool, 'security-runtime-health');
  assert.ok(Array.isArray(doc.summary.checks_run));

  const reportDir = path.join(tmp, 'report');
  execFileSync(node, [report, '--findings', path.join(outDir, 'RUNTIME-HEALTH-FINDINGS.json'), '--out-dir', reportDir, '--quiet'], { cwd: repoRoot });
  const rep = JSON.parse(fs.readFileSync(path.join(reportDir, 'REPORT.json'), 'utf8'));
  assert.equal(rep.source_tool, 'security-runtime-health');
  // redaction proof: no home username in the report
  const blob = fs.readFileSync(path.join(reportDir, 'REPORT.json'), 'utf8');
  assert.ok(!blob.includes(os.userInfo().username) || os.userInfo().username.length < 3, 'no host username leak');

  fs.rmSync(tmp, { recursive: true, force: true });
});

process.stdout.write(`\n${passed} tests passed\n`);
