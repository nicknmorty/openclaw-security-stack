#!/usr/bin/env node
// security-stack runtime-health scanner (v1 lane)
//
// Read-only host posture checks emitted as `security-stack.findings.v1` so they
// flow through scripts/security-report.mjs and the orchestrator.
//
// Design goals:
// - Portable + generic: no hardcoded host paths, usernames, or identity. Works
//   on any Linux/macOS host; degrades gracefully where tools/files are missing.
// - Read-only. Detection before remediation. No service/config/firewall changes.
// - Core checks are PURE functions fed string/stat inputs, so they are testable
//   without depending on the live host. main() gathers live inputs best-effort.
//
// Usage:
//   node scripts/security-runtime-health.mjs [--label <name>] [--scope <dir>]
//        [--out-dir <dir>] [--ssh-dir <dir>] [--sensitive <path,path>] [--quiet]

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const FINDINGS_SCHEMA_VERSION = 'security-stack.findings.v1';
const SEV_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 };

// --- pure analyzers ------------------------------------------------------

// ss -H -tuln output -> findings for non-loopback listeners.
export function analyzeListeningSockets(ssText) {
  const findings = [];
  const seen = new Set();
  for (const line of String(ssText || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    const parts = t.split(/\s+/);
    if (parts.length < 5) continue;
    const proto = parts[0];
    const local = parts[4];
    const m = local.match(/^(.*):([0-9*]+)$/);
    if (!m) continue;
    let addr = m[1];
    const port = m[2];
    addr = addr.replace(/^\[|\]$/g, '');
    const isLoopback = addr === '127.0.0.1' || addr.startsWith('127.') || addr === '::1';
    const isUnspecified = addr === '0.0.0.0' || addr === '::' || addr === '*';
    if (isLoopback) continue;
    const key = `${proto}:${addr}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      category: 'listening-non-loopback',
      title: isUnspecified
        ? 'Service listening on all interfaces'
        : 'Service listening on a non-loopback address',
      severity: 'MEDIUM',
      confidence: 0.6,
      surface: 'Network exposure',
      detail: `${proto} listening on ${addr}:${port}. Confirm this exposure is intended.`,
    });
  }
  return findings;
}

// sshd_config (concatenated) -> findings for risky directives.
export function analyzeSshConfig(configText) {
  const findings = [];
  const directives = {};
  for (const line of String(configText || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const m = t.match(/^(\w+)\s+(.+?)\s*$/);
    if (!m) continue;
    directives[m[1].toLowerCase()] = m[2].toLowerCase();
  }
  if (directives.permitrootlogin === 'yes') {
    findings.push({
      category: 'ssh-permit-root-login',
      title: 'SSH permits direct root login',
      severity: 'HIGH',
      confidence: 0.9,
      surface: 'SSH access',
      detail: 'PermitRootLogin yes allows direct root SSH login.',
    });
  }
  if (directives.passwordauthentication === 'yes') {
    findings.push({
      category: 'ssh-password-auth',
      title: 'SSH password authentication is enabled',
      severity: 'MEDIUM',
      confidence: 0.8,
      surface: 'SSH access',
      detail: 'PasswordAuthentication yes permits brute-forceable password logins.',
    });
  }
  return findings;
}

// entries: [{ file, mode }] (mode is the numeric st_mode & 0o777) -> findings.
export function analyzeKeyPerms(entries) {
  const findings = [];
  for (const e of entries || []) {
    if (typeof e.mode !== 'number') continue;
    if (e.mode & 0o077) {
      findings.push({
        category: 'ssh-key-loose-perms',
        title: 'SSH private key is group/other-accessible',
        severity: 'HIGH',
        confidence: 0.95,
        surface: 'Credential exposure',
        file: e.file,
        detail: `Private key mode ${e.mode.toString(8).padStart(3, '0')} grants group/other access; should be 600.`,
      });
    }
  }
  return findings;
}

// entries: [{ path, mode }] for configured sensitive files -> findings.
export function analyzeSensitiveFiles(entries) {
  const findings = [];
  for (const e of entries || []) {
    if (typeof e.mode !== 'number') continue;
    if (e.mode & 0o077) {
      findings.push({
        category: 'world-readable-sensitive-file',
        title: 'Sensitive file is group/other-accessible',
        severity: 'MEDIUM',
        confidence: 0.85,
        surface: 'Credential exposure',
        file: e.path,
        detail: `Mode ${e.mode.toString(8).padStart(3, '0')} grants group/other access to a sensitive file.`,
      });
    }
  }
  return findings;
}

// state: { ufwActive: bool|null, iptablesRules: number|null } -> finding if none.
export function analyzeFirewall(state) {
  const { ufwActive, iptablesRules } = state || {};
  if (ufwActive === true) return [];
  if (typeof iptablesRules === 'number' && iptablesRules > 0) return [];
  if (ufwActive === null && iptablesRules === null) return []; // couldn't determine; stay quiet
  return [{
    category: 'no-active-firewall',
    title: 'No active host firewall detected',
    severity: 'LOW',
    confidence: 0.5,
    surface: 'Network exposure',
    detail: 'Neither an active ufw profile nor iptables rules were detected. Confirm host firewalling.',
  }];
}

// --- live collectors (best-effort) --------------------------------------

function tryExec(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'], ...opts });
  } catch {
    return null;
  }
}

function readFileSafe(p) {
  try { return fs.readFileSync(p, 'utf8'); } catch { return null; }
}

function collectSsh() {
  const parts = [];
  const main = readFileSafe('/etc/ssh/sshd_config');
  if (main) parts.push(main);
  try {
    for (const f of fs.readdirSync('/etc/ssh/sshd_config.d')) {
      if (f.endsWith('.conf')) {
        const c = readFileSafe(path.join('/etc/ssh/sshd_config.d', f));
        if (c) parts.push(c);
      }
    }
  } catch { /* dir absent */ }
  return parts.length ? parts.join('\n') : null;
}

function collectKeyPerms(sshDir) {
  const entries = [];
  let names;
  try { names = fs.readdirSync(sshDir); } catch { return { entries, available: false }; }
  for (const name of names) {
    if (name.endsWith('.pub')) continue;
    if (!/^id_|_rsa$|_ed25519$|_ecdsa$|_dsa$/.test(name)) continue;
    const full = path.join(sshDir, name);
    try {
      const st = fs.statSync(full);
      if (st.isFile()) entries.push({ file: path.join('~/.ssh', name), mode: st.mode & 0o777 });
    } catch { /* skip */ }
  }
  return { entries, available: true };
}

function collectSensitive(paths) {
  const entries = [];
  for (const p of paths || []) {
    try {
      const st = fs.statSync(p);
      if (st.isFile()) entries.push({ path: p, mode: st.mode & 0o777 });
    } catch { /* skip missing */ }
  }
  return entries;
}

function collectFirewall() {
  let ufwActive = null;
  const ufw = tryExec('ufw', ['status']);
  if (ufw !== null) ufwActive = /status:\s*active/i.test(ufw);
  let iptablesRules = null;
  const ipt = tryExec('iptables', ['-S']);
  if (ipt !== null) {
    // Count non-policy rules (lines starting with -A).
    iptablesRules = ipt.split(/\r?\n/).filter((l) => l.startsWith('-A')).length;
  }
  return { ufwActive, iptablesRules };
}

// --- assembly ------------------------------------------------------------

export function buildFindingsDoc(rawFindings, meta = {}) {
  let counter = 0;
  const findings = rawFindings.map((f) => {
    counter += 1;
    return {
      id: `RH-${String(counter).padStart(3, '0')}`,
      lane: 'runtime-health',
      status: 'new',
      verdict: 'observation',
      redaction_level: 'shareable-redacted',
      ...f,
    };
  });
  findings.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  const by_severity = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) if (by_severity[f.severity] !== undefined) by_severity[f.severity] += 1;
  return {
    schema_version: FINDINGS_SCHEMA_VERSION,
    tool: 'security-runtime-health',
    summary: {
      scanner: 'security-runtime-health',
      mode: 'host-readonly',
      name: meta.label || 'host',
      target_label: meta.label || 'host',
      target_basename: meta.label || 'host',
      date: new Date().toISOString(),
      checks_run: meta.checksRun || [],
      checks_skipped: meta.checksSkipped || [],
      finding_count: findings.length,
      by_severity,
      by_lane: { 'runtime-health': findings.length },
    },
    findings,
  };
}

function parseArgs(argv) {
  const args = { quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    switch (a) {
      case '--label': args.label = argv[++i]; break;
      case '--scope': args.scope = argv[++i]; break;
      case '--out-dir': args.outDir = argv[++i]; break;
      case '--ssh-dir': args.sshDir = argv[++i]; break;
      case '--sensitive': args.sensitive = argv[++i].split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--quiet': args.quiet = true; break;
      case '-h': case '--help': args.help = true; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

function usage() {
  return [
    'Usage: node scripts/security-runtime-health.mjs [options]',
    '  --label <name>       Label for output (default: host)',
    '  --out-dir <dir>      Output dir (default runs/runtime-health/<label>)',
    '  --ssh-dir <dir>      SSH key dir to check (default ~/.ssh)',
    '  --sensitive <list>   Comma list of sensitive file paths to permission-check',
    '  --quiet              Suppress stdout summary',
  ].join('\n');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(`${usage()}\n`); return; }
  const label = args.label || os.hostname() || 'host';
  const checksRun = [];
  const checksSkipped = [];
  const findings = [];

  // listening sockets
  const ss = tryExec('ss', ['-H', '-tuln']);
  if (ss !== null) { checksRun.push('listening-sockets'); findings.push(...analyzeListeningSockets(ss)); }
  else checksSkipped.push('listening-sockets');

  // ssh config
  const sshConf = collectSsh();
  if (sshConf !== null) { checksRun.push('ssh-config'); findings.push(...analyzeSshConfig(sshConf)); }
  else checksSkipped.push('ssh-config');

  // ssh key perms
  const sshDir = args.sshDir || path.join(os.homedir(), '.ssh');
  const keys = collectKeyPerms(sshDir);
  if (keys.available) { checksRun.push('ssh-key-perms'); findings.push(...analyzeKeyPerms(keys.entries)); }
  else checksSkipped.push('ssh-key-perms');

  // sensitive files (only if provided)
  if (args.sensitive && args.sensitive.length) {
    checksRun.push('sensitive-files');
    findings.push(...analyzeSensitiveFiles(collectSensitive(args.sensitive)));
  }

  // firewall
  const fw = collectFirewall();
  if (fw.ufwActive !== null || fw.iptablesRules !== null) { checksRun.push('firewall'); findings.push(...analyzeFirewall(fw)); }
  else checksSkipped.push('firewall');

  const doc = buildFindingsDoc(findings, { label, checksRun, checksSkipped });
  const outDir = args.outDir || path.join('runs', 'runtime-health', label.replace(/[^A-Za-z0-9._-]+/g, '-'));
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'RUNTIME-HEALTH-FINDINGS.json');
  fs.writeFileSync(jsonPath, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');

  if (!args.quiet) {
    const s = doc.summary.by_severity;
    process.stdout.write(
      `security-runtime-health: ${label}\n`
        + `  findings=${doc.summary.finding_count} (H=${s.HIGH} M=${s.MEDIUM} L=${s.LOW})\n`
        + `  ran: ${checksRun.join(', ') || 'none'}\n`
        + `  skipped: ${checksSkipped.join(', ') || 'none'}\n`
        + `  output: ${jsonPath}\n`,
    );
  }
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try { main(); } catch (err) {
    process.stderr.write(`security-runtime-health error: ${err.message}\n`);
    process.exitCode = 1;
  }
}
