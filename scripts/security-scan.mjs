#!/usr/bin/env node
// security-stack orchestrator (v1 "usable" entry point)
//
// Runs the configured scanners against one or more targets and produces a
// consolidated, redacted, local-only report:
//   threat-model -> static-scan (consumes the threat model) -> supply-chain
//   -> per-tool report (redacted, with new/persistent/resolved state)
//   -> SUMMARY.json + SUMMARY.md across all targets and tools.
//
// Safety contract:
// - Read-only with respect to scanned targets. Detection before remediation.
// - All output is local-only under <out-root>/ and redacted by default.
// - One scanner failing does not abort the whole run; failures are recorded.
//
// Usage:
//   node scripts/security-scan.mjs [--config <file>]
//   node scripts/security-scan.mjs --target <path> [--label <name>] [--scanners a,b,c]
//   Options: --out-root <dir> --identity-file <p> --no-redact --quiet

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeRedactor } from './lib/redact.mjs';
import { buildDigest } from './lib/digest.mjs';

export const SUMMARY_SCHEMA_VERSION = 'security-stack.scan-summary.v1';
export const ALL_SCANNERS = ['threat-model', 'static-scan', 'supply-chain', 'runtime-health'];

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

function parseArgs(argv) {
  const args = { redact: true, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    switch (a) {
      case '--config': args.config = argv[++i]; break;
      case '--target': args.target = argv[++i]; break;
      case '--label': args.label = argv[++i]; break;
      case '--scanners': args.scanners = argv[++i].split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--out-root': args.outRoot = argv[++i]; break;
      case '--identity-file': args.identityFile = argv[++i]; break;
      case '--suppressions': args.suppressions = argv[++i]; break;
      case '--no-redact': args.redact = false; break;
      case '--quiet': args.quiet = true; break;
      case '-h': case '--help': args.help = true; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

function usage() {
  return [
    'Usage:',
    '  node scripts/security-scan.mjs [--config <file>]',
    '  node scripts/security-scan.mjs --target <path> [--label <name>] [--scanners a,b,c]',
    '',
    'Options:',
    '  --config <file>       JSON config with targets[] (default security-scan.config.json)',
    '  --target <path>       Ad-hoc single target (overrides config)',
    '  --label <name>        Label for the ad-hoc target',
    `  --scanners <list>     Comma list from: ${ALL_SCANNERS.join(', ')} (default all)`,
    '  --out-root <dir>      Output root (default runs)',
    '  --identity-file <p>   Private identity denylist JSON',
    '  --suppressions <p>    Acknowledge/ignore rules JSON',
    '  --no-redact           DANGER: skip redaction (debug only)',
    '  --quiet               Suppress progress output',
  ].join('\n');
}

function slug(s) {
  return String(s).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'target';
}

export function loadConfig(args) {
  if (args.target) {
    return {
      redact: args.redact,
      outRoot: args.outRoot || 'runs',
      identityFile: args.identityFile,
      suppressions: args.suppressions,
      targets: [{ label: args.label || path.basename(path.resolve(args.target)), path: args.target, scanners: args.scanners || ALL_SCANNERS }],
    };
  }
  const candidates = [
    args.config,
    path.join(repoRoot, 'security-scan.config.json'),
    path.join(repoRoot, 'security-scan.config.example.json'),
  ].filter(Boolean);
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      const cfg = JSON.parse(fs.readFileSync(c, 'utf8'));
      cfg._source = c;
      cfg.outRoot = args.outRoot || cfg.outRoot || 'runs';
      if (typeof args.redact === 'boolean' && args.redact === false) cfg.redact = false;
      if (cfg.redact === undefined) cfg.redact = true;
      if (args.identityFile) cfg.identityFile = args.identityFile;
      if (args.suppressions) cfg.suppressions = args.suppressions;
      if (args.scanners) cfg.targets = (cfg.targets || []).map((t) => ({ ...t, scanners: args.scanners }));
      return cfg;
    }
  }
  throw new Error('no config found and no --target provided');
}

function runNode(scriptRel, scriptArgs) {
  const out = execFileSync(process.execPath, [path.join(repoRoot, scriptRel), ...scriptArgs], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return out;
}

// Run one scanner; returns { tool, ok, findingsFile?, error? }. findingsFile is
// only set for scanners that emit security-stack.findings.v1.
// outBase is an ABSOLUTE output root so absolute and relative --out-root both work.
function runScanner(tool, target, label, outBase) {
  const s = slug(label);
  const abs = path.resolve(target);
  try {
    if (tool === 'threat-model') {
      const dir = path.join(outBase, 'threat-model', s);
      runNode('scripts/security-threat-model.mjs', [abs, '--name', label, '--force',
        '--json-out', path.join(dir, 'threat-model.json'), '--out', path.join(dir, 'THREAT_MODEL.md')]);
      return { tool, ok: true, artifact: path.join(dir, 'threat-model.json') };
    }
    if (tool === 'static-scan') {
      const dir = path.join(outBase, 'static-scan', s);
      const tm = path.join(outBase, 'threat-model', s, 'threat-model.json');
      const scanArgs = [abs, '--name', label, '--force',
        '--out', path.join(dir, 'VULN-FINDINGS.json'), '--md-out', path.join(dir, 'VULN-FINDINGS.md')];
      if (fs.existsSync(tm)) scanArgs.push('--threat-model', tm);
      runNode('scripts/security-static-scan.mjs', scanArgs);
      return { tool, ok: true, findingsFile: path.join(dir, 'VULN-FINDINGS.json') };
    }
    if (tool === 'supply-chain') {
      const dir = path.join(outBase, 'supply-chain', s);
      runNode('scripts/security-supply-chain.mjs', ['--target', abs, '--label', label, '--out-dir', dir, '--quiet']);
      return { tool, ok: true, findingsFile: path.join(dir, 'SUPPLY-CHAIN-FINDINGS.json') };
    }
    if (tool === 'runtime-health') {
      // Host-level check; uses the target label for output namespacing, not the path.
      const dir = path.join(outBase, 'runtime-health', s);
      runNode('scripts/security-runtime-health.mjs', ['--label', label, '--out-dir', dir, '--quiet']);
      return { tool, ok: true, findingsFile: path.join(dir, 'RUNTIME-HEALTH-FINDINGS.json') };
    }
    return { tool, ok: false, error: `unknown scanner: ${tool}` };
  } catch (err) {
    return { tool, ok: false, error: (err.stderr || err.message || String(err)).toString().trim().slice(0, 500) };
  }
}

function runReport(findingsFile, label, outBase, identityFile, redact, suppressions) {
  const reportArgs = ['--findings', findingsFile, '--quiet'];
  if (label) reportArgs.push('--label', label);
  if (identityFile) reportArgs.push('--identity-file', identityFile);
  if (suppressions) reportArgs.push('--suppressions', suppressions);
  if (!redact) reportArgs.push('--no-redact');
  // findingsFile is absolute (produced by runScanner). Read it to namespace output.
  const doc = JSON.parse(fs.readFileSync(findingsFile, 'utf8'));
  const tgt = doc.summary?.target_basename || 'target';
  const tool = doc.tool || doc.summary?.scanner || 'unknown';
  const reportDir = path.join(outBase, 'report', tgt, tool);
  reportArgs.push('--out-dir', reportDir);
  runNode('scripts/security-report.mjs', reportArgs);
  const rep = JSON.parse(fs.readFileSync(path.join(reportDir, 'REPORT.json'), 'utf8'));
  return { reportDir, counts: rep.counts, report: rep };
}

export function buildSummary(perTarget, meta = {}) {
  const totals = { new: 0, persistent: 0, acknowledged: 0, resolved: 0, total_current: 0 };
  const bySeverity = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const t of perTarget) {
    for (const tool of t.tools) {
      if (!tool.counts) continue;
      totals.new += tool.counts.new || 0;
      totals.persistent += tool.counts.persistent || 0;
      totals.acknowledged += tool.counts.acknowledged || 0;
      totals.resolved += tool.counts.resolved || 0;
      totals.total_current += tool.counts.total_current || 0;
      for (const f of [...(tool.report?.findings?.new || []), ...(tool.report?.findings?.persistent || [])]) {
        if (bySeverity[f.severity] !== undefined) bySeverity[f.severity] += 1;
      }
    }
  }
  return {
    schema_version: SUMMARY_SCHEMA_VERSION,
    generated: meta.now || new Date().toISOString(),
    totals,
    by_severity: bySeverity,
    targets: perTarget.map((t) => ({
      label: t.label,
      tools: t.tools.map((tool) => ({ tool: tool.tool, ok: tool.ok, counts: tool.counts || null, error: tool.error || null })),
    })),
  };
}

function renderSummaryMd(summary) {
  const lines = ['# Security Scan Summary', '', `- Generated: ${summary.generated}`,
    `- Totals: new ${summary.totals.new} | persistent ${summary.totals.persistent} | acknowledged ${summary.totals.acknowledged ?? 0} | resolved ${summary.totals.resolved} | current ${summary.totals.total_current}`,
    `- Current by severity: HIGH ${summary.by_severity.HIGH} | MEDIUM ${summary.by_severity.MEDIUM} | LOW ${summary.by_severity.LOW}`,
    '', '> Redacted, local-only. Detection only — no remediation performed.', ''];
  for (const t of summary.targets) {
    lines.push(`## ${t.label}`);
    for (const tool of t.tools) {
      if (!tool.ok) { lines.push(`- ❌ ${tool.tool}: ${tool.error || 'failed'}`); continue; }
      if (tool.counts) lines.push(`- ✅ ${tool.tool}: new ${tool.counts.new} | persistent ${tool.counts.persistent} | acknowledged ${tool.counts.acknowledged ?? 0} | resolved ${tool.counts.resolved}`);
      else lines.push(`- ✅ ${tool.tool}: artifact produced (no findings stream)`);
    }
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(`${usage()}\n`); return; }
  const cfg = loadConfig(args);
  const outRoot = cfg.outRoot || 'runs';
  const outBase = path.resolve(repoRoot, outRoot); // absolute; handles relative + absolute --out-root
  const redact = cfg.redact !== false;
  const log = (m) => { if (!args.quiet) process.stdout.write(`${m}\n`); };

  const perTarget = [];
  for (const target of cfg.targets || []) {
    const scanners = target.scanners || ALL_SCANNERS;
    log(`▶ ${target.label} (${scanners.join(', ')})`);
    const tools = [];
    for (const tool of scanners) {
      const res = runScanner(tool, target.path, target.label, outBase);
      if (!res.ok) { log(`  ❌ ${tool}: ${res.error}`); tools.push(res); continue; }
      if (res.findingsFile) {
        try {
          const rep = runReport(res.findingsFile, target.label, outBase, cfg.identityFile, redact, cfg.suppressions);
          log(`  ✅ ${tool}: new=${rep.counts.new} persistent=${rep.counts.persistent} resolved=${rep.counts.resolved}`);
          tools.push({ ...res, counts: rep.counts, report: rep.report });
        } catch (err) {
          log(`  ⚠ ${tool}: scan ok but report failed: ${err.message}`);
          tools.push({ ...res, error: `report failed: ${err.message}` });
        }
      } else {
        log(`  ✅ ${tool}: artifact produced`);
        tools.push(res);
      }
    }
    perTarget.push({ label: target.label, tools });
  }

  let summary = buildSummary(perTarget);
  if (redact) summary = makeRedactor({ identityFile: cfg.identityFile }).value(summary);
  const summaryDir = path.join(outBase, 'summary');
  fs.mkdirSync(summaryDir, { recursive: true });
  fs.writeFileSync(path.join(summaryDir, 'SUMMARY.json'), `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(summaryDir, 'SUMMARY.md'), renderSummaryMd(summary), 'utf8');

  // Shareable low-noise digest, built from the already-redacted reports/summary.
  const newFindings = [];
  for (const t of perTarget) {
    for (const tool of t.tools) {
      for (const f of tool.report?.findings?.new ?? []) {
        newFindings.push({ severity: f.severity, title: f.title, category: f.category, file: f.file, line: f.line, tool: tool.tool, target: t.label });
      }
    }
  }
  const toolStatuses = [];
  for (const t of summary.targets ?? []) {
    for (const tool of t.tools ?? []) toolStatuses.push({ label: t.label, tool: tool.tool, ok: tool.ok !== false, error: tool.error });
  }
  const digest = buildDigest({
    generated: summary.generated, totals: summary.totals, by_severity: summary.by_severity, toolStatuses, newFindings,
  }, { topN: 10 });
  fs.writeFileSync(path.join(summaryDir, 'DIGEST.txt'), digest, 'utf8');

  log(`\nSummary: new=${summary.totals.new} persistent=${summary.totals.persistent} resolved=${summary.totals.resolved}`);
  log(`  ${path.join(outRoot, 'summary', 'SUMMARY.md')}`);
  log(`  ${path.join(outRoot, 'summary', 'DIGEST.txt')}`);
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try { main(); } catch (err) {
    process.stderr.write(`security-scan error: ${err.message}\n`);
    process.exitCode = 1;
  }
}
