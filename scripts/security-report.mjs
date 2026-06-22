#!/usr/bin/env node
// security-stack report builder
//
// Reads a `security-stack.findings.v1` file (e.g. from security-static-scan),
// diffs it against saved prior state to assign new / persistent / resolved
// status, redacts the result, and writes a local-only Markdown + JSON report.
//
// Safety contract:
// - Read-only with respect to the scanned target. Detection before remediation.
// - Output is local-only under runs/report/<target>/ and redacted by default.
// - Redaction strips home paths, secrets/tokens, phone numbers, chat IDs, and
//   private-only annotation blocks. Personal identity terms come from a private
//   gitignored denylist (see scripts/lib/redact.mjs loadIdentityDenylist).
//
// Usage:
//   node scripts/security-report.mjs --findings <path-to-findings.json> \
//        [--state <state.json>] [--out-dir <dir>] [--label <name>] \
//        [--identity-file <denylist.json>] [--no-redact] [--quiet]

import fs from 'node:fs';
import path from 'node:path';
import { makeRedactor } from './lib/redact.mjs';
import { diffFindings, loadState, writeState } from './lib/finding-state.mjs';
import { loadSuppressions, applySuppressions } from './lib/suppressions.mjs';

const DEFAULT_SUPPRESSIONS = 'security-suppressions.json';

export const REPORT_SCHEMA_VERSION = 'security-stack.report.v1';

function parseArgs(argv) {
  const args = { redact: true, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    switch (a) {
      case '--findings': args.findings = argv[++i]; break;
      case '--state': args.state = argv[++i]; break;
      case '--out-dir': args.outDir = argv[++i]; break;
      case '--label': args.label = argv[++i]; break;
      case '--identity-file': args.identityFile = argv[++i]; break;
      case '--suppressions': args.suppressions = argv[++i]; break;
      case '--no-redact': args.redact = false; break;
      case '--quiet': args.quiet = true; break;
      case '-h': case '--help': args.help = true; break;
      default:
        throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

function usage() {
  return [
    'Usage: node scripts/security-report.mjs --findings <findings.json> [options]',
    '',
    'Options:',
    '  --findings <path>     security-stack.findings.v1 input (required)',
    '  --state <path>        prior/next state file (default: <out-dir>/STATE.json)',
    '  --out-dir <path>      report output dir (default: runs/report/<target>)',
    '  --label <name>        human label for the report',
    '  --identity-file <p>   private identity denylist JSON (terms/patterns)',
    '  --suppressions <p>    acknowledge/ignore rules JSON (default security-suppressions.json)',
    '  --no-redact           DANGER: skip redaction (debug only, never share)',
    '  --quiet               suppress stdout summary',
  ].join('\n');
}

/**
 * Build a structured (un-redacted) report object from a findings file payload
 * and a diff result. Exposed for tests.
 */
// view = { findings: active[], resolved: [], acknowledged: [] }
export function buildReport(findingsDoc, view, meta = {}) {
  const summary = findingsDoc.summary ?? {};
  const byStatus = { new: [], persistent: [], acknowledged: [], resolved: [] };
  for (const f of view.findings ?? []) {
    if (f.status === 'new') byStatus.new.push(f);
    else byStatus.persistent.push(f);
  }
  byStatus.acknowledged = view.acknowledged ?? [];
  byStatus.resolved = view.resolved ?? [];
  const counts = {
    new: byStatus.new.length,
    persistent: byStatus.persistent.length,
    acknowledged: byStatus.acknowledged.length,
    resolved: byStatus.resolved.length,
    total_current: byStatus.new.length + byStatus.persistent.length + byStatus.acknowledged.length,
  };
  return {
    schema_version: REPORT_SCHEMA_VERSION,
    generated: meta.now ?? new Date().toISOString(),
    source_tool: findingsDoc.tool ?? summary.scanner ?? 'unknown',
    source_schema: findingsDoc.schema_version ?? null,
    target_label: meta.label ?? summary.target_label ?? summary.name ?? 'unknown',
    target_basename: summary.target_basename ?? null,
    target_commit: summary.target_commit ?? null,
    counts,
    findings: byStatus,
  };
}

function sevRank(s) {
  return { HIGH: 0, MEDIUM: 1, LOW: 2 }[String(s).toUpperCase()] ?? 3;
}

function renderMarkdown(report) {
  const lines = [];
  lines.push(`# Security Report — ${report.target_label}`);
  lines.push('');
  lines.push(`- Generated: ${report.generated}`);
  lines.push(`- Source tool: ${report.source_tool}`);
  if (report.target_commit) lines.push(`- Target commit: ${report.target_commit}`);
  lines.push('');
  const c = report.counts;
  lines.push(`**New:** ${c.new}  |  **Persistent:** ${c.persistent}  |  **Acknowledged:** ${c.acknowledged ?? 0}  |  **Resolved:** ${c.resolved}  |  **Current total:** ${c.total_current}`);
  lines.push('');
  lines.push('> Redacted, local-only report. Detection only — no remediation performed.');
  lines.push('');

  const section = (title, items, opts = {}) => {
    lines.push(`## ${title} (${items.length})`);
    if (items.length === 0) {
      lines.push('');
      lines.push('_None._');
      lines.push('');
      return;
    }
    const sorted = [...items].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
    for (const f of sorted) {
      const sev = f.severity ?? 'n/a';
      const loc = f.file ? ` — \`${f.file}\`${f.line ? `:${f.line}` : ''}` : '';
      lines.push(`- **[${sev}]** ${f.title ?? f.category ?? f.fingerprint}${loc}`);
      const bits = [];
      if (f.lane) bits.push(`lane: ${f.lane}`);
      if (f.category) bits.push(`category: ${f.category}`);
      if (typeof f.confidence === 'number') bits.push(`confidence: ${f.confidence}`);
      if (opts.showResolvedAt && f.resolved_at) bits.push(`resolved: ${f.resolved_at}`);
      else if (f.first_seen) bits.push(`first seen: ${f.first_seen}`);
      if (opts.showAck && f.suppression) {
        bits.push(`acknowledged${f.suppression.reason ? `: ${f.suppression.reason}` : ''}`);
        if (f.suppression.expires) bits.push(`expires: ${f.suppression.expires}`);
      }
      if (bits.length) lines.push(`  - ${bits.join(' · ')}`);
    }
    lines.push('');
  };

  section('New findings', report.findings.new);
  section('Persistent findings', report.findings.persistent);
  section('Acknowledged findings', report.findings.acknowledged ?? [], { showAck: true });
  section('Resolved findings', report.findings.resolved, { showResolvedAt: true });
  return `${lines.join('\n')}\n`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (!args.findings) {
    process.stderr.write(`error: --findings is required\n\n${usage()}\n`);
    process.exitCode = 2;
    return;
  }

  const findingsRaw = fs.readFileSync(args.findings, 'utf8');
  const findingsDoc = JSON.parse(findingsRaw);
  const findings = Array.isArray(findingsDoc.findings) ? findingsDoc.findings : [];

  const target = findingsDoc.summary?.target_basename
    || path.basename(path.dirname(args.findings))
    || 'target';
  // Namespace report output/state per source tool so findings from different
  // scanners (e.g. static-scan vs supply-chain) do not cross-resolve each other.
  const sourceTool = findingsDoc.tool || findingsDoc.summary?.scanner || 'unknown';
  const outDir = args.outDir || path.join('runs', 'report', target, sourceTool);
  const statePath = args.state || path.join(outDir, 'STATE.json');

  const now = new Date().toISOString();
  const priorState = loadState(statePath);
  const diff = diffFindings(findings, priorState, { now });

  // Acknowledge/ignore is a view-layer filter; scan state above is left intact
  // so resolved-detection still works and removing a suppression resurfaces it.
  const suppPath = args.suppressions || (fs.existsSync(DEFAULT_SUPPRESSIONS) ? DEFAULT_SUPPRESSIONS : null);
  const supp = loadSuppressions(suppPath);
  const { active, acknowledged } = applySuppressions(diff.findings, supp.suppressions, now);

  let report = buildReport(findingsDoc, { findings: active, acknowledged, resolved: diff.resolved }, { label: args.label, now });
  if (args.redact) {
    const redactor = makeRedactor({ identityFile: args.identityFile });
    report = redactor.value(report);
  }

  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'REPORT.json');
  const mdPath = path.join(outDir, 'REPORT.md');
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  fs.writeFileSync(mdPath, renderMarkdown(report), 'utf8');
  writeState(statePath, diff.nextState);

  if (!args.quiet) {
    const c = report.counts;
    process.stdout.write(
      `security-report: ${report.target_label}\n`
        + `  new=${c.new} persistent=${c.persistent} acknowledged=${c.acknowledged} resolved=${c.resolved} current=${c.total_current}\n`
        + `  report: ${mdPath}\n  json:   ${jsonPath}\n  state:  ${statePath}\n`
        + `  redacted: ${args.redact}${supp.source ? ` suppressions: ${supp.source}` : ''}\n`,
    );
  }
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try {
    main();
  } catch (err) {
    process.stderr.write(`security-report error: ${err.message}\n`);
    process.exitCode = 1;
  }
}
