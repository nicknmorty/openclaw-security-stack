#!/usr/bin/env node
// security-stack digest CLI
//
// Builds a short, shareable, redaction-safe digest from a completed scan run
// (the redacted SUMMARY + per-tool REPORTs under a runs root). Read-only.
//
// Usage:
//   node scripts/security-digest.mjs [--runs runs] [--top 10]
//        [--severities HIGH,MEDIUM] [--out runs/summary/DIGEST.txt] [--quiet]

import fs from 'node:fs';
import path from 'node:path';
import { buildDigest, collectNewFindings } from './lib/digest.mjs';

function parseArgs(argv) {
  const args = { runs: 'runs', top: 10, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    switch (a) {
      case '--runs': args.runs = argv[++i]; break;
      case '--top': args.top = Number(argv[++i]); break;
      case '--severities': args.severities = argv[++i].split(',').map((s) => s.trim()).filter(Boolean); break;
      case '--out': args.out = argv[++i]; break;
      case '--quiet': args.quiet = true; break;
      case '-h': case '--help': args.help = true; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

function usage() {
  return [
    'Usage: node scripts/security-digest.mjs [options]',
    '  --runs <dir>         runs root (default runs)',
    '  --top <n>            max new findings to list (default 10)',
    '  --severities <list>  limit listed findings to these severities',
    '  --out <path>         also write the digest to a file',
    '  --quiet              do not print to stdout',
  ].join('\n');
}

function readJsonSafe(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

// Find runs/report/<target>/<tool>/REPORT.json (bounded depth).
function findReports(reportRoot) {
  const out = [];
  let targets;
  try { targets = fs.readdirSync(reportRoot, { withFileTypes: true }); } catch { return out; }
  for (const t of targets) {
    if (!t.isDirectory()) continue;
    const tdir = path.join(reportRoot, t.name);
    let tools;
    try { tools = fs.readdirSync(tdir, { withFileTypes: true }); } catch { continue; }
    for (const tool of tools) {
      if (!tool.isDirectory()) continue;
      const rp = path.join(tdir, tool.name, 'REPORT.json');
      const rep = readJsonSafe(rp);
      if (rep) out.push(rep);
    }
  }
  return out;
}

function toolStatusesFromSummary(summary) {
  const out = [];
  for (const t of summary?.targets ?? []) {
    for (const tool of t.tools ?? []) out.push({ label: t.label, tool: tool.tool, ok: tool.ok !== false, error: tool.error ?? null });
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(`${usage()}\n`); return; }
  const runs = args.runs;
  const summary = readJsonSafe(path.join(runs, 'summary', 'SUMMARY.json'));
  const reports = findReports(path.join(runs, 'report'));
  const newFindings = collectNewFindings(reports, { severities: args.severities });

  const text = buildDigest({
    generated: summary?.generated ?? new Date().toISOString(),
    totals: summary?.totals,
    by_severity: summary?.by_severity,
    toolStatuses: toolStatusesFromSummary(summary),
    newFindings,
  }, { topN: args.top });

  if (args.out) {
    fs.mkdirSync(path.dirname(args.out), { recursive: true });
    fs.writeFileSync(args.out, text, 'utf8');
  }
  if (!args.quiet) process.stdout.write(text);
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try { main(); } catch (err) {
    process.stderr.write(`security-digest error: ${err.message}\n`);
    process.exitCode = 1;
  }
}
