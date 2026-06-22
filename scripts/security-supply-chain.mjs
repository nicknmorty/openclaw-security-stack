#!/usr/bin/env node
// security-stack supply-chain inventory scanner (V0)
//
// Read-only inventory of package manifests and lockfiles plus a small set of
// deterministic posture rules. Emits a `security-stack.findings.v1` document so
// output flows straight through scripts/security-report.mjs.
//
// Safety contract:
// - Read-only. Detection before remediation. No installs, no network, no
//   dependency resolution, no exploitability claims.
// - V0 findings are deterministic posture observations (unpinned deps,
//   non-registry dependency sources), NOT CVE/advisory matches. Advisory intel
//   is a separate, later backlog item.
// - Host-resource guard caps the number of entries walked so scans stay light
//   on constrained hosts.
//
// Usage:
//   node scripts/security-supply-chain.mjs --target <root> [--out-dir <dir>]
//        [--label <name>] [--max-entries <n>] [--quiet]

import fs from 'node:fs';
import path from 'node:path';

export const FINDINGS_SCHEMA_VERSION = 'security-stack.findings.v1';

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'runs', 'dist', 'build', 'coverage', 'vendor',
  '.venv', 'venv', '__pycache__', '.cache', '.next', '.turbo', 'out',
]);

const NPM_MANIFEST = 'package.json';
const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];
const PY_REQ = /^requirements.*\.txt$/;
const PY_MANIFESTS = ['pyproject.toml', 'Pipfile', 'setup.py', 'setup.cfg'];
const PY_LOCKS = ['poetry.lock', 'Pipfile.lock'];

function parseArgs(argv) {
  const args = { maxEntries: 20000, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    switch (a) {
      case '--target': args.target = argv[++i]; break;
      case '--out-dir': args.outDir = argv[++i]; break;
      case '--label': args.label = argv[++i]; break;
      case '--max-entries': args.maxEntries = Number(argv[++i]); break;
      case '--quiet': args.quiet = true; break;
      case '-h': case '--help': args.help = true; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

function usage() {
  return [
    'Usage: node scripts/security-supply-chain.mjs --target <root> [options]',
    '',
    '  --target <root>     directory to inventory (default: cwd)',
    '  --out-dir <path>    output dir (default: runs/supply-chain/<target>)',
    '  --label <name>      human label',
    '  --max-entries <n>   host-resource guard (default 20000)',
    '  --quiet             suppress stdout summary',
  ].join('\n');
}

/** Bounded recursive walk that collects relevant manifest/lock files only. */
export function walkManifests(root, maxEntries = 20000) {
  const found = [];
  let visited = 0;
  let truncated = false;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      visited += 1;
      if (visited > maxEntries) { truncated = true; break; }
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name) || ent.name.startsWith('.git')) continue;
        stack.push(full);
      } else if (ent.isFile()) {
        const name = ent.name;
        if (
          name === NPM_MANIFEST || NPM_LOCKS.includes(name)
          || PY_REQ.test(name) || PY_MANIFESTS.includes(name) || PY_LOCKS.includes(name)
        ) {
          found.push(full);
        }
      }
    }
    if (truncated) break;
  }
  return { files: found, visited, truncated };
}

function readJsonSafe(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

// npm dependency value that is not a plain registry semver range.
function isNonRegistryNpmSource(value) {
  if (typeof value !== 'string') return false;
  return /^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:)/i.test(value)
    || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(value); // owner/repo shorthand
}

/**
 * Build inventory + deterministic findings from a list of manifest/lock files.
 * Exposed for tests. Returns { inventory, findings }.
 */
export function analyze(files, root) {
  const rel = (f) => path.relative(root, f) || path.basename(f);
  const byDir = new Map();
  for (const f of files) {
    const d = path.dirname(f);
    if (!byDir.has(d)) byDir.set(d, []);
    byDir.get(d).push(path.basename(f));
  }

  const inventory = { npm: [], python: [] };
  const findings = [];
  let counter = 0;
  const addFinding = (fields) => {
    counter += 1;
    findings.push({
      id: `SC-${String(counter).padStart(3, '0')}`,
      lane: 'supply-chain',
      status: 'new',
      verdict: 'observation',
      confidence: 0.9,
      redaction_level: 'shareable-redacted',
      ...fields,
    });
  };

  for (const [dir, names] of byDir) {
    // --- npm ---
    if (names.includes(NPM_MANIFEST)) {
      const manifestPath = path.join(dir, NPM_MANIFEST);
      const pkg = readJsonSafe(manifestPath) || {};
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.optionalDependencies || {}) };
      const depCount = Object.keys(deps).length;
      const lock = NPM_LOCKS.find((l) => names.includes(l)) || null;
      inventory.npm.push({ dir: rel(dir), manifest: rel(manifestPath), lockfile: lock, dependency_count: depCount });

      if (depCount > 0 && !lock) {
        addFinding({
          category: 'unpinned-dependencies',
          title: 'npm manifest declares dependencies but has no lockfile',
          severity: 'LOW',
          file: rel(manifestPath),
          surface: 'Supply chain (npm)',
          detail: `${depCount} declared dependencies without a committed lockfile (versions not pinned).`,
        });
      }
      for (const [depName, depVal] of Object.entries(deps)) {
        if (isNonRegistryNpmSource(depVal)) {
          addFinding({
            category: 'non-registry-dependency-source',
            title: 'npm dependency resolves from a non-registry source',
            severity: 'MEDIUM',
            file: rel(manifestPath),
            surface: 'Supply chain (npm)',
            detail: `Dependency "${depName}" points at a non-registry source.`,
          });
        }
      }
    }

    // --- python ---
    const pyManifests = names.filter((n) => PY_MANIFESTS.includes(n) || PY_REQ.test(n));
    if (pyManifests.length) {
      const lock = PY_LOCKS.find((l) => names.includes(l)) || null;
      inventory.python.push({ dir: rel(dir), manifests: pyManifests, lockfile: lock });
      for (const reqName of names.filter((n) => PY_REQ.test(n))) {
        const reqPath = path.join(dir, reqName);
        let lines = [];
        try { lines = fs.readFileSync(reqPath, 'utf8').split(/\r?\n/); } catch { lines = []; }
        let unpinned = 0;
        let firstLine = null;
        lines.forEach((line, idx) => {
          const t = line.trim();
          if (!t || t.startsWith('#') || t.startsWith('-')) return;
          // pinned if it has == ; treat ranges/no-version as unpinned
          if (!/==/.test(t)) {
            unpinned += 1;
            if (firstLine === null) firstLine = idx + 1;
          }
        });
        if (unpinned > 0) {
          addFinding({
            category: 'unpinned-python-requirement',
            title: 'Python requirements file has unpinned dependencies',
            severity: 'LOW',
            file: rel(reqPath),
            line: firstLine,
            surface: 'Supply chain (python)',
            detail: `${unpinned} requirement(s) without an exact == pin.`,
          });
        }
      }
    }
  }

  findings.sort((a, b) => ({ HIGH: 0, MEDIUM: 1, LOW: 2 }[a.severity] - { HIGH: 0, MEDIUM: 1, LOW: 2 }[b.severity]));
  return { inventory, findings };
}

function summarize(findings) {
  const by_severity = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const by_lane = {};
  for (const f of findings) {
    if (by_severity[f.severity] !== undefined) by_severity[f.severity] += 1;
    by_lane[f.lane] = (by_lane[f.lane] || 0) + 1;
  }
  return { by_severity, by_lane };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { process.stdout.write(`${usage()}\n`); return; }
  const root = path.resolve(args.target || process.cwd());
  if (!fs.existsSync(root)) throw new Error(`target does not exist: ${root}`);

  const { files, visited, truncated } = walkManifests(root, args.maxEntries);
  const { inventory, findings } = analyze(files, root);
  const { by_severity, by_lane } = summarize(findings);

  const target = path.basename(root);
  const doc = {
    schema_version: FINDINGS_SCHEMA_VERSION,
    tool: 'security-supply-chain',
    summary: {
      scanner: 'security-supply-chain',
      mode: 'inventory-readonly',
      name: args.label || target,
      target_label: args.label || target,
      target_basename: target,
      date: new Date().toISOString(),
      entries_visited: visited,
      truncated,
      npm_projects: inventory.npm.length,
      python_projects: inventory.python.length,
      finding_count: findings.length,
      by_severity,
      by_lane,
    },
    inventory,
    findings,
  };

  const outDir = args.outDir || path.join('runs', 'supply-chain', target);
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'SUPPLY-CHAIN-FINDINGS.json');
  fs.writeFileSync(jsonPath, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');

  if (!args.quiet) {
    process.stdout.write(
      `security-supply-chain: ${doc.summary.target_label}\n`
        + `  npm=${inventory.npm.length} python=${inventory.python.length} findings=${findings.length}`
        + ` (H=${by_severity.HIGH} M=${by_severity.MEDIUM} L=${by_severity.LOW})\n`
        + `  visited=${visited}${truncated ? ' (TRUNCATED by --max-entries)' : ''}\n`
        + `  output: ${jsonPath}\n`,
    );
  }
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  try { main(); } catch (err) {
    process.stderr.write(`security-supply-chain error: ${err.message}\n`);
    process.exitCode = 1;
  }
}
