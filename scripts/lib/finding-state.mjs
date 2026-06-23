// security-stack finding state + diff engine
//
// Dependency-free. Assigns durable new / persistent / resolved status to
// findings by comparing the current scan against a saved prior-state file.
//
// Status semantics (V0 acceptance criteria):
// - new        : fingerprint not present in prior state
// - persistent : fingerprint present in prior state and in current scan
// - resolved   : fingerprint present in prior state but absent from current scan
//
// Detection before remediation: this module only computes and records state.
// It performs no fixes and mutates no source files.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const STATE_SCHEMA_VERSION = 'security-stack.finding-state.v1';

function norm(v) {
  return String(v ?? '').trim().toLowerCase();
}

/**
 * Stable fingerprint for a finding. Intentionally excludes volatile fields
 * (array index ids like F-001, line numbers, timestamps, confidence) so the
 * same underlying issue keeps one identity across runs even as the file drifts.
 * Scanners may provide `fingerprint_key` for stable, scanner-owned identity
 * details that are semantically part of the issue, such as a socket's
 * protocol/address/port.
 */
export function fingerprintFinding(finding = {}) {
  const parts = [
    norm(finding.lane),
    norm(finding.category ?? finding.rule),
    norm(finding.file ?? finding.path),
    norm(finding.title ?? finding.message),
    norm(finding.fingerprint_key),
  ];
  const hash = crypto.createHash('sha256').update(parts.join('\u0000')).digest('hex');
  return `f-${hash.slice(0, 16)}`;
}

/**
 * Load prior state. Missing or unreadable file yields an empty baseline so a
 * first run treats everything as new without error.
 */
export function loadState(statePath) {
  if (!statePath) return emptyState();
  let raw;
  try {
    raw = fs.readFileSync(statePath, 'utf8');
  } catch {
    return emptyState();
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`prior state is not valid JSON (${statePath}): ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || !parsed.findings) return emptyState();
  return parsed;
}

function emptyState() {
  return { schema_version: STATE_SCHEMA_VERSION, updated: null, findings: {} };
}

/**
 * Diff current findings against prior state.
 * @returns {{
 *   findings: object[],   // current findings, annotated with fingerprint+status+first_seen
 *   resolved: object[],   // prior findings no longer present
 *   counts: {new:number,persistent:number,resolved:number,total_current:number},
 *   nextState: object,    // state to persist for the next run
 * }}
 */
export function diffFindings(currentFindings = [], priorState = emptyState(), opts = {}) {
  const now = opts.now ?? new Date().toISOString();
  const prior = priorState && priorState.findings ? priorState.findings : {};
  const annotated = [];
  const nextFindings = {};
  const seen = new Set();
  let newCount = 0;
  let persistentCount = 0;

  for (const finding of currentFindings) {
    const fp = finding.fingerprint || fingerprintFinding(finding);
    const priorEntry = prior[fp];
    const status = priorEntry ? 'persistent' : 'new';
    if (status === 'new') newCount += 1;
    else persistentCount += 1;
    const firstSeen = priorEntry?.first_seen ?? now;
    annotated.push({ ...finding, fingerprint: fp, status, first_seen: firstSeen, last_seen: now });
    nextFindings[fp] = {
      fingerprint: fp,
      lane: finding.lane ?? null,
      category: finding.category ?? finding.rule ?? null,
      title: finding.title ?? finding.message ?? null,
      file: finding.file ?? finding.path ?? null,
      fingerprint_key: finding.fingerprint_key ?? null,
      severity: finding.severity ?? null,
      status: 'persistent', // anything carried forward is persistent next run
      first_seen: firstSeen,
      last_seen: now,
    };
    seen.add(fp);
  }

  const resolved = [];
  for (const [fp, entry] of Object.entries(prior)) {
    if (seen.has(fp)) continue;
    if (entry.status === 'resolved') continue; // already resolved previously; drop from active state
    resolved.push({ ...entry, status: 'resolved', resolved_at: now });
  }

  const nextState = {
    schema_version: STATE_SCHEMA_VERSION,
    updated: now,
    findings: nextFindings,
  };

  return {
    findings: annotated,
    resolved,
    counts: {
      new: newCount,
      persistent: persistentCount,
      resolved: resolved.length,
      total_current: annotated.length,
    },
    nextState,
  };
}

/** Persist next-run state, creating parent directories as needed. */
export function writeState(statePath, state) {
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  fs.writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
}
