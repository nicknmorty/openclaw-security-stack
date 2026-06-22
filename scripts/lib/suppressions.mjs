// security-stack suppression (acknowledge/ignore) engine
//
// Lets an operator acknowledge accepted findings so reports surface true signal
// instead of known/expected noise. This is a VIEW-LAYER filter only:
// - It never mutates scan state, so resolved-detection still works and removing
//   a suppression immediately resurfaces the finding.
// - Suppressions match by exact fingerprint OR by a match-rule (any subset of
//   lane/category/file/severity/title; all specified fields must match).
// - Optional `expires` (ISO date) auto-deactivates a suppression after a date.
//
// Dependency-free.

import fs from 'node:fs';

export const SUPPRESSIONS_SCHEMA_VERSION = 'security-stack.suppressions.v1';
const MATCH_KEYS = ['lane', 'category', 'file', 'severity', 'title'];

export function loadSuppressions(filePath) {
  if (!filePath) return { suppressions: [], source: null };
  let raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); } catch { return { suppressions: [], source: null }; }
  let parsed;
  try { parsed = JSON.parse(raw); } catch (err) {
    throw new Error(`suppressions file is not valid JSON (${filePath}): ${err.message}`);
  }
  const suppressions = Array.isArray(parsed.suppressions) ? parsed.suppressions : [];
  return { suppressions, source: filePath };
}

export function isExpired(suppression, now) {
  if (!suppression || !suppression.expires) return false;
  const exp = new Date(suppression.expires).getTime();
  if (Number.isNaN(exp)) return false; // malformed date -> treat as non-expiring
  return exp < new Date(now).getTime();
}

/** Return the first active suppression matching this finding, or null. */
export function matchSuppression(finding, suppressions, now) {
  for (const s of suppressions || []) {
    if (isExpired(s, now)) continue;
    if (s.fingerprint) {
      if (s.fingerprint === finding.fingerprint) return s;
      continue;
    }
    if (s.match && typeof s.match === 'object') {
      const keys = MATCH_KEYS.filter((k) => s.match[k] !== undefined);
      if (keys.length === 0) continue;
      const ok = keys.every((k) => String(s.match[k]).toLowerCase() === String(finding[k] ?? '').toLowerCase());
      if (ok) return s;
    }
  }
  return null;
}

/**
 * Split findings into { active, acknowledged }. Acknowledged findings keep a
 * `suppression` annotation and status `acknowledged`. Source findings are not
 * mutated.
 */
export function applySuppressions(findings, suppressions, now) {
  const active = [];
  const acknowledged = [];
  for (const f of findings || []) {
    const s = matchSuppression(f, suppressions, now);
    if (s) {
      acknowledged.push({
        ...f,
        status: 'acknowledged',
        suppression: {
          id: s.id ?? null,
          reason: s.reason ?? null,
          by: s.by ?? null,
          expires: s.expires ?? null,
          matched_by: s.fingerprint ? 'fingerprint' : 'rule',
        },
      });
    } else {
      active.push(f);
    }
  }
  return { active, acknowledged };
}
