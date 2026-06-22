// security-stack shareable digest renderer
//
// Produces a short, low-noise, redaction-safe summary of a scan run, suitable
// for a chat message or CLI glance. It intentionally focuses on ACTIVE signal
// (new findings) and leaves acknowledged/persistent noise out of the headline.
//
// Input is expected to already be redacted (it is built from redacted reports
// and the redacted SUMMARY). This module does not itself redact.
//
// Dependency-free.

export const DIGEST_SCHEMA_VERSION = 'security-stack.digest.v1';
const SEV_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 };
const SEV_ICON = { HIGH: '\u{1F534}', MEDIUM: '\u{1F7E0}', LOW: '\u{1F7E1}' };

function truncate(s, n) {
  const t = String(s ?? '');
  return t.length > n ? `${t.slice(0, n - 1)}\u2026` : t;
}

/**
 * @param {object} data
 *   - generated: ISO string
 *   - totals: { new, persistent, acknowledged, resolved, total_current }
 *   - by_severity: { HIGH, MEDIUM, LOW } (active)
 *   - toolStatuses: [{ label, tool, ok, error }]
 *   - newFindings: [{ severity, title, category, file, line, tool, target }]
 * @param {object} opts - { topN=10, title }
 * @returns {string} plain-text digest
 */
export function buildDigest(data, opts = {}) {
  const topN = opts.topN ?? 10;
  const totals = data.totals ?? {};
  const sev = data.by_severity ?? { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const lines = [];
  lines.push(`\u{1F6E1}\uFE0F ${opts.title ?? 'Security digest'}`);
  if (data.generated) lines.push(data.generated);
  lines.push(
    `Active: new ${totals.new ?? 0} \u00b7 persistent ${totals.persistent ?? 0}`
      + ` \u00b7 acknowledged ${totals.acknowledged ?? 0} \u00b7 resolved ${totals.resolved ?? 0}`,
  );
  lines.push(`Severity (active): HIGH ${sev.HIGH ?? 0} \u00b7 MEDIUM ${sev.MEDIUM ?? 0} \u00b7 LOW ${sev.LOW ?? 0}`);
  lines.push('');

  const newFindings = [...(data.newFindings ?? [])].sort(
    (a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9),
  );
  if (newFindings.length === 0) {
    lines.push('\u2705 No new findings.');
  } else {
    const shown = newFindings.slice(0, topN);
    lines.push(`New findings (showing ${shown.length} of ${newFindings.length}):`);
    for (const f of shown) {
      const icon = SEV_ICON[f.severity] ?? '\u2022';
      const loc = f.file ? ` \u2014 ${f.file}${f.line ? `:${f.line}` : ''}` : '';
      const ctx = [f.tool, f.target].filter(Boolean).join(' \u00b7 ');
      lines.push(`${icon} [${f.severity}] ${truncate(f.title ?? f.category ?? 'finding', 80)}${loc}${ctx ? ` (${ctx})` : ''}`);
    }
    if (newFindings.length > shown.length) lines.push(`\u2026 +${newFindings.length - shown.length} more new`);
  }
  lines.push('');

  const statuses = data.toolStatuses ?? [];
  const failed = statuses.filter((t) => t.ok === false);
  if (failed.length === 0 && statuses.length) {
    lines.push(`Tools: \u2705 ${statuses.length} ran ok`);
  } else if (failed.length) {
    lines.push(`Tools: \u26a0\uFE0F ${failed.length} failed \u2014 ${failed.map((t) => `${t.tool}${t.label ? `@${t.label}` : ''}`).join(', ')}`);
  }
  return `${lines.join('\n')}\n`;
}

/** Collect new findings from an array of redacted report objects. */
export function collectNewFindings(reports, opts = {}) {
  const severities = opts.severities ? new Set(opts.severities) : null;
  const out = [];
  for (const rep of reports) {
    const tool = rep.source_tool;
    const target = rep.target_label;
    for (const f of rep.findings?.new ?? []) {
      if (severities && !severities.has(f.severity)) continue;
      out.push({ severity: f.severity, title: f.title, category: f.category, file: f.file, line: f.line, tool, target });
    }
  }
  return out;
}
