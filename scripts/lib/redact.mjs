// security-stack redaction helper
//
// Reusable, dependency-free redaction for security-stack reports and any
// captured text/JSON before it leaves the local host.
//
// Design contract:
// - This module embeds NO personal identity literals (names, phone numbers,
//   usernames, chat IDs). It must stay safe to publish verbatim.
// - Built-in patterns are generic (home paths, secrets/tokens, phone numbers,
//   chat IDs).
// - Site-specific identity terms (real names, usernames, exact IDs/numbers)
//   are supplied at call time via `extraTerms` or loaded from a private,
//   gitignored denylist file (see loadIdentityDenylist).
// - Detection before remediation: redaction never mutates source files; it
//   returns redacted copies.

import fs from 'node:fs';

export const REDACTED = '[REDACTED]';
export const REDACTED_PATH = '~';
export const REDACTED_PHONE = '[REDACTED_PHONE]';
export const REDACTED_CHAT_ID = '[REDACTED_CHAT_ID]';
export const REDACTED_SECRET = '[REDACTED_SECRET]';

// Keys whose entire subtree is dropped from structured reports because they are
// intentional private-only annotations.
export const DEFAULT_DROP_KEYS = ['local_private', 'local_target_path', 'local_threat_model_path'];

// Object keys whose scalar values are always treated as secrets.
const SECRET_KEY_RE =
  /^(?:.*[_-])?(?:access_token|refresh_token|id_token|client_secret|client_id|api[_-]?key|apikey|secret|password|passwd|passphrase|token|authorization|bearer|private[_-]?key|session[_-]?token|cookie)$/i;

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --- string-level redaction ---------------------------------------------

function redactHomePaths(str) {
  // /home/<user>/... and /Users/<user>/... -> ~/...
  // Hides the username segment while keeping path structure for triage.
  return str.replace(/\/(?:home|Users)\/[^\/\s"':,;)\]}]+/g, REDACTED_PATH);
}

function redactSecretsInString(str) {
  let out = str;
  // Authorization: Bearer <token>
  out = out.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi, `$1${REDACTED_SECRET}`);
  // key: "value" / key=value for sensitive key names (JSON-ish or env-ish)
  out = out.replace(
    /("?(?:access_token|refresh_token|id_token|client_secret|api[_-]?key|apikey|secret|password|passwd|passphrase|token|authorization|private[_-]?key|session[_-]?token)"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,}\]]+)/gi,
    `$1"${REDACTED_SECRET}"`,
  );
  // Common credential token prefixes appearing bare
  out = out.replace(
    /\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g,
    REDACTED_SECRET,
  );
  return out;
}

function redactChatIds(str) {
  let out = str;
  // telegram:<id> / signal:<id> style routing identifiers
  out = out.replace(/\b(telegram|signal|discord|slack|whatsapp):-?\d{4,}/gi, `$1:${REDACTED_CHAT_ID}`);
  // Telegram supergroup/channel ids (-100xxxxxxxxxx)
  out = out.replace(/-100\d{7,}/g, REDACTED_CHAT_ID);
  return out;
}

function redactPhones(str) {
  let out = str;
  // +<country><number> E.164-ish
  out = out.replace(/\+\d{10,15}\b/g, REDACTED_PHONE);
  // US style: (425) 681-3513 / 425-681-3513 / 425.681.3513 / +1 425 681 3513
  out = out.replace(/(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)/g, REDACTED_PHONE);
  return out;
}

/**
 * Redact a single string with built-in generic rules plus any explicit terms.
 * Order matters: explicit identity terms first, then secrets, ids, phones,
 * and home paths last so path rewriting does not interfere with id matching.
 */
export function redactString(str, opts = {}) {
  if (typeof str !== 'string' || str.length === 0) return str;
  const { extraTerms = [], extraPatterns = [] } = opts;
  let out = str;
  for (const term of extraTerms) {
    if (!term) continue;
    out = out.replace(new RegExp(escapeRegExp(String(term)), 'g'), REDACTED);
  }
  for (const pat of extraPatterns) {
    if (pat instanceof RegExp) out = out.replace(pat, REDACTED);
  }
  out = redactSecretsInString(out);
  out = redactChatIds(out);
  out = redactPhones(out);
  out = redactHomePaths(out);
  return out;
}

// --- structured (deep) redaction ----------------------------------------

/**
 * Deep-redact any JSON-compatible value. Objects and arrays are copied;
 * source data is never mutated. Keys in dropKeys are removed entirely.
 * Scalar values under secret-like keys are fully replaced.
 */
export function redactValue(value, opts = {}) {
  const dropKeys = new Set(opts.dropKeys ?? DEFAULT_DROP_KEYS);
  const seen = new WeakSet();

  const walk = (val, keyHint) => {
    if (val === null || val === undefined) return val;
    if (typeof val === 'string') {
      if (keyHint && SECRET_KEY_RE.test(keyHint)) return REDACTED_SECRET;
      return redactString(val, opts);
    }
    if (typeof val === 'number' || typeof val === 'boolean') {
      if (keyHint && SECRET_KEY_RE.test(keyHint)) return REDACTED_SECRET;
      return val;
    }
    if (Array.isArray(val)) {
      if (seen.has(val)) return '[Circular]';
      seen.add(val);
      return val.map((v) => walk(v, keyHint));
    }
    if (typeof val === 'object') {
      if (seen.has(val)) return '[Circular]';
      seen.add(val);
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (dropKeys.has(k)) continue;
        if (SECRET_KEY_RE.test(k)) {
          out[k] = REDACTED_SECRET;
          continue;
        }
        out[k] = walk(v, k);
      }
      return out;
    }
    return val;
  };

  return walk(value, undefined);
}

/**
 * Load a private identity denylist (terms + patterns) from a gitignored file.
 * Returns { extraTerms, extraPatterns } suitable for spreading into opts.
 * Missing file is not an error (returns empty lists) so the generic redactor
 * still works on hosts without a configured denylist.
 *
 * File format (JSON): { "terms": ["..."], "patterns": ["regex", ...] }
 */
export function loadIdentityDenylist(filePath) {
  const path =
    filePath || process.env.SECURITY_STACK_IDENTITY_FILE || null;
  if (!path) return { extraTerms: [], extraPatterns: [] };
  let raw;
  try {
    raw = fs.readFileSync(path, 'utf8');
  } catch {
    return { extraTerms: [], extraPatterns: [] };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`identity denylist is not valid JSON (${path}): ${err.message}`);
  }
  const extraTerms = Array.isArray(parsed.terms) ? parsed.terms.filter(Boolean).map(String) : [];
  const extraPatterns = Array.isArray(parsed.patterns)
    ? parsed.patterns.filter(Boolean).map((p) => new RegExp(String(p), 'g'))
    : [];
  return { extraTerms, extraPatterns };
}

/**
 * Convenience factory bundling options (including an optional identity file)
 * into ready-to-use redact functions.
 */
export function makeRedactor(opts = {}) {
  const denylist = loadIdentityDenylist(opts.identityFile);
  const merged = {
    ...opts,
    extraTerms: [...(opts.extraTerms ?? []), ...denylist.extraTerms],
    extraPatterns: [...(opts.extraPatterns ?? []), ...denylist.extraPatterns],
  };
  return {
    options: merged,
    string: (s) => redactString(s, merged),
    value: (v) => redactValue(v, merged),
  };
}
