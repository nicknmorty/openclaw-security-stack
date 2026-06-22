# Shareable Digest

A short, low-noise, redaction-safe summary of a scan run — suitable for a chat
message or a quick CLI glance. It focuses on ACTIVE signal (new findings) and
keeps acknowledged/persistent noise out of the headline.

## What it shows

- Headline counts: new / persistent / acknowledged / resolved.
- Active severity breakdown (HIGH / MEDIUM / LOW), excluding acknowledged.
- Top N new findings, sorted by severity, each one line:
  `\u{1F534} [HIGH] <title> — <file>:<line> (<tool> · <target>)`.
- Tool run status (all ok, or which failed).

Input is already redacted (built from the redacted reports + SUMMARY), so the
digest is safe to paste into a channel.

## Usage

The orchestrator writes `runs/summary/DIGEST.txt` automatically on every run.
You can also generate it standalone from an existing runs root:

```bash
node scripts/security-digest.mjs --runs runs --top 10
node scripts/security-digest.mjs --runs runs --severities HIGH,MEDIUM --out runs/summary/DIGEST.txt
```

Options: `--runs <dir>`, `--top <n>`, `--severities <list>`, `--out <path>`,
`--quiet`.

Pair it with suppressions to keep the digest honest: acknowledged findings drop
out of `new`, so the digest highlights only what actually needs attention.

## Tests

```bash
node scripts/test-security-digest.mjs
```
