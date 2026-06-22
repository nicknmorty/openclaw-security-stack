#!/usr/bin/env node
// Tests for the static-scan severity/confidence tuning (tiered taint).

import assert from 'node:assert/strict';
import { taintStrength, downgradeSeverity, scoreCandidate, denoiseContext } from './security-static-scan.mjs';

let passed = 0;
function test(name, fn) { fn(); passed += 1; process.stdout.write(`ok - ${name}\n`); }

test('taintStrength: strong external sources', () => {
  assert.equal(taintStrength('const v = req.body.path;'), 'strong');
  assert.equal(taintStrength('handle(message.text)'), 'strong');
  assert.equal(taintStrength('webhook payload here'), 'strong');
});

test('taintStrength: weak plumbing sources', () => {
  assert.equal(taintStrength('path.join(args.outDir, x)'), 'weak');
  assert.equal(taintStrength('process.env.FOO'), 'weak');
  assert.equal(taintStrength('handle(input)'), 'weak');
});

test('taintStrength: none (and substrings do not count as tokens)', () => {
  assert.equal(taintStrength('const total = a + b;'), null);
  // "userName" is not a standalone "user" token -> no false taint
  assert.equal(taintStrength('const userName = 1'), null);
});

test('denoiseContext strips err.message/error.stack but keeps real sources', () => {
  assert.equal(taintStrength('throw new Error(`bad: ${err.message}`)'), null, 'err.message is not taint');
  assert.equal(taintStrength('return (err.stderr || err.message)'), null);
  assert.ok(!denoiseContext('err.message').includes('message'));
  // real agent message source survives denoise
  assert.equal(taintStrength('handle(update.message.text)'), 'strong');
  assert.equal(taintStrength('const t = ctx.message'), 'strong');
});

test('downgradeSeverity steps down one notch and floors at LOW', () => {
  assert.equal(downgradeSeverity('HIGH'), 'MEDIUM');
  assert.equal(downgradeSeverity('MEDIUM'), 'LOW');
  assert.equal(downgradeSeverity('LOW'), 'LOW');
});

test('scoreCandidate: strong taint keeps base severity/confidence', () => {
  const rule = { severity: 'MEDIUM', confidence: 0.68, needsTaint: true };
  const s = scoreCandidate(rule, 'strong');
  assert.equal(s.severity, 'MEDIUM');
  assert.equal(s.confidence, 0.68);
  assert.equal(s.taint_strength, 'strong');
});

test('scoreCandidate: weak taint downgrades severity and confidence', () => {
  const pathRule = { severity: 'MEDIUM', confidence: 0.68, needsTaint: true };
  const w = scoreCandidate(pathRule, 'weak');
  assert.equal(w.severity, 'LOW');
  assert.equal(w.confidence, 0.43);
  assert.equal(w.taint_strength, 'weak');

  const execRule = { severity: 'HIGH', confidence: 0.72, needsTaint: true };
  const we = scoreCandidate(execRule, 'weak');
  assert.equal(we.severity, 'MEDIUM');
  assert.equal(we.confidence, 0.47);
});

test('scoreCandidate: non-taint rules are unaffected', () => {
  const rule = { severity: 'HIGH', confidence: 0.76, needsTaint: false };
  const s = scoreCandidate(rule, 'weak');
  assert.equal(s.severity, 'HIGH');
  assert.equal(s.confidence, 0.76);
  assert.equal(s.taint_strength, 'n/a');
});

process.stdout.write(`\n${passed} tests passed\n`);
