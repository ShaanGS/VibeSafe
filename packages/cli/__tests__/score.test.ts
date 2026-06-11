import { describe, expect, it } from 'vitest';
import { calculateScore } from '../src/output/score.js';
import type { Finding } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers — build a minimal Finding
// ---------------------------------------------------------------------------

function makeFinding(
  overrides: Partial<Finding> & Pick<Finding, 'severity' | 'category'>,
): Finding {
  return {
    id: 'test-001',
    title: 'Test finding',
    description: 'Test description',
    file: 'test.ts',
    line: 1,
    code_snippet: 'test',
    rule_id: 'test-rule',
    references: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('calculateScore', () => {
  // ----- Zero findings -----

  it('returns score 100, grade A, SAFE TO SHIP for zero findings', () => {
    const score = calculateScore([]);

    expect(score.value).toBe(100);
    expect(score.grade).toBe('A');
    expect(score.label).toContain('SAFE TO SHIP');
    expect(score.breakdown.secrets.score).toBe(100);
    expect(score.breakdown.secrets.issues).toBe(0);
    expect(score.breakdown.sast.score).toBe(100);
    expect(score.breakdown.sast.issues).toBe(0);
    expect(score.breakdown.dependencies.score).toBe(100);
    expect(score.breakdown.dependencies.issues).toBe(0);
    expect(score.breakdown.config.score).toBe(100);
    expect(score.breakdown.config.issues).toBe(0);
  });

  // ----- Single critical secret -----

  it('1 critical secret → penalty 37.5, score ≤ 63', () => {
    // penalty = 25 (critical) × 1.5 (secret) = 37.5
    // rawScore = 100 - 37.5 = 62.5 → rounds to 63
    const findings = [
      makeFinding({ severity: 'critical', category: 'secret' }),
    ];

    const score = calculateScore(findings);

    expect(score.value).toBe(63);
    expect(score.grade).toBe('C');
    expect(score.breakdown.secrets.issues).toBe(1);
    expect(score.breakdown.secrets.score).toBe(63);
  });

  // ----- 4 high SAST findings -----

  it('4 high SAST findings → penalty 40, score ≤ 60', () => {
    // penalty = 4 × (10 × 1.0) = 40
    // rawScore = 100 - 40 = 60
    const findings = Array.from({ length: 4 }, (_, i) =>
      makeFinding({
        id: `sast-${i}`,
        severity: 'high',
        category: 'sast',
        rule_id: `rule-${i}`,
      }),
    );

    const score = calculateScore(findings);

    expect(score.value).toBe(60);
    expect(score.grade).toBe('C');
    expect(score.breakdown.sast.issues).toBe(4);
    expect(score.breakdown.sast.score).toBe(60);
  });

  // ----- Mixed findings -----

  it('mixed findings: formula is applied correctly', () => {
    // 1 critical secret:   25 × 1.5 = 37.5
    // 2 high SAST:         2 × (10 × 1.0) = 20
    // 1 medium dependency: 4 × 0.8 = 3.2
    // Total penalty = 37.5 + 20 + 3.2 = 60.7
    // rawScore = 100 - 60.7 = 39.3 → rounds to 39
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical', category: 'secret', rule_id: 'r1' }),
      makeFinding({ id: 'f2', severity: 'high', category: 'sast', rule_id: 'r2' }),
      makeFinding({ id: 'f3', severity: 'high', category: 'sast', rule_id: 'r3' }),
      makeFinding({ id: 'f4', severity: 'medium', category: 'dependency', rule_id: 'r4' }),
    ];

    const score = calculateScore(findings);

    expect(score.value).toBe(39);
    expect(score.grade).toBe('F');
    expect(score.label).toContain('FIX BEFORE SHIPPING');
    expect(score.breakdown.secrets.issues).toBe(1);
    expect(score.breakdown.sast.issues).toBe(2);
    expect(score.breakdown.dependencies.issues).toBe(1);
    expect(score.breakdown.config.issues).toBe(0);
  });

  // ----- Grade boundaries -----

  it('grade A for score >= 90 (1 low info finding)', () => {
    // penalty = 1 × 1.0 = 1 → score 99
    const findings = [
      makeFinding({ severity: 'low', category: 'sast' }),
    ];
    const score = calculateScore(findings);
    expect(score.value).toBe(99);
    expect(score.grade).toBe('A');
  });

  it('grade B for score in 75–89 range', () => {
    // 1 high secret: 10 × 1.5 = 15 → score 85 → B
    const findings = [
      makeFinding({ severity: 'high', category: 'secret' }),
    ];
    const score = calculateScore(findings);
    expect(score.value).toBe(85);
    expect(score.grade).toBe('B');
    expect(score.label).toContain('SAFE TO SHIP');
  });

  it('grade D for score in 40–59 range', () => {
    // 2 critical SAST: 2 × (25 × 1.0) = 50 → score 50 → D
    const findings = [
      makeFinding({ id: 'c1', severity: 'critical', category: 'sast', rule_id: 'cr1' }),
      makeFinding({ id: 'c2', severity: 'critical', category: 'sast', rule_id: 'cr2' }),
    ];
    const score = calculateScore(findings);
    expect(score.value).toBe(50);
    expect(score.grade).toBe('D');
    expect(score.label).toContain('REVIEW BEFORE SHIPPING');
  });

  // ----- Score clamped to 0 -----

  it('score is clamped at 0 for massive penalties', () => {
    // 10 critical secrets: 10 × (25 × 1.5) = 375 → capped at 100 → score 0
    const findings = Array.from({ length: 10 }, (_, i) =>
      makeFinding({
        id: `s-${i}`,
        severity: 'critical',
        category: 'secret',
        rule_id: `r-${i}`,
      }),
    );

    const score = calculateScore(findings);
    expect(score.value).toBe(0);
    expect(score.grade).toBe('F');
    expect(score.label).toContain('FIX BEFORE SHIPPING');
  });

  // ----- Info findings -----

  it('info findings have zero penalty', () => {
    const findings = [
      makeFinding({ severity: 'info', category: 'sast' }),
    ];

    const score = calculateScore(findings);
    expect(score.value).toBe(100);
    expect(score.grade).toBe('A');
  });

  // ----- Config category -----

  it('config findings use 0.6 multiplier', () => {
    // 1 medium config: 4 × 0.6 = 2.4 → score 98 → A
    const findings = [
      makeFinding({ severity: 'medium', category: 'config' }),
    ];

    const score = calculateScore(findings);
    expect(score.value).toBe(98);
    expect(score.grade).toBe('A');
    expect(score.breakdown.config.issues).toBe(1);
  });

  // ----- Breakdown sub-scores -----

  it('breakdown sub-scores are computed independently per category', () => {
    const findings = [
      makeFinding({ id: 'f1', severity: 'critical', category: 'secret', rule_id: 'r1' }),
      makeFinding({ id: 'f2', severity: 'low', category: 'sast', rule_id: 'r2' }),
    ];

    const score = calculateScore(findings);

    // secrets: penalty 25 × 1.5 = 37.5 → score 63
    expect(score.breakdown.secrets.score).toBe(63);
    expect(score.breakdown.secrets.issues).toBe(1);

    // sast: penalty 1 × 1.0 = 1 → score 99
    expect(score.breakdown.sast.score).toBe(99);
    expect(score.breakdown.sast.issues).toBe(1);

    // deps and config: untouched
    expect(score.breakdown.dependencies.score).toBe(100);
    expect(score.breakdown.config.score).toBe(100);
  });
});
