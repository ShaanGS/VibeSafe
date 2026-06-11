import type { Finding, FindingCategory, SafetyScore, Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Weights
// ---------------------------------------------------------------------------

/** Penalty points per finding, keyed by severity. */
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
};

/** Multiplier applied on top of severity weight, keyed by category. */
const CATEGORY_MULTIPLIERS: Record<FindingCategory, number> = {
  secret: 1.5,
  sast: 1.0,
  dependency: 0.8,
  config: 0.6,
};

/** Maps FindingCategory to the breakdown key name. */
const CATEGORY_TO_BREAKDOWN: Record<FindingCategory, keyof SafetyScore['breakdown']> = {
  secret: 'secrets',
  sast: 'sast',
  dependency: 'dependencies',
  config: 'config',
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Computes the 0–100 Safety Score from a list of findings.
 *
 * Formula:
 *   penalty = Σ (SEVERITY_WEIGHTS[severity] × CATEGORY_MULTIPLIERS[category])
 *   rawScore = max(0, 100 − min(penalty, 100))
 *   score = round(rawScore)
 *
 * Grade:  A (≥90) | B (≥75) | C (≥60) | D (≥40) | F (<40)
 * Label:  ✅ SAFE TO SHIP (≥75) | ⚠️  REVIEW BEFORE SHIPPING (≥50) | ⛔ FIX BEFORE SHIPPING (<50)
 */
export function calculateScore(findings: Finding[]): SafetyScore {
  // --- Per-category breakdown ---
  const categoryFindings: Record<keyof SafetyScore['breakdown'], Finding[]> = {
    secrets: [],
    sast: [],
    dependencies: [],
    config: [],
  };

  for (const f of findings) {
    const key = CATEGORY_TO_BREAKDOWN[f.category];
    if (key) {
      categoryFindings[key].push(f);
    }
  }

  const breakdown: SafetyScore['breakdown'] = {
    secrets: computeCategoryBreakdown(categoryFindings.secrets),
    sast: computeCategoryBreakdown(categoryFindings.sast),
    dependencies: computeCategoryBreakdown(categoryFindings.dependencies),
    config: computeCategoryBreakdown(categoryFindings.config),
  };

  // --- Overall score ---
  const penalty = findings.reduce((acc, f) => {
    const severityPenalty = SEVERITY_WEIGHTS[f.severity];
    const categoryMultiplier = CATEGORY_MULTIPLIERS[f.category];
    return acc + severityPenalty * categoryMultiplier;
  }, 0);

  const rawScore = Math.max(0, 100 - Math.min(penalty, 100));
  const value = Math.round(rawScore);

  const grade: SafetyScore['grade'] =
    value >= 90
      ? 'A'
      : value >= 75
        ? 'B'
        : value >= 60
          ? 'C'
          : value >= 40
            ? 'D'
            : 'F';

  const label =
    value >= 75
      ? '✅ SAFE TO SHIP'
      : value >= 50
        ? '⚠️  REVIEW BEFORE SHIPPING'
        : '⛔ FIX BEFORE SHIPPING';

  return { value, grade, label, breakdown };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Computes the sub-score for a single category.
 * Uses the same penalty formula but scoped to one category's findings,
 * then scales to 0–100.
 */
function computeCategoryBreakdown(
  findings: Finding[],
): { score: number; issues: number } {
  if (findings.length === 0) {
    return { score: 100, issues: 0 };
  }

  const penalty = findings.reduce((acc, f) => {
    return acc + SEVERITY_WEIGHTS[f.severity] * CATEGORY_MULTIPLIERS[f.category];
  }, 0);

  const score = Math.round(Math.max(0, 100 - Math.min(penalty, 100)));
  return { score, issues: findings.length };
}
