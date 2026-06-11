import { resolve } from 'path';
import ora from 'ora';
import chalk from 'chalk';
import {
  printBanner,
  printProjectTypeDetection,
  printFindings,
  printSummary,
  printScore,
  sortFindings,
} from '../output/terminal.js';
import { calculateScore } from '../output/score.js';
import { detectProjectType } from '../utils/detect.js';
import { getIgnorePatterns } from '../utils/ignore.js';
import { scanSecrets } from '../scanners/secrets.js';
import { scanDependencies } from '../scanners/deps.js';
import { scanSAST } from '../scanners/sast.js';
import type { Finding, FindingCategory, ScanResult, Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Removes duplicate findings where file + line + rule_id are identical.
 */
function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.file}:${f.line}:${f.rule_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Builds the summary counts from a list of findings.
 */
function buildSummary(findings: Finding[]): ScanResult['summary'] {
  const by_severity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const by_category: Record<FindingCategory, number> = {
    sast: 0,
    secret: 0,
    dependency: 0,
    config: 0,
  };

  for (const f of findings) {
    by_severity[f.severity]++;
    by_category[f.category]++;
  }

  return { total: findings.length, by_severity, by_category };
}

/**
 * Returns true when there are findings at or above the given severity.
 */
function hasHighSeverity(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === 'critical' || f.severity === 'high');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ScanCommandOptions {
  json?: boolean;
}

/**
 * Runs the `vibesafe scan` command end-to-end:
 * banner → project detection → SAST → secrets → deps → score → output.
 */
export async function scanCommand(
  path: string,
  options: ScanCommandOptions = {},
): Promise<void> {
  const startTime = Date.now();

  if (!options.json) {
    printBanner();
  }

  const repoPath = resolve(path);

  // --- Project detection ---
  const detectSpinner = options.json ? null : ora('Detecting project type...').start();
  let projectTypes: Awaited<ReturnType<typeof detectProjectType>>;
  try {
    projectTypes = await detectProjectType(repoPath);
    detectSpinner?.succeed('Detecting project type...');
    if (!options.json) printProjectTypeDetection(projectTypes);
  } catch (error: unknown) {
    detectSpinner?.fail('Detecting project type...');
    throw error;
  }

  const ignorePatterns = await getIgnorePatterns(repoPath);
  const allFindings: Finding[] = [];

  // --- SAST scan ---
  const sastSpinner = options.json ? null : ora('Running SAST scan...').start();
  try {
    const sastFindings = await scanSAST(repoPath, ignorePatterns);
    allFindings.push(...sastFindings);
    sastSpinner?.succeed(
      `SAST scan complete — ${sastFindings.length} issue${sastFindings.length !== 1 ? 's' : ''} found`,
    );
  } catch (error: unknown) {
    sastSpinner?.fail('Running SAST scan...');
    throw error;
  }

  // --- Secrets scan ---
  const secretsSpinner = options.json ? null : ora('Scanning for secrets...').start();
  try {
    const secretFindings = await scanSecrets(repoPath, ignorePatterns);
    allFindings.push(...secretFindings);
    secretsSpinner?.succeed(
      `Scanning for secrets... ${secretFindings.length} issue${secretFindings.length !== 1 ? 's' : ''} found`,
    );
  } catch (error: unknown) {
    secretsSpinner?.fail('Scanning for secrets...');
    throw error;
  }

  // --- Dependency scan ---
  const depsSpinner = options.json ? null : ora('Checking dependencies...').start();
  try {
    const depFindings = await scanDependencies(repoPath, projectTypes);
    allFindings.push(...depFindings);
    depsSpinner?.succeed(
      `Dependency scan complete — ${depFindings.length} issue${depFindings.length !== 1 ? 's' : ''} found`,
    );
  } catch (error: unknown) {
    depsSpinner?.fail('Checking dependencies...');
    throw error;
  }

  // --- Build result ---
  const dedupedFindings = deduplicateFindings(allFindings);
  const summary = buildSummary(dedupedFindings);
  const score = calculateScore(dedupedFindings);
  const durationMs = Date.now() - startTime;

  const scanResult: ScanResult = {
    meta: {
      repo_path: repoPath,
      scanned_at: new Date().toISOString(),
      duration_ms: durationMs,
      project_type: projectTypes,
      vibesafe_version: '0.1.0',
    },
    findings: dedupedFindings,
    summary,
    score,
  };

  // --- Output ---
  if (options.json) {
    console.log(JSON.stringify(scanResult, null, 2));
  } else {
    // Print findings sorted by severity (critical first)
    const sorted = sortFindings(dedupedFindings);
    printFindings(sorted);

    // Summary + Score
    printSummary(summary);
    printScore(score);

    // Bottom call-to-action
    if (dedupedFindings.length > 0) {
      console.log(
        chalk.cyan('   Run ') +
        chalk.cyan.bold('vibesafe fix') +
        chalk.cyan(' to auto-generate fixes.'),
      );
      console.log(
        chalk.gray('   Run ') +
        chalk.gray('vibesafe fix --pr') +
        chalk.gray(' to open a GitHub PR with fixes applied.'),
      );
      console.log('');
    }
  }

  // --- Exit code ---
  if (hasHighSeverity(dedupedFindings)) {
    process.exit(1);
  }
}
