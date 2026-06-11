import figlet from 'figlet';
import chalk from 'chalk';
import boxen from 'boxen';
import type { Finding, ProjectType, SafetyScore, ScanResult, Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BANNER_VERSION = 'v0.1.0';
const BANNER_DIVIDER_WIDTH = 54;

const PROJECT_TYPE_LABELS: Record<Exclude<ProjectType, 'unknown'>, string> = {
  nodejs: 'Node.js',
  python: 'Python',
  rust: 'Rust',
  go: 'Go',
};

/** Severity → coloured label function. */
const SEVERITY_COLOUR: Record<Severity, (text: string) => string> = {
  critical: (t) => chalk.red.bold(t),
  high: (t) => chalk.hex('#FF6600')(t),
  medium: (t) => chalk.yellow(t),
  low: (t) => chalk.blue(t),
  info: (t) => chalk.gray(t),
};

/** Severity → emoji. */
const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

/** Severity ordering for sorting (lower index = more severe). */
const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/**
 * Prints the VibeSafe ASCII art banner and version line.
 */
export function printBanner(): void {
  const art = figlet.textSync('VIBESAFE', { font: 'ANSI Shadow' });
  console.log(chalk.hex('#FF6B35')(art));
  console.log(chalk.gray(`Security scanner for vibe-coded apps  ${BANNER_VERSION}`));
  console.log(chalk.gray('─'.repeat(BANNER_DIVIDER_WIDTH)));
}

// ---------------------------------------------------------------------------
// Project type
// ---------------------------------------------------------------------------

/**
 * Prints the detected project type(s) or an unknown-project warning.
 */
export function printProjectTypeDetection(types: ProjectType[]): void {
  if (types.length === 1 && types[0] === 'unknown') {
    console.log(chalk.yellow('⚠  Could not detect project type. Scanning anyway.'));
    return;
  }

  const labels = types
    .filter((type): type is Exclude<ProjectType, 'unknown'> => type !== 'unknown')
    .map((type) => PROJECT_TYPE_LABELS[type]);

  console.log(chalk.white(`Detected: ${labels.join(' + ')} project`));
}

// ---------------------------------------------------------------------------
// Word-wrap helper
// ---------------------------------------------------------------------------

/**
 * Wraps text to a maximum width, breaking on whitespace.
 */
function wordWrap(text: string, maxWidth: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= maxWidth) {
      current += ' ' + word;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current.length > 0) lines.push(current);

  return lines;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/**
 * Prints every finding to the terminal with rich formatting.
 * Findings should be sorted by severity (critical first) before calling.
 */
export function printFindings(findings: Finding[]): void {
  if (findings.length === 0) return;

  console.log('');
  console.log(chalk.gray('─'.repeat(BANNER_DIVIDER_WIDTH)));
  console.log('');

  for (const finding of findings) {
    const colour = SEVERITY_COLOUR[finding.severity];
    const emoji = SEVERITY_EMOJI[finding.severity];
    const sevLabel = finding.severity.toUpperCase();

    // Header: emoji + severity + title
    console.log(colour(`${emoji} ${sevLabel}  ${finding.title}`));

    // File location
    console.log(chalk.gray(`   ${finding.file}:${finding.line}`));
    console.log('');

    // Description (word-wrapped)
    const descLines = wordWrap(finding.description, 60);
    for (const line of descLines) {
      console.log(chalk.white(`   ${line}`));
    }
    console.log('');

    // Code snippet
    if (finding.code_snippet) {
      console.log(chalk.gray('   Vulnerable code:'));
      console.log(chalk.gray('   │  ') + chalk.white(finding.code_snippet));
      console.log('');
    }

    // Fix suggestion
    if (finding.fix_suggestion) {
      const fixLines = wordWrap(finding.fix_suggestion, 60);
      console.log(chalk.green('   Fix: ') + chalk.white(fixLines[0]));
      for (let i = 1; i < fixLines.length; i++) {
        console.log(chalk.white(`        ${fixLines[i]}`));
      }
      console.log('');
    }

    // Footer: OWASP tag + rule ID
    const parts: string[] = [];
    if (finding.owasp) parts.push(finding.owasp);
    parts.push(`Rule: ${finding.rule_id}`);
    console.log(chalk.gray(`   → ${parts.join(' | ')}`));

    console.log('');
    console.log(chalk.gray('─'.repeat(BANNER_DIVIDER_WIDTH)));
    console.log('');
  }
}

/**
 * Sorts findings by severity (critical first, then high, medium, low, info).
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  });
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/**
 * Prints the issue-count summary grouped by severity.
 */
export function printSummary(summary: ScanResult['summary']): void {
  console.log('');
  console.log(chalk.bold('📊 SCAN COMPLETE'));
  console.log('');

  if (summary.total === 0) {
    console.log(chalk.green('   ✅ No issues found — looking clean!'));
    console.log('');
    return;
  }

  console.log('   Issues found:');

  // Collect non-zero severity levels in order
  const levels: { sev: Severity; count: number }[] = SEVERITY_ORDER
    .map((sev) => ({ sev, count: summary.by_severity[sev] ?? 0 }))
    .filter((l) => l.count > 0);

  for (let i = 0; i < levels.length; i++) {
    const { sev, count } = levels[i];
    const emoji = SEVERITY_EMOJI[sev];
    const colour = SEVERITY_COLOUR[sev];
    const label = sev.charAt(0).toUpperCase() + sev.slice(1) + ':';
    const prefix = i < levels.length - 1 ? '├──' : '└──';

    console.log(`   ${prefix} ${emoji} ${colour(label.padEnd(11))} ${count}`);
  }

  console.log('');
}

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

/**
 * Prints the Safety Score box and category breakdown bar chart.
 */
export function printScore(score: SafetyScore): void {
  // Determine box colour
  const borderColor = score.value >= 75 ? 'green' : score.value >= 50 ? 'yellow' : 'red';

  const scoreBox = boxen(
    [
      `${chalk.bold(`VibeSafe Score: ${score.value} / 100`)}`,
      `Grade: ${chalk.bold(score.grade)}`,
      score.label,
    ].join('\n'),
    {
      padding: 1,
      margin: { top: 0, bottom: 0, left: 3, right: 0 },
      borderStyle: 'round',
      borderColor: borderColor as 'green' | 'yellow' | 'red',
    },
  );

  console.log(scoreBox);
  console.log('');

  // Category breakdown bar chart
  console.log(chalk.bold('   Breakdown:'));

  const categories: { label: string; score: number; issues: number }[] = [
    { label: 'Secrets', ...score.breakdown.secrets },
    { label: 'SAST', ...score.breakdown.sast },
    { label: 'Dependencies', ...score.breakdown.dependencies },
    { label: 'Config', ...score.breakdown.config },
  ];

  const maxLabelLen = Math.max(...categories.map((c) => c.label.length));

  for (const cat of categories) {
    const paddedLabel = cat.label.padEnd(maxLabelLen + 1);
    const bar = renderBar(cat.score, 10);
    const scoreStr = `${String(cat.score).padStart(3)}/100`;
    const issueStr = `(${cat.issues} issue${cat.issues !== 1 ? 's' : ''})`;

    console.log(`   ${paddedLabel} ${bar}  ${scoreStr}  ${chalk.gray(issueStr)}`);
  }

  console.log('');
}

/**
 * Renders a bar chart string of `width` characters.
 * Filled portion uses █, empty uses ░.
 * Colour: green (≥75), yellow (≥50), red (<50).
 */
function renderBar(score: number, width: number): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const filledStr = '█'.repeat(filled);
  const emptyStr = '░'.repeat(empty);

  const colourFn =
    score >= 75
      ? chalk.green
      : score >= 50
        ? chalk.yellow
        : chalk.red;

  return colourFn(filledStr) + chalk.gray(emptyStr);
}

// ---------------------------------------------------------------------------
// Full output (legacy stub — now delegates to individual functions)
// ---------------------------------------------------------------------------

/**
 * Renders full scan results to the terminal with chalk, boxen, and ora.
 */
export function printTerminalOutput(result: ScanResult): void {
  const sorted = sortFindings(result.findings);
  printFindings(sorted);
  printSummary(result.summary);
  printScore(result.score);
}
