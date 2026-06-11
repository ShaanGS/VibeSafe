import { execFile } from 'child_process';
import { readdir, readFile, stat } from 'fs/promises';
import { join, relative, extname } from 'path';
import chalk from 'chalk';
import type { Finding, Severity } from '../types.js';
import { FALLBACK_REGEX_RULES, type RegexRule } from '../config/rule-descriptions.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum file size to scan with regex rules (512 KB). */
const MAX_FILE_SIZE = 512_000;

/** Extensions that are never interesting for SAST. */
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pyc', '.class', '.jar', '.lock',
  '.map', '.min.js', '.min.css',
]);

// ---------------------------------------------------------------------------
// Command execution helper (same pattern as deps.ts)
// ---------------------------------------------------------------------------

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Runs a command and captures stdout, stderr, and exit code.
 * Never throws — exit codes and errors are returned in the result.
 */
function runCommand(
  cmd: string,
  args: string[],
  cwd: string,
): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      const exitCode =
        error && 'code' in error && typeof error.code === 'number'
          ? error.code
          : error
            ? 1
            : 0;
      resolve({
        stdout: stdout ?? '',
        stderr: stderr ?? '',
        exitCode,
      });
    });
  });
}

/**
 * Returns true when the given command is available on $PATH.
 */
async function commandExists(cmd: string): Promise<boolean> {
  const { exitCode } = await runCommand(
    process.platform === 'win32' ? 'where' : 'which',
    [cmd],
    '.',
  );
  return exitCode === 0;
}

// ---------------------------------------------------------------------------
// Finding counter
// ---------------------------------------------------------------------------

let findingCounter = 0;

function nextFindingId(): string {
  findingCounter += 1;
  return `vs-sast-${String(findingCounter).padStart(3, '0')}`;
}

// ---------------------------------------------------------------------------
// Semgrep JSON parser
// ---------------------------------------------------------------------------

/**
 * Shapes from Semgrep's JSON output — only the fields we use.
 */
interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message?: string;
    severity?: string;       // ERROR | WARNING | INFO
    metadata?: {
      owasp?: string[];
      cwe?: string[];
      references?: string[];
    };
    lines?: string;
    fix?: string;
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: unknown[];
}

/** Maps Semgrep severity to our Severity type. */
function mapSemgrepSeverity(s: string | undefined): Severity {
  switch (s?.toUpperCase()) {
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'low';
    default:
      return 'medium';
  }
}

/**
 * Parses Semgrep JSON output into Finding[].
 * Exported for unit testing.
 */
export function parseSemgrepOutput(json: string): Finding[] {
  let output: SemgrepOutput;
  try {
    output = JSON.parse(json) as SemgrepOutput;
  } catch {
    return [];
  }

  const results = output.results;
  if (!Array.isArray(results)) return [];

  return results.map((r): Finding => {
    const severity = mapSemgrepSeverity(r.extra?.severity);
    const owaspTags = r.extra?.metadata?.owasp ?? [];
    const cweList = r.extra?.metadata?.cwe ?? [];

    return {
      id: nextFindingId(),
      category: 'sast',
      severity,
      title: r.extra?.message ?? r.check_id,
      description:
        r.extra?.message ??
        `Semgrep rule ${r.check_id} found a potential vulnerability.`,
      file: r.path,
      line: r.start.line,
      column: r.start.col,
      code_snippet: r.extra?.lines ?? '',
      rule_id: r.check_id,
      owasp: owaspTags[0],
      fix_suggestion: r.extra?.fix ?? 'Review and fix this code manually.',
      references: [
        ...(r.extra?.metadata?.references ?? []),
        ...cweList.map((c) => `https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html`),
      ],
    };
  });
}

// ---------------------------------------------------------------------------
// Ignore-pattern matching (same logic as secrets scanner)
// ---------------------------------------------------------------------------

function shouldIgnoreFile(filePath: string, ignorePatterns: string[]): boolean {
  for (const pattern of ignorePatterns) {
    if (pattern.endsWith('/')) {
      const dirName = pattern.slice(0, -1);
      if (filePath.includes(`/${dirName}/`) || filePath.startsWith(`${dirName}/`)) {
        return true;
      }
    } else if (pattern.startsWith('*.')) {
      const ext = pattern.slice(1);
      if (filePath.endsWith(ext)) {
        return true;
      }
    } else {
      if (filePath === pattern || filePath.includes(`/${pattern}`) || filePath.startsWith(`${pattern}`)) {
        return true;
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// File walker
// ---------------------------------------------------------------------------

async function* walkFiles(
  dirPath: string,
  rootPath: string,
  ignorePatterns: string[],
): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    const relPath = relative(rootPath, fullPath);

    if (entry.isDirectory()) {
      if (shouldIgnoreFile(relPath + '/', ignorePatterns)) continue;
      yield* walkFiles(fullPath, rootPath, ignorePatterns);
    } else if (entry.isFile()) {
      if (SKIP_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
      if (shouldIgnoreFile(relPath, ignorePatterns)) continue;
      yield fullPath;
    }
  }
}

// ---------------------------------------------------------------------------
// Fallback regex scanner
// ---------------------------------------------------------------------------

/**
 * Runs the built-in regex rules against all matching files.
 * Used when Semgrep is not installed.
 * Exported for unit testing.
 */
export async function runFallbackRegexRules(
  repoPath: string,
  ignorePatterns: string[],
  rules?: RegexRule[],
): Promise<Finding[]> {
  const ruleSet = rules ?? FALLBACK_REGEX_RULES;
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for await (const filePath of walkFiles(repoPath, repoPath, ignorePatterns)) {
    const ext = extname(filePath).toLowerCase();

    // Collect rules that apply to this file extension
    const applicableRules = ruleSet.filter((r) => r.fileTypes.includes(ext));
    if (applicableRules.length === 0) continue;

    // Skip large files
    let fileStat;
    try {
      fileStat = await stat(filePath);
    } catch {
      continue;
    }
    if (fileStat.size > MAX_FILE_SIZE) continue;

    // Read file
    let content: string;
    try {
      content = await readFile(filePath, 'utf-8');
    } catch {
      continue;
    }

    // Skip binary files (null-byte heuristic)
    if (content.includes('\0')) continue;

    const relFile = relative(repoPath, filePath);
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      for (const rule of applicableRules) {
        // Reset lastIndex for stateful regexes
        if (rule.pattern.global) rule.pattern.lastIndex = 0;

        if (rule.pattern.test(line)) {
          const key = `${relFile}:${lineNum}:${rule.id}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            id: nextFindingId(),
            category: 'sast',
            severity: rule.severity,
            title: rule.title,
            description: rule.description,
            file: relFile,
            line: lineNum,
            code_snippet: line.trimEnd(),
            rule_id: rule.id,
            owasp: rule.owasp,
            fix_suggestion: rule.fixSuggestion,
            references: rule.references,
          });
        }
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Whether a "semgrep not installed" hint has been printed this run. */
let hintPrinted = false;

/**
 * Runs static analysis (SAST) on the repository.
 *
 * If Semgrep is installed, runs it with `--config=auto --json --quiet` and also
 * loads any custom rules from `packages/cli/rules/`.
 *
 * If Semgrep is not installed, falls back to the built-in regex rules that
 * catch the most common OWASP vulnerabilities in AI-generated code.
 *
 * @param repoPath - Absolute path to the repository root.
 * @param ignorePatterns - Glob patterns for files/directories to skip.
 * @returns Array of Finding objects.
 */
export async function scanSAST(
  repoPath: string,
  ignorePatterns: string[],
): Promise<Finding[]> {
  // Reset counter for each scan run
  findingCounter = 0;
  hintPrinted = false;

  const hasSemgrep = await commandExists('semgrep');

  if (hasSemgrep) {
    return runSemgrep(repoPath, ignorePatterns);
  }

  // Semgrep not installed — print hint and fall back to regex rules
  if (!hintPrinted) {
    console.log(
      chalk.yellow('💡 Install Semgrep for deeper scanning: ') +
      chalk.cyan('brew install semgrep'),
    );
    hintPrinted = true;
  }

  return runFallbackRegexRules(repoPath, ignorePatterns);
}

// ---------------------------------------------------------------------------
// Semgrep runner
// ---------------------------------------------------------------------------

/**
 * Runs Semgrep with both auto-config and custom rules, then parses the output.
 */
async function runSemgrep(
  repoPath: string,
  _ignorePatterns: string[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Build the semgrep CLI arguments
  const args = [
    'scan',
    '--config=auto',
    '--json',
    '--quiet',
  ];

  // Also include our custom rules directory if it exists
  const rulesDir = join(repoPath, 'rules');
  try {
    const { exitCode } = await runCommand('test', ['-d', rulesDir], '.');
    if (exitCode === 0) {
      args.push(`--config=${rulesDir}`);
    }
  } catch {
    // rules dir doesn't exist — fine, just use auto config
  }

  args.push(repoPath);

  const result = await runCommand('semgrep', args, repoPath);

  // Semgrep may return exit code 1 if findings exist — that's normal
  if (result.stdout.trim().length > 0) {
    findings.push(...parseSemgrepOutput(result.stdout));
  }

  // Also run our fallback rules to catch things Semgrep might miss
  // (e.g. our AI-specific patterns)
  const regexFindings = await runFallbackRegexRules(repoPath, _ignorePatterns);

  // Merge, deduplicating by file:line:category
  const seen = new Set(findings.map((f) => `${f.file}:${f.line}`));
  for (const rf of regexFindings) {
    const key = `${rf.file}:${rf.line}`;
    if (!seen.has(key)) {
      findings.push(rf);
      seen.add(key);
    }
  }

  return findings;
}
