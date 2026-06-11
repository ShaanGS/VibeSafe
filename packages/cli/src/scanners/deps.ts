import { execFile } from 'child_process';
import { readFile, access } from 'fs/promises';
import { join } from 'path';
import type { DependencyFinding, Finding, ProjectType, Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maps npm audit severity strings to our Severity type. */
const NPM_SEVERITY_MAP: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  low: 'low',
  info: 'info',
};

/** Maps pip-audit severity (if present) or defaults to high. */
const PIP_SEVERITY_MAP: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  LOW: 'low',
};

/**
 * Known problematic npm packages with historically severe CVEs.
 * Checked against package.json dependencies as a fast supplementary scan.
 */
const KNOWN_BAD_NPM_PACKAGES: {
  name: string;
  maxSafeVersion: string;
  cve: string;
  severity: Severity;
  title: string;
  description: string;
}[] = [
  {
    name: 'event-stream',
    maxSafeVersion: '3.3.4',
    cve: 'CVE-2018-16396',
    severity: 'critical',
    title: 'Malicious dependency injection in event-stream',
    description:
      'The event-stream package was compromised with a malicious dependency (flatmap-stream) that stole cryptocurrency wallet credentials. Remove or replace this package immediately.',
  },
  {
    name: 'ua-parser-js',
    maxSafeVersion: '0.7.30',
    cve: 'CVE-2021-27292',
    severity: 'critical',
    title: 'Supply chain attack in ua-parser-js',
    description:
      'Versions of ua-parser-js were hijacked to include cryptomining and credential-stealing malware. Update to a safe version immediately.',
  },
  {
    name: 'node-ipc',
    maxSafeVersion: '10.1.0',
    cve: 'CVE-2022-23812',
    severity: 'critical',
    title: 'Protestware — destructive payload in node-ipc',
    description:
      'Certain versions of node-ipc contain protestware that overwrites files on disk. Update to a version above 10.1.0 or remove entirely.',
  },
  {
    name: 'colors',
    maxSafeVersion: '1.4.0',
    cve: 'CVE-2022-colors',
    severity: 'high',
    title: 'Sabotaged package — colors',
    description:
      'The colors package was intentionally corrupted by its author, causing infinite loops and garbled terminal output. Pin to version 1.4.0.',
  },
  {
    name: 'faker',
    maxSafeVersion: '5.5.3',
    cve: 'CVE-2022-faker',
    severity: 'high',
    title: 'Sabotaged package — faker',
    description:
      'The faker package was intentionally corrupted by its author. Use @faker-js/faker (the community fork) instead.',
  },
  {
    name: 'lodash',
    maxSafeVersion: '4.17.20',
    cve: 'CVE-2021-23337',
    severity: 'high',
    title: 'Prototype Pollution in lodash',
    description:
      'Older versions of lodash are vulnerable to Prototype Pollution via the template function. Update to lodash 4.17.21 or later.',
  },
  {
    name: 'minimist',
    maxSafeVersion: '1.2.5',
    cve: 'CVE-2021-44906',
    severity: 'high',
    title: 'Prototype Pollution in minimist',
    description:
      'Older versions of minimist allow Prototype Pollution through crafted command-line arguments. Update to 1.2.6 or later.',
  },
  {
    name: 'jsonwebtoken',
    maxSafeVersion: '8.5.1',
    cve: 'CVE-2022-23529',
    severity: 'high',
    title: 'Insecure key retrieval in jsonwebtoken',
    description:
      'Versions of jsonwebtoken before 9.0.0 are vulnerable to remote code execution when using a maliciously crafted JWK. Update to 9.0.0+.',
  },
  {
    name: 'shell-quote',
    maxSafeVersion: '1.7.2',
    cve: 'CVE-2021-42740',
    severity: 'high',
    title: 'Command injection in shell-quote',
    description:
      'Older versions of shell-quote allow attackers to inject arbitrary commands via unsanitised input. Update to 1.7.3 or later.',
  },
  {
    name: 'tar',
    maxSafeVersion: '6.1.8',
    cve: 'CVE-2021-37701',
    severity: 'high',
    title: 'Arbitrary file write in tar',
    description:
      'Older versions of the tar package are vulnerable to arbitrary file creation/overwrite via a specially crafted tarball. Update to 6.1.9+.',
  },
];

// ---------------------------------------------------------------------------
// Command execution helper
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
export function runCommand(
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
  return `vs-dep-${String(findingCounter).padStart(3, '0')}`;
}

// ---------------------------------------------------------------------------
// npm audit parser
// ---------------------------------------------------------------------------

/**
 * Shapes expected from `npm audit --json` (npm v7+ / audit report v2).
 * Only the fields we consume are typed here.
 */
interface NpmAuditVia {
  source?: number;
  name?: string;
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string[];
  range?: string;
}

interface NpmAuditFixAvailable {
  name?: string;
  version?: string;
  isSemVerMajor?: boolean;
}

interface NpmAuditVuln {
  name: string;
  severity: string;
  via: (NpmAuditVia | string)[];
  range?: string;
  fixAvailable?: NpmAuditFixAvailable | boolean;
  nodes?: string[];
}

interface NpmAuditReport {
  auditReportVersion?: number;
  vulnerabilities?: Record<string, NpmAuditVuln>;
  metadata?: {
    vulnerabilities?: Record<string, number>;
  };
}

/**
 * Parses npm audit JSON output (v7+ report format) into Finding[].
 * Exported for unit testing.
 */
export function parseNpmAuditOutput(json: string): DependencyFinding[] {
  let report: NpmAuditReport;
  try {
    report = JSON.parse(json) as NpmAuditReport;
  } catch {
    return [];
  }

  const vulns = report.vulnerabilities;
  if (!vulns || typeof vulns !== 'object') return [];

  const findings: DependencyFinding[] = [];

  for (const [pkgName, vuln] of Object.entries(vulns)) {
    // Resolve the advisory details from `via` — skip string-only via entries
    // (those just point to a parent package, not an actual advisory)
    const advisoryVias = (vuln.via ?? []).filter(
      (v): v is NpmAuditVia => typeof v === 'object',
    );

    if (advisoryVias.length === 0) {
      // This is a transitive-only entry (via is just strings). Still report it
      // but with less detail.
      const severity = NPM_SEVERITY_MAP[vuln.severity] ?? 'medium';
      const patchedVersion =
        typeof vuln.fixAvailable === 'object' && vuln.fixAvailable?.version
          ? vuln.fixAvailable.version
          : 'unknown';

      findings.push({
        id: nextFindingId(),
        category: 'dependency',
        severity,
        title: `Vulnerable dependency: ${pkgName}`,
        description:
          `The ${pkgName} package you're using has a known security vulnerability. ` +
          `Update to version ${patchedVersion !== 'unknown' ? patchedVersion : 'the latest safe version'} to fix this.`,
        file: 'package.json',
        line: 0,
        code_snippet: `"${pkgName}": "..."`,
        rule_id: `vs-dep-npm-${pkgName}`,
        fix_suggestion: `Run \`npm install ${pkgName}@latest\` to update to a safe version.`,
        references: [],
        package_name: pkgName,
        installed_version: 'unknown',
        patched_version: patchedVersion,
        ecosystem: 'npm',
      });
      continue;
    }

    // Create one finding per distinct advisory
    for (const advisory of advisoryVias) {
      const severity = NPM_SEVERITY_MAP[advisory.severity ?? vuln.severity] ?? 'medium';
      const advisoryTitle = advisory.title ?? 'Unknown vulnerability';
      const advisoryUrl = advisory.url ?? '';
      const patchedVersion =
        typeof vuln.fixAvailable === 'object' && vuln.fixAvailable?.version
          ? vuln.fixAvailable.version
          : 'unknown';

      // Extract CVE from advisory URL if it's a GHSA URL, or use the title
      const cve = advisoryUrl.includes('GHSA-')
        ? advisoryUrl.split('/').pop() ?? undefined
        : undefined;

      findings.push({
        id: nextFindingId(),
        category: 'dependency',
        severity,
        title: `${advisoryTitle} in ${pkgName}`,
        description:
          `The ${pkgName} package you're using has a known security vulnerability` +
          (cve ? ` (${cve})` : '') +
          ` that ${advisoryTitle.toLowerCase()}. ` +
          `Update to version ${patchedVersion !== 'unknown' ? patchedVersion : 'the latest safe version'} to fix this.`,
        file: 'package.json',
        line: 0,
        code_snippet: `"${pkgName}": "..."`,
        rule_id: `vs-dep-npm-${pkgName}`,
        cve,
        owasp: 'A06:2021 – Vulnerable and Outdated Components',
        fix_suggestion: `Run \`npm install ${pkgName}@${patchedVersion !== 'unknown' ? patchedVersion : 'latest'}\` to update to a safe version.`,
        references: advisoryUrl ? [advisoryUrl] : [],
        package_name: pkgName,
        installed_version: vuln.range ?? 'unknown',
        patched_version: patchedVersion,
        ecosystem: 'npm',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// pip-audit parser
// ---------------------------------------------------------------------------

interface PipAuditVuln {
  id: string;
  fix_versions?: string[];
  description?: string;
  aliases?: string[];
}

interface PipAuditEntry {
  name: string;
  version: string;
  vulns: PipAuditVuln[];
}

/**
 * Parses pip-audit JSON output into Finding[].
 * Exported for unit testing.
 */
export function parsePipAuditOutput(json: string): DependencyFinding[] {
  let entries: PipAuditEntry[];
  try {
    entries = JSON.parse(json) as PipAuditEntry[];
  } catch {
    return [];
  }

  if (!Array.isArray(entries)) return [];

  const findings: DependencyFinding[] = [];

  for (const entry of entries) {
    for (const vuln of entry.vulns ?? []) {
      const fixVersion =
        vuln.fix_versions && vuln.fix_versions.length > 0
          ? vuln.fix_versions[vuln.fix_versions.length - 1]
          : 'unknown';

      // Derive severity from ID prefix or default to high
      const severityHint = vuln.id?.toUpperCase() ?? '';
      let severity: Severity = 'high';
      if (severityHint.includes('CRITICAL')) severity = 'critical';

      // Check aliases for CVE
      const cve = vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id;

      findings.push({
        id: nextFindingId(),
        category: 'dependency',
        severity,
        title: `${vuln.id} in ${entry.name}`,
        description:
          `The ${entry.name} package (version ${entry.version}) has a known vulnerability (${vuln.id}). ` +
          (vuln.description
            ? vuln.description.slice(0, 200)
            : `Update to version ${fixVersion !== 'unknown' ? fixVersion : 'the latest safe version'} to fix this.`),
        file: 'requirements.txt',
        line: 0,
        code_snippet: `${entry.name}==${entry.version}`,
        rule_id: `vs-dep-pip-${entry.name}`,
        cve,
        owasp: 'A06:2021 – Vulnerable and Outdated Components',
        fix_suggestion: `Run \`pip install ${entry.name}>=${fixVersion !== 'unknown' ? fixVersion : 'latest'}\` to update.`,
        references: vuln.id.startsWith('PYSEC-')
          ? [`https://osv.dev/vulnerability/${vuln.id}`]
          : cve
            ? [`https://nvd.nist.gov/vuln/detail/${cve}`]
            : [],
        package_name: entry.name,
        installed_version: entry.version,
        patched_version: fixVersion,
        ecosystem: 'pip',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Known-bad-package checker
// ---------------------------------------------------------------------------

/**
 * Compares a semver string against a max-safe boundary.
 * Returns true when `installed` is less than or equal to `maxSafe`.
 * Only handles simple "x.y.z" versions — complex ranges are not supported.
 */
function semverLte(installed: string, maxSafe: string): boolean {
  const parse = (v: string): number[] =>
    v
      .replace(/^[^0-9]*/, '')
      .split('.')
      .map((n) => parseInt(n, 10) || 0);

  const a = parse(installed);
  const b = parse(maxSafe);

  for (let i = 0; i < 3; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai < bi) return true;
    if (ai > bi) return false;
  }
  return true; // equal
}

/**
 * Reads package.json from `repoPath` and checks dependencies against
 * the known-bad-packages list. Returns findings for any matches.
 * Exported for unit testing.
 */
export async function checkKnownBadPackages(repoPath: string): Promise<DependencyFinding[]> {
  let pkgJson: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    const raw = await readFile(join(repoPath, 'package.json'), 'utf-8');
    pkgJson = JSON.parse(raw);
  } catch {
    return [];
  }

  const allDeps: Record<string, string> = {
    ...(pkgJson.dependencies ?? {}),
    ...(pkgJson.devDependencies ?? {}),
  };

  const findings: DependencyFinding[] = [];

  for (const bad of KNOWN_BAD_NPM_PACKAGES) {
    const installedRange = allDeps[bad.name];
    if (!installedRange) continue;

    // Strip range prefixes (^, ~, >=, etc.) to get a bare version
    const bareVersion = installedRange.replace(/^[\^~>=<\s]+/, '');

    // If the installed version looks like a semver and is <= maxSafe, flag it
    if (/^\d+\.\d+\.\d+/.test(bareVersion) && semverLte(bareVersion, bad.maxSafeVersion)) {
      findings.push({
        id: nextFindingId(),
        category: 'dependency',
        severity: bad.severity,
        title: bad.title,
        description: bad.description,
        file: 'package.json',
        line: 0,
        code_snippet: `"${bad.name}": "${installedRange}"`,
        rule_id: `vs-dep-known-${bad.name}`,
        cve: bad.cve,
        owasp: 'A06:2021 – Vulnerable and Outdated Components',
        fix_suggestion: `Update or remove ${bad.name}. Run \`npm install ${bad.name}@latest\` or find a replacement.`,
        references: [`https://nvd.nist.gov/vuln/detail/${bad.cve}`],
        package_name: bad.name,
        installed_version: bareVersion,
        patched_version: `>${bad.maxSafeVersion}`,
        ecosystem: 'npm',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scans dependencies for known vulnerabilities.
 *
 * For Node.js projects:
 * - Runs `npm audit --json` and parses the output
 * - Checks package.json against a known-bad-packages list
 *
 * For Python projects:
 * - Runs `pip-audit --format json` (if available)
 *
 * Handles gracefully: missing npm/pip, non-zero exit codes (normal for npm audit
 * when vulnerabilities are found), and missing manifest files.
 *
 * @param repoPath - Absolute path to the repository root.
 * @param projectTypes - Detected project types to decide which scanners to run.
 * @returns Array of DependencyFinding objects.
 */
export async function scanDependencies(
  repoPath: string,
  projectTypes: ProjectType[],
): Promise<Finding[]> {
  // Reset counter for each scan run
  findingCounter = 0;

  const findings: Finding[] = [];

  // ----- Node.js dependencies -----
  if (projectTypes.includes('nodejs')) {
    // Check that package.json exists
    let hasPackageJson = false;
    try {
      await access(join(repoPath, 'package.json'));
      hasPackageJson = true;
    } catch {
      // No package.json — skip npm audit
    }

    if (hasPackageJson) {
      // Check that npm is available
      const npmAvailable = await commandExists('npm');

      if (npmAvailable) {
        const result = await runCommand('npm', ['audit', '--json'], repoPath);

        // npm audit returns exit code 1 when vulnerabilities are found — that's
        // expected behaviour, not an error. We only skip if stdout is empty
        // (which would indicate a genuine execution failure).
        if (result.stdout.trim().length > 0) {
          findings.push(...parseNpmAuditOutput(result.stdout));
        }
      }

      // Always check known-bad packages (no npm required)
      findings.push(...(await checkKnownBadPackages(repoPath)));
    }
  }

  // ----- Python dependencies -----
  if (projectTypes.includes('python')) {
    const pipAuditAvailable = await commandExists('pip-audit');

    if (pipAuditAvailable) {
      const result = await runCommand('pip-audit', ['--format', 'json'], repoPath);

      if (result.stdout.trim().length > 0) {
        findings.push(...parsePipAuditOutput(result.stdout));
      }
    }
    // If pip-audit is not installed we silently skip — no crash, no findings.
  }

  // Deduplicate: same package + same rule = one finding
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.rule_id}:${(f as DependencyFinding).package_name ?? f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
