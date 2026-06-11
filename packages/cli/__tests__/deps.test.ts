import { mkdtemp, mkdir, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  parseNpmAuditOutput,
  parsePipAuditOutput,
  checkKnownBadPackages,
  scanDependencies,
  runCommand,
} from '../src/scanners/deps.js';
import type { DependencyFinding } from '../src/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vibesafe-deps-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
  );
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// parseNpmAuditOutput
// ---------------------------------------------------------------------------

describe('parseNpmAuditOutput', () => {
  it('parses a minimal npm audit v2 report with one vulnerability', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          severity: 'high',
          via: [
            {
              source: 1065,
              name: 'lodash',
              title: 'Prototype Pollution',
              url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695',
              severity: 'high',
              range: '<4.17.21',
            },
          ],
          fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));

    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('dependency');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('lodash');
    expect(findings[0].title).toContain('Prototype Pollution');
    expect(findings[0].package_name).toBe('lodash');
    expect(findings[0].patched_version).toBe('4.17.21');
    expect(findings[0].ecosystem).toBe('npm');
    expect(findings[0].references).toContain(
      'https://github.com/advisories/GHSA-jf85-cpcp-j695',
    );
    expect(findings[0].owasp).toContain('A06:2021');
  });

  it('parses multiple vulnerabilities in a single report', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          severity: 'high',
          via: [
            {
              source: 1065,
              name: 'lodash',
              title: 'Prototype Pollution',
              url: 'https://github.com/advisories/GHSA-jf85-cpcp-j695',
              severity: 'high',
              range: '<4.17.21',
            },
          ],
          fixAvailable: { name: 'lodash', version: '4.17.21' },
        },
        minimist: {
          name: 'minimist',
          severity: 'critical',
          via: [
            {
              source: 2000,
              name: 'minimist',
              title: 'Prototype Pollution',
              url: 'https://github.com/advisories/GHSA-xvch-5gv4-984h',
              severity: 'critical',
              range: '<1.2.6',
            },
          ],
          fixAvailable: { name: 'minimist', version: '1.2.6' },
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));

    expect(findings).toHaveLength(2);
    const severities = findings.map((f) => f.severity);
    expect(severities).toContain('high');
    expect(severities).toContain('critical');
  });

  it('maps npm "moderate" severity to "medium"', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        axios: {
          name: 'axios',
          severity: 'moderate',
          via: [
            {
              source: 999,
              name: 'axios',
              title: 'Server-Side Request Forgery',
              url: 'https://github.com/advisories/GHSA-test-1234',
              severity: 'moderate',
            },
          ],
          fixAvailable: { name: 'axios', version: '1.6.0' },
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings[0].severity).toBe('medium');
  });

  it('handles transitive vulnerabilities (via is array of strings)', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        'request-promise': {
          name: 'request-promise',
          severity: 'high',
          via: ['request'],
          fixAvailable: false,
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain('request-promise');
  });

  it('returns empty array for malformed JSON', () => {
    const findings = parseNpmAuditOutput('this is not json!!!');
    expect(findings).toEqual([]);
  });

  it('returns empty array for empty vulnerabilities object', () => {
    const report = { auditReportVersion: 2, vulnerabilities: {} };
    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings).toEqual([]);
  });

  it('returns empty array when vulnerabilities key is missing', () => {
    const report = { auditReportVersion: 2 };
    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings).toEqual([]);
  });

  it('includes the GHSA ID as cve when URL contains GHSA-', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        tar: {
          name: 'tar',
          severity: 'high',
          via: [
            {
              source: 500,
              name: 'tar',
              title: 'Arbitrary file write',
              url: 'https://github.com/advisories/GHSA-r628-mhmh-qjhw',
              severity: 'high',
            },
          ],
          fixAvailable: { name: 'tar', version: '6.1.9' },
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings[0].cve).toBe('GHSA-r628-mhmh-qjhw');
  });

  it('generates plain English description mentioning package name', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        jsonwebtoken: {
          name: 'jsonwebtoken',
          severity: 'high',
          via: [
            {
              source: 1234,
              name: 'jsonwebtoken',
              title: 'Unrestricted key type',
              url: 'https://github.com/advisories/GHSA-test',
              severity: 'high',
            },
          ],
          fixAvailable: { name: 'jsonwebtoken', version: '9.0.0' },
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings[0].description).toContain('jsonwebtoken');
    expect(findings[0].description).toContain('9.0.0');
  });

  it('includes fix_suggestion with npm install command', () => {
    const report = {
      auditReportVersion: 2,
      vulnerabilities: {
        express: {
          name: 'express',
          severity: 'low',
          via: [
            {
              source: 42,
              name: 'express',
              title: 'Open Redirect',
              url: 'https://github.com/advisories/GHSA-aaaa',
              severity: 'low',
            },
          ],
          fixAvailable: { name: 'express', version: '4.19.0' },
        },
      },
    };

    const findings = parseNpmAuditOutput(JSON.stringify(report));
    expect(findings[0].fix_suggestion).toContain('npm install express@4.19.0');
  });
});

// ---------------------------------------------------------------------------
// parsePipAuditOutput
// ---------------------------------------------------------------------------

describe('parsePipAuditOutput', () => {
  it('parses a minimal pip-audit report with one vulnerability', () => {
    const report = [
      {
        name: 'django',
        version: '3.2.0',
        vulns: [
          {
            id: 'PYSEC-2023-100',
            fix_versions: ['3.2.20'],
            description: 'SQL injection in Django QuerySet.',
            aliases: ['CVE-2023-12345'],
          },
        ],
      },
    ];

    const findings = parsePipAuditOutput(JSON.stringify(report));

    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('dependency');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('django');
    expect(findings[0].title).toContain('PYSEC-2023-100');
    expect(findings[0].package_name).toBe('django');
    expect(findings[0].installed_version).toBe('3.2.0');
    expect(findings[0].patched_version).toBe('3.2.20');
    expect(findings[0].ecosystem).toBe('pip');
    expect(findings[0].cve).toBe('CVE-2023-12345');
  });

  it('parses multiple packages with multiple vulns', () => {
    const report = [
      {
        name: 'flask',
        version: '1.0',
        vulns: [
          { id: 'PYSEC-2023-1', fix_versions: ['2.0'], description: 'XSS' },
          { id: 'PYSEC-2023-2', fix_versions: ['2.0'], description: 'CSRF' },
        ],
      },
      {
        name: 'requests',
        version: '2.20.0',
        vulns: [
          { id: 'PYSEC-2023-3', fix_versions: ['2.25.0'], description: 'SSRF' },
        ],
      },
    ];

    const findings = parsePipAuditOutput(JSON.stringify(report));
    expect(findings).toHaveLength(3);
  });

  it('returns empty array for malformed JSON', () => {
    expect(parsePipAuditOutput('not json')).toEqual([]);
  });

  it('returns empty array for packages with no vulns', () => {
    const report = [{ name: 'requests', version: '2.31.0', vulns: [] }];
    expect(parsePipAuditOutput(JSON.stringify(report))).toEqual([]);
  });

  it('includes OSV link in references for PYSEC IDs', () => {
    const report = [
      {
        name: 'pillow',
        version: '8.0.0',
        vulns: [{ id: 'PYSEC-2021-500', fix_versions: ['9.0.0'] }],
      },
    ];

    const findings = parsePipAuditOutput(JSON.stringify(report));
    expect(findings[0].references).toContain(
      'https://osv.dev/vulnerability/PYSEC-2021-500',
    );
  });
});

// ---------------------------------------------------------------------------
// checkKnownBadPackages
// ---------------------------------------------------------------------------

describe('checkKnownBadPackages', () => {
  it('flags a known-bad package at a vulnerable version', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { lodash: '4.17.19' },
      }),
    );

    const findings = await checkKnownBadPackages(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].package_name).toBe('lodash');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].cve).toBe('CVE-2021-23337');
    expect(findings[0].description).toContain('lodash');
    expect(findings[0].description).toContain('Prototype Pollution');
  });

  it('does not flag a known-bad package at a safe version', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { lodash: '4.17.21' },
      }),
    );

    const findings = await checkKnownBadPackages(dir);

    expect(findings).toEqual([]);
  });

  it('checks devDependencies as well', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        devDependencies: { minimist: '1.2.5' },
      }),
    );

    const findings = await checkKnownBadPackages(dir);

    expect(findings).toHaveLength(1);
    expect(findings[0].package_name).toBe('minimist');
  });

  it('handles packages with range prefixes (^, ~)', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { 'event-stream': '^3.3.4' },
      }),
    );

    const findings = await checkKnownBadPackages(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0].package_name).toBe('event-stream');
  });

  it('returns empty for a clean package.json', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { express: '4.19.0', react: '18.2.0' },
      }),
    );

    const findings = await checkKnownBadPackages(dir);
    expect(findings).toEqual([]);
  });

  it('returns empty when package.json does not exist', async () => {
    const dir = await createTempDir();

    const findings = await checkKnownBadPackages(dir);
    expect(findings).toEqual([]);
  });

  it('flags multiple known-bad packages', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: {
          'event-stream': '3.3.4',
          colors: '1.4.0',
          faker: '5.5.3',
        },
      }),
    );

    const findings = await checkKnownBadPackages(dir);
    expect(findings).toHaveLength(3);
    const names = findings.map((f) => f.package_name).sort();
    expect(names).toEqual(['colors', 'event-stream', 'faker']);
  });
});

// ---------------------------------------------------------------------------
// scanDependencies (integration-level)
// ---------------------------------------------------------------------------

describe('scanDependencies', () => {
  it('returns empty array for unknown project type', async () => {
    const dir = await createTempDir();
    const findings = await scanDependencies(dir, ['unknown']);
    expect(findings).toEqual([]);
  });

  it('returns empty array for nodejs project with no package.json', async () => {
    const dir = await createTempDir();
    const findings = await scanDependencies(dir, ['nodejs']);
    expect(findings).toEqual([]);
  });

  it('still checks known-bad packages even when npm audit fails', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { 'event-stream': '3.3.4' },
      }),
    );

    // npm audit will likely fail (no node_modules / no lock file) but
    // known-bad-packages check should still run and catch event-stream
    const findings = await scanDependencies(dir, ['nodejs']);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings.some((f) => f.title.includes('event-stream'))).toBe(true);
  });

  it('produces unique finding IDs', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: {
          'event-stream': '3.3.4',
          lodash: '4.17.19',
        },
      }),
    );

    const findings = await scanDependencies(dir, ['nodejs']);
    const ids = findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('all findings have category "dependency"', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { lodash: '4.17.19' },
      }),
    );

    const findings = await scanDependencies(dir, ['nodejs']);
    for (const f of findings) {
      expect(f.category).toBe('dependency');
    }
  });

  it('findings include DependencyFinding fields', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { lodash: '4.17.19' },
      }),
    );

    const findings = await scanDependencies(dir, ['nodejs']);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const f = findings[0] as DependencyFinding;
    expect(f.package_name).toBeDefined();
    expect(f.installed_version).toBeDefined();
    expect(f.patched_version).toBeDefined();
    expect(f.ecosystem).toBeDefined();
  });

  it('deduplicates findings with same rule_id and package_name', async () => {
    // If npm audit and known-bad both find lodash, should only appear once
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        dependencies: { lodash: '4.17.19' },
      }),
    );

    const findings = await scanDependencies(dir, ['nodejs']);
    const lodashFindings = findings.filter((f) =>
      f.title.toLowerCase().includes('lodash'),
    );
    // Should be at least 1 but each rule_id:package combo should be unique
    const keys = lodashFindings.map(
      (f) => `${f.rule_id}:${(f as DependencyFinding).package_name}`,
    );
    expect(new Set(keys).size).toBe(keys.length);
  });
});

// ---------------------------------------------------------------------------
// runCommand helper
// ---------------------------------------------------------------------------

describe('runCommand', () => {
  it('captures stdout from a successful command', async () => {
    const result = await runCommand('echo', ['hello world'], '.');
    expect(result.stdout.trim()).toBe('hello world');
    expect(result.exitCode).toBe(0);
  });

  it('returns non-zero exit code without throwing', async () => {
    const result = await runCommand('node', ['-e', 'process.exit(42)'], '.');
    expect(result.exitCode).not.toBe(0);
  });

  it('handles command not found without throwing', async () => {
    const result = await runCommand('__vibesafe_nonexistent_cmd__', [], '.');
    expect(result.exitCode).not.toBe(0);
  });
});
