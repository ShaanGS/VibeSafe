import { mkdtemp, mkdir, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { runFallbackRegexRules, parseSemgrepOutput } from '../src/scanners/sast.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vibesafe-sast-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
  );
});

// ---------------------------------------------------------------------------
// Fallback regex rules — eval()
// ---------------------------------------------------------------------------

describe('fallback regex rules', () => {
  it('detects eval() in a JS file with severity high', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'danger.js'),
      `const result = eval(userInput);\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const evalFinding = findings.find((f) => f.rule_id === 'vs-sast-eval');
    expect(evalFinding).toBeDefined();
    expect(evalFinding!.severity).toBe('high');
    expect(evalFinding!.category).toBe('sast');
    expect(evalFinding!.file).toBe('danger.js');
    expect(evalFinding!.line).toBe(1);
    expect(evalFinding!.owasp).toContain('A03:2021');
  });

  // -----------------------------------------------------------------------
  // innerHTML
  // -----------------------------------------------------------------------

  it('detects innerHTML assignment', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'component.ts'),
      `element.innerHTML = userContent;\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const xssFinding = findings.find((f) => f.rule_id === 'vs-sast-xss-innerhtml');
    expect(xssFinding).toBeDefined();
    expect(xssFinding!.severity).toBe('high');
    expect(xssFinding!.title).toContain('innerHTML');
  });

  // -----------------------------------------------------------------------
  // Math.random()
  // -----------------------------------------------------------------------

  it('detects Math.random() with severity medium', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'token.js'),
      `const token = Math.random().toString(36);\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const randomFinding = findings.find((f) => f.rule_id === 'vs-sast-insecure-random');
    expect(randomFinding).toBeDefined();
    expect(randomFinding!.severity).toBe('medium');
  });

  // -----------------------------------------------------------------------
  // SQL injection
  // -----------------------------------------------------------------------

  it('detects SQL injection via template literal', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'db.ts'),
      'const q = `SELECT * FROM users WHERE id = ${req.params.id}`;\n',
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const sqliFinding = findings.find((f) => f.rule_id === 'vs-sast-sqli');
    expect(sqliFinding).toBeDefined();
    expect(sqliFinding!.severity).toBe('high');
  });

  // -----------------------------------------------------------------------
  // Command injection
  // -----------------------------------------------------------------------

  it('detects exec() as command injection', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'run.js'),
      `const { exec } = require("child_process");\nexec("rm -rf " + userPath);\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const cmdFinding = findings.find((f) => f.rule_id === 'vs-sast-cmd-injection');
    expect(cmdFinding).toBeDefined();
    expect(cmdFinding!.severity).toBe('high');
  });

  // -----------------------------------------------------------------------
  // Broken auth
  // -----------------------------------------------------------------------

  it('detects route without auth middleware', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'routes.js'),
      `app.get("/admin", async (req, res) => { res.json({ secret: true }); });\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const authFinding = findings.find((f) => f.rule_id === 'vs-sast-no-auth');
    expect(authFinding).toBeDefined();
    expect(authFinding!.severity).toBe('medium');
  });

  // -----------------------------------------------------------------------
  // Python SQL injection
  // -----------------------------------------------------------------------

  it('detects Python f-string SQL injection', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'db.py'),
      `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const sqliFinding = findings.find((f) => f.rule_id === 'vs-sast-sqli-python');
    expect(sqliFinding).toBeDefined();
    expect(sqliFinding!.severity).toBe('high');
  });

  // -----------------------------------------------------------------------
  // Hardcoded JWT secret
  // -----------------------------------------------------------------------

  it('detects hardcoded JWT signing secret', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'auth.ts'),
      `const token = jwt.sign(payload, "mysupersecretkey123");\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);

    expect(findings.length).toBeGreaterThanOrEqual(1);
    const jwtFinding = findings.find((f) => f.rule_id === 'vs-sast-hardcoded-jwt');
    expect(jwtFinding).toBeDefined();
    expect(jwtFinding!.severity).toBe('critical');
  });

  // -----------------------------------------------------------------------
  // Clean / edge cases
  // -----------------------------------------------------------------------

  it('returns 0 findings for a clean JS file', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'clean.js'),
      `const x = 1 + 2;\nconsole.log("Hello, world!");\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings).toEqual([]);
  });

  it('does not scan .json files (only relevant extensions)', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'data.json'),
      `{"query": "eval(something)", "innerHTML": "danger"}\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings).toEqual([]);
  });

  it('does not scan .md files', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'README.md'),
      `\`\`\`js\neval(foo)\n\`\`\`\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings).toEqual([]);
  });

  it('returns 0 findings for an empty directory', async () => {
    const dir = await createTempDir();
    const findings = await runFallbackRegexRules(dir, []);
    expect(findings).toEqual([]);
  });

  it('respects ignore patterns', async () => {
    const dir = await createTempDir();
    await mkdir(join(dir, 'node_modules'));
    await writeFile(
      join(dir, 'node_modules', 'bad.js'),
      `eval(something);\n`,
    );

    const findings = await runFallbackRegexRules(dir, ['node_modules/']);
    expect(findings).toEqual([]);
  });

  it('scans files in subdirectories recursively', async () => {
    const dir = await createTempDir();
    await mkdir(join(dir, 'src', 'utils'), { recursive: true });
    await writeFile(
      join(dir, 'src', 'utils', 'deep.js'),
      `eval(userInput);\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].file).toBe('src/utils/deep.js');
  });

  it('generates unique finding IDs', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'multi.js'),
      [
        'eval(x);',
        'element.innerHTML = y;',
        'const r = Math.random();',
      ].join('\n') + '\n',
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings.length).toBeGreaterThanOrEqual(3);
    const ids = findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('finding has all required fields', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'test.js'),
      `eval(userInput);\n`,
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const f = findings[0];
    expect(f.id).toMatch(/^vs-sast-\d{3}$/);
    expect(f.category).toBe('sast');
    expect(f.severity).toBeDefined();
    expect(f.title).toBeDefined();
    expect(f.description).toBeDefined();
    expect(f.file).toBeDefined();
    expect(f.line).toBeGreaterThan(0);
    expect(f.code_snippet).toBeDefined();
    expect(f.rule_id).toBeDefined();
    expect(f.owasp).toBeDefined();
    expect(f.fix_suggestion).toBeDefined();
    expect(f.references).toBeInstanceOf(Array);
  });

  it('detects multiple issues on different lines of the same file', async () => {
    const dir = await createTempDir();
    await writeFile(
      join(dir, 'mixed.js'),
      [
        'const a = eval(x);',
        'const b = 2;',
        'div.innerHTML = c;',
      ].join('\n') + '\n',
    );

    const findings = await runFallbackRegexRules(dir, []);
    expect(findings.length).toBeGreaterThanOrEqual(2);

    const rules = findings.map((f) => f.rule_id);
    expect(rules).toContain('vs-sast-eval');
    expect(rules).toContain('vs-sast-xss-innerhtml');
  });
});

// ---------------------------------------------------------------------------
// parseSemgrepOutput
// ---------------------------------------------------------------------------

describe('parseSemgrepOutput', () => {
  it('parses a minimal semgrep JSON result', () => {
    const output = {
      results: [
        {
          check_id: 'javascript.express.security.audit.xss.mustache-escape',
          path: 'src/app.js',
          start: { line: 42, col: 5 },
          end: { line: 42, col: 50 },
          extra: {
            message: 'User input flows into HTML without escaping',
            severity: 'WARNING',
            lines: '  res.send("<div>" + req.query.name + "</div>");',
            metadata: {
              owasp: ['A03:2021 – Injection'],
              cwe: ['CWE-79'],
              references: ['https://owasp.org/Top10/A03_2021-Injection/'],
            },
          },
        },
      ],
    };

    const findings = parseSemgrepOutput(JSON.stringify(output));

    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('sast');
    expect(findings[0].severity).toBe('medium'); // WARNING → medium
    expect(findings[0].file).toBe('src/app.js');
    expect(findings[0].line).toBe(42);
    expect(findings[0].owasp).toContain('A03:2021');
    expect(findings[0].references).toContain('https://owasp.org/Top10/A03_2021-Injection/');
  });

  it('maps ERROR severity to high', () => {
    const output = {
      results: [
        {
          check_id: 'test-rule',
          path: 'file.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: { severity: 'ERROR', message: 'test' },
        },
      ],
    };

    const findings = parseSemgrepOutput(JSON.stringify(output));
    expect(findings[0].severity).toBe('high');
  });

  it('maps INFO severity to low', () => {
    const output = {
      results: [
        {
          check_id: 'info-rule',
          path: 'file.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: { severity: 'INFO', message: 'informational' },
        },
      ],
    };

    const findings = parseSemgrepOutput(JSON.stringify(output));
    expect(findings[0].severity).toBe('low');
  });

  it('returns empty for malformed JSON', () => {
    expect(parseSemgrepOutput('not json')).toEqual([]);
  });

  it('returns empty when results array is missing', () => {
    expect(parseSemgrepOutput(JSON.stringify({ errors: [] }))).toEqual([]);
  });

  it('handles multiple results', () => {
    const output = {
      results: [
        {
          check_id: 'rule-a',
          path: 'a.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: { severity: 'ERROR', message: 'issue A' },
        },
        {
          check_id: 'rule-b',
          path: 'b.js',
          start: { line: 5, col: 1 },
          end: { line: 5, col: 20 },
          extra: { severity: 'WARNING', message: 'issue B' },
        },
      ],
    };

    const findings = parseSemgrepOutput(JSON.stringify(output));
    expect(findings).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// scanSAST integration (no semgrep installed → fallback)
// ---------------------------------------------------------------------------

describe('scanSAST — semgrep not installed fallback', () => {
  // We can't guarantee semgrep IS installed in CI, but we CAN test that the
  // function doesn't crash and falls back to regex rules.

  it('does not crash when semgrep is not installed', async () => {
    const { scanSAST } = await import('../src/scanners/sast.js');
    const dir = await createTempDir();
    await writeFile(join(dir, 'app.js'), `eval(x);\n`);

    // Should not throw — falls back to regex rules
    const findings = await scanSAST(dir, []);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule_id).toBe('vs-sast-eval');
  });
});
