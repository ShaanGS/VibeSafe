import type { Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Regex rule definition
// ---------------------------------------------------------------------------

/**
 * A lightweight regex-based SAST rule used as fallback when Semgrep is not
 * installed.  Each rule targets specific file extensions and maps to an
 * OWASP category.
 */
export interface RegexRule {
  /** Unique rule identifier. */
  id: string;
  /** Short title shown in terminal output. */
  title: string;
  /** The regex pattern applied per-line to matching files. */
  pattern: RegExp;
  /** File extensions this rule applies to (e.g. ['.ts', '.js']). */
  fileTypes: string[];
  /** Finding severity. */
  severity: Severity;
  /** OWASP Top 10 reference. */
  owasp: string;
  /** Plain-English explanation of why this is dangerous. */
  description: string;
  /** One-liner fix suggestion. */
  fixSuggestion: string;
  /** External reference links. */
  references: string[];
}

// ---------------------------------------------------------------------------
// Built-in fallback rules
// ---------------------------------------------------------------------------

export const FALLBACK_REGEX_RULES: RegexRule[] = [
  // 1. SQL Injection (JS/TS)
  {
    id: 'vs-sast-sqli',
    title: 'SQL Injection',
    pattern: /['"`]\s*\+\s*\w+|query\s*\+\s*|`SELECT.*\$\{/i,
    fileTypes: ['.ts', '.js', '.py'],
    severity: 'high',
    owasp: 'A03:2021 – Injection',
    description:
      'Your code builds a database query by directly inserting a variable into the query string. ' +
      'An attacker can type something like "\'; DROP TABLE users;--" into the input field and ' +
      'delete your entire database.',
    fixSuggestion:
      'Use parameterised queries — pass user input as a separate argument, never as part of the query string.',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },

  // 2. XSS — innerHTML
  {
    id: 'vs-sast-xss-innerhtml',
    title: 'XSS — dangerous innerHTML assignment',
    pattern: /\.innerHTML\s*=/,
    fileTypes: ['.ts', '.js'],
    severity: 'high',
    owasp: 'A03:2021 – Injection',
    description:
      'Setting innerHTML directly injects raw HTML into the page. If any part of that HTML comes ' +
      'from user input, an attacker can inject a <script> tag and steal cookies, tokens, or redirect users.',
    fixSuggestion:
      'Use textContent instead of innerHTML, or sanitise the HTML with a library like DOMPurify.',
    references: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations',
    ],
  },

  // 3. eval() usage
  {
    id: 'vs-sast-eval',
    title: 'Dangerous eval() usage',
    pattern: /\beval\s*\(/,
    fileTypes: ['.ts', '.js'],
    severity: 'high',
    owasp: 'A03:2021 – Injection',
    description:
      'eval() executes arbitrary JavaScript code at runtime. If an attacker can control the string ' +
      'passed to eval, they can run any code they want in your application — steal data, modify the ' +
      'page, or take over sessions.',
    fixSuggestion:
      'Remove eval() and use JSON.parse() for data, or a safe alternative for dynamic logic.',
    references: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!',
    ],
  },

  // 4. Broken auth — unprotected route
  {
    id: 'vs-sast-no-auth',
    title: 'Potentially unprotected route (no auth middleware)',
    pattern: /app\.(get|post|put|delete)\s*\([^)]*,\s*async?\s*\(/,
    fileTypes: ['.ts', '.js'],
    severity: 'medium',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    description:
      'This Express route handler does not appear to have authentication middleware. ' +
      'Anyone on the internet can call this endpoint without logging in.',
    fixSuggestion:
      'Add an authentication middleware before the route handler, e.g. app.get("/path", authMiddleware, async (req, res) => { ... }).',
    references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
  },

  // 5. Command injection
  {
    id: 'vs-sast-cmd-injection',
    title: 'Potential command injection',
    pattern: /exec\s*\(|execSync\s*\(|spawn\s*\(/,
    fileTypes: ['.ts', '.js'],
    severity: 'high',
    owasp: 'A03:2021 – Injection',
    description:
      'Functions like exec(), execSync(), and spawn() run shell commands. If user input flows ' +
      'into these functions, an attacker can inject arbitrary commands and take over your server.',
    fixSuggestion:
      'Use execFile() or spawn() with an argument array (no shell) instead, and never interpolate user input into command strings.',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },

  // 6. Python SQL injection
  {
    id: 'vs-sast-sqli-python',
    title: 'SQL Injection (Python)',
    pattern: /execute\s*\(\s*f["']|execute\s*\(\s*["'].*%\s*\w/,
    fileTypes: ['.py'],
    severity: 'high',
    owasp: 'A03:2021 – Injection',
    description:
      'Your Python code builds a SQL query using an f-string or %-formatting with user data. ' +
      'An attacker can inject malicious SQL and read, modify, or delete your database.',
    fixSuggestion:
      'Use parameterised queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)).',
    references: ['https://owasp.org/Top10/A03_2021-Injection/'],
  },

  // 7. Insecure random
  {
    id: 'vs-sast-insecure-random',
    title: 'Insecure random number generator',
    pattern: /Math\.random\s*\(\)/,
    fileTypes: ['.ts', '.js'],
    severity: 'medium',
    owasp: 'A02:2021 – Cryptographic Failures',
    description:
      'Math.random() is not cryptographically secure. If you use it to generate tokens, ' +
      'session IDs, or passwords, an attacker may be able to predict the values.',
    fixSuggestion:
      'Use crypto.randomUUID() or crypto.getRandomValues() for security-sensitive randomness.',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues',
    ],
  },

  // 8. Hardcoded JWT secret
  {
    id: 'vs-sast-hardcoded-jwt',
    title: 'Hardcoded JWT signing secret',
    pattern: /jwt\.sign\s*\([^)]*,\s*["'][^"']{8,}["']/,
    fileTypes: ['.ts', '.js'],
    severity: 'critical',
    owasp: 'A02:2021 – Cryptographic Failures',
    description:
      'The secret used to sign JWTs is hardcoded in source code. Anyone who reads this file ' +
      'can forge valid tokens, bypassing all authentication.',
    fixSuggestion:
      'Move the JWT secret to an environment variable: jwt.sign(payload, process.env.JWT_SECRET).',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
];
