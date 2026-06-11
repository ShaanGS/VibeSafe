import { readdir, readFile, stat } from 'fs/promises';
import { join, relative, extname } from 'path';
import type { Finding } from '../types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum file size to scan (1 MB). */
const MAX_FILE_SIZE = 1_048_576;

/** Extensions treated as binary — never scanned. */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pyc', '.class', '.jar',
  '.lock',
]);

/** Words that signal a line is an example/placeholder — skip these matches. */
const PLACEHOLDER_WORDS = ['example', 'placeholder', 'fake', 'test', 'dummy', 'sample', 'xxx', 'your_'];

// ---------------------------------------------------------------------------
// Secret patterns
// ---------------------------------------------------------------------------

interface SecretPattern {
  /** Human-readable name shown in findings. */
  name: string;
  /** Regex applied per-line. Must contain a capture group (group 1) for the secret value. */
  regex: RegExp;
  /** Severity — secrets are almost always critical. */
  severity: 'critical' | 'high';
  /** Rule ID for deduplication. */
  ruleId: string;
  /** Plain English description template. Use `{value}` for the redacted key. */
  description: string;
  /** Optional OWASP reference. */
  owasp?: string;
  /** External reference links. */
  references: string[];
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'OpenAI API Key',
    regex: /(sk-[A-Za-z0-9]{20,})/,
    severity: 'critical',
    ruleId: 'vs-secret-openai',
    description:
      'Your OpenAI API key is hardcoded. Anyone with access to this repo can use your API key and rack up charges on your account.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'Anthropic API Key',
    regex: /(sk-ant-[A-Za-z0-9\-]{20,})/,
    severity: 'critical',
    ruleId: 'vs-secret-anthropic',
    description:
      'Your Anthropic API key is hardcoded. Anyone who finds this repo can use your key and run up your bill.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'AWS Access Key',
    regex: /(AKIA[0-9A-Z]{16})/,
    severity: 'critical',
    ruleId: 'vs-secret-aws',
    description:
      'An AWS access key is hardcoded. Attackers can use this to access your AWS account, spin up resources, and steal data.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
    ],
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /(ghp_[A-Za-z0-9]{36})/,
    severity: 'critical',
    ruleId: 'vs-secret-github-pat',
    description:
      'A GitHub personal access token is hardcoded. Anyone with this token can access your repositories and potentially push malicious code.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'GitHub Fine-Grained Token',
    regex: /(github_pat_[A-Za-z0-9_]{20,})/,
    severity: 'critical',
    ruleId: 'vs-secret-github-fine',
    description:
      'A GitHub fine-grained personal access token is hardcoded. This grants scoped access to your GitHub resources and must be kept secret.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'Stripe Secret Key',
    regex: /(sk_live_[A-Za-z0-9]{20,})/,
    severity: 'critical',
    ruleId: 'vs-secret-stripe',
    description:
      'Your Stripe live secret key is hardcoded. Attackers can use this to issue refunds, access customer payment data, or transfer funds.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://stripe.com/docs/keys',
    ],
  },
  {
    name: 'Supabase Service-Role Key',
    regex: /(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/,
    severity: 'critical',
    ruleId: 'vs-secret-supabase-jwt',
    description:
      'A Supabase JWT (likely a service-role key) is hardcoded. This key bypasses Row Level Security and gives full database access.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://supabase.com/docs/guides/auth/jwts',
    ],
  },
  {
    name: 'Generic Hardcoded Password',
    regex: /(?:["']?(?:password|passwd|pwd)["']?)\s*[:=]\s*["']([^"']{8,})["']/i,
    severity: 'high',
    ruleId: 'vs-secret-password',
    description:
      'A password is hardcoded in your source code. Move it to an environment variable and load it at runtime with process.env.',
    owasp: 'A07:2021 – Identification and Authentication Failures',
    references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
  },
  {
    name: 'Generic Hardcoded Secret',
    regex: /(?:["']?(?:secret|api_secret|app_secret)["']?)\s*[:=]\s*["']([^"']{8,})["']/i,
    severity: 'high',
    ruleId: 'vs-secret-generic-secret',
    description:
      'A secret value is hardcoded in your source code. Anyone with access to this file can read it. Use an environment variable instead.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'Generic Hardcoded API Key',
    regex: /(?:["']?(?:api_key|apikey|api-key)["']?)\s*[:=]\s*["']([^"']{8,})["']/i,
    severity: 'high',
    ruleId: 'vs-secret-generic-apikey',
    description:
      'An API key is hardcoded in your source code. Move it to a .env file, add .env to .gitignore, and load it via process.env.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'Google API Key',
    regex: /(AIza[0-9A-Za-z_-]{35})/,
    severity: 'high',
    ruleId: 'vs-secret-google',
    description:
      'A Google API key is hardcoded. Depending on its scope, attackers could access Google Cloud services, Maps, or other APIs on your account.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'Slack Webhook URL',
    regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/,
    severity: 'high',
    ruleId: 'vs-secret-slack-webhook',
    description:
      'A Slack webhook URL is hardcoded. Anyone with this URL can post messages to your Slack channel.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
  {
    name: 'Private Key',
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/,
    severity: 'critical',
    ruleId: 'vs-secret-private-key',
    description:
      'A private key is embedded in this file. Private keys must never be committed to source control — anyone who finds this can impersonate your server or decrypt traffic.',
    owasp: 'A02:2021 – Cryptographic Failures',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  },
];

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

/**
 * Calculates the Shannon entropy (bits per character) of a string.
 * High entropy strings (> 4.5 bits/char) look random and are likely tokens.
 */
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/** Minimum entropy (bits/char) to flag a token-like string. */
const MIN_ENTROPY = 4.5;
/** Minimum length for a token candidate. */
const MIN_TOKEN_LENGTH = 20;

/**
 * Regex to capture strings that look like tokens/keys — long alphanumeric+symbols.
 * Matches quoted strings and bare assignment values.
 */
const TOKEN_CANDIDATE_RE = /["']([A-Za-z0-9+/=_\-]{20,})["']/g;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Redacts a secret value: shows first 8 characters, masks the rest.
 */
function redact(value: string): string {
  if (value.length <= 12) {
    return value.slice(0, 4) + '****';
  }
  return value.slice(0, 8) + '****';
}

/**
 * Redacts the secret value in a full line of code for display.
 */
function redactLine(line: string, secretValue: string): string {
  return line.replace(secretValue, redact(secretValue));
}

/**
 * Returns true if a line is a comment containing a placeholder keyword.
 * Per PRD: "Skip lines that are comments containing 'example', 'placeholder', 'fake', 'test'."
 * Only comments are skipped — real code with these words in variable names is still scanned.
 */
function isPlaceholderComment(line: string): boolean {
  const trimmed = line.trim().toLowerCase();
  // Must start with a comment marker to be considered a skip-able line
  const isComment =
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*');

  if (!isComment) return false;

  return PLACEHOLDER_WORDS.some((word) => trimmed.includes(word));
}

/**
 * Returns true if a file path should be ignored, based on the ignore patterns.
 * Supports both directory patterns (ending with /) and glob-style filename patterns.
 */
function shouldIgnoreFile(filePath: string, ignorePatterns: string[]): boolean {
  for (const pattern of ignorePatterns) {
    if (pattern.endsWith('/')) {
      // Directory pattern: check if any segment matches
      const dirName = pattern.slice(0, -1);
      if (filePath.includes(`/${dirName}/`) || filePath.startsWith(`${dirName}/`)) {
        return true;
      }
    } else if (pattern.startsWith('*.')) {
      // Extension pattern: *.lock, *.min.js etc.
      const ext = pattern.slice(1); // e.g. ".lock"
      if (filePath.endsWith(ext)) {
        return true;
      }
    } else {
      // Exact filename or path segment match
      if (filePath === pattern || filePath.includes(`/${pattern}`) || filePath.startsWith(`${pattern}`)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Recursively walks a directory, yielding absolute paths of all regular files.
 * Skips directories that match ignore patterns and binary extensions.
 */
async function* walkFiles(
  dirPath: string,
  rootPath: string,
  ignorePatterns: string[],
): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dirPath, { withFileTypes: true });
  } catch {
    return; // Permission denied or not a directory — skip silently
  }

  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name);
    const relPath = relative(rootPath, fullPath);

    if (entry.isDirectory()) {
      // Check if directory should be ignored
      if (shouldIgnoreFile(relPath + '/', ignorePatterns)) {
        continue;
      }
      yield* walkFiles(fullPath, rootPath, ignorePatterns);
    } else if (entry.isFile()) {
      // Skip binary extensions
      if (BINARY_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        continue;
      }
      // Skip ignored files
      if (shouldIgnoreFile(relPath, ignorePatterns)) {
        continue;
      }
      yield fullPath;
    }
  }
}

// ---------------------------------------------------------------------------
// Finding counter — unique IDs
// ---------------------------------------------------------------------------

let findingCounter = 0;

function nextFindingId(): string {
  findingCounter += 1;
  return `vs-sec-${String(findingCounter).padStart(3, '0')}`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scans repository files for hardcoded secrets and high-entropy tokens.
 *
 * The scanner:
 * 1. Walks all files in the repo (respecting ignore patterns)
 * 2. Checks each line against regex patterns for known API keys/tokens
 * 3. Runs Shannon entropy checks on strings that look like tokens
 * 4. Skips binary files, files > 1 MB, and placeholder/example comments
 *
 * @param repoPath - Absolute path to the repository root.
 * @param ignorePatterns - Glob patterns for files/directories to skip.
 * @returns Array of Finding objects for detected secrets.
 */
export async function scanSecrets(
  repoPath: string,
  ignorePatterns: string[],
): Promise<Finding[]> {
  // Reset counter for each scan run
  findingCounter = 0;

  const findings: Finding[] = [];
  /** Track already-reported locations to avoid duplicates. */
  const seen = new Set<string>();

  for await (const filePath of walkFiles(repoPath, repoPath, ignorePatterns)) {
    // Skip files larger than 1 MB
    let fileStat;
    try {
      fileStat = await stat(filePath);
    } catch {
      continue;
    }
    if (fileStat.size > MAX_FILE_SIZE) {
      continue;
    }

    // Read file content
    let content: string;
    try {
      content = await readFile(filePath, 'utf-8');
    } catch {
      continue; // Can't read (binary/encoding issue) — skip
    }

    // Quick binary heuristic: if the file contains null bytes, skip it
    if (content.includes('\0')) {
      continue;
    }

    const relFile = relative(repoPath, filePath);
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Skip placeholder/example lines
      if (isPlaceholderComment(line)) {
        continue;
      }

      // --- Regex pattern matching ---
      for (const pattern of SECRET_PATTERNS) {
        const match = pattern.regex.exec(line);
        if (!match) continue;

        const secretValue = match[1];
        const key = `${relFile}:${lineNum}:${pattern.ruleId}`;

        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          id: nextFindingId(),
          category: 'secret',
          severity: pattern.severity,
          title: pattern.name,
          description: pattern.description,
          file: relFile,
          line: lineNum,
          column: match.index + 1,
          code_snippet: redactLine(line.trimEnd(), secretValue),
          rule_id: pattern.ruleId,
          owasp: pattern.owasp,
          fix_suggestion:
            'Move this secret to a .env file, add .env to .gitignore, and load it via environment variables (e.g. process.env.YOUR_KEY).',
          references: pattern.references,
        });
      }

      // --- Shannon entropy check for token-like strings ---
      let tokenMatch: RegExpExecArray | null;
      TOKEN_CANDIDATE_RE.lastIndex = 0; // Reset stateful regex
      while ((tokenMatch = TOKEN_CANDIDATE_RE.exec(line)) !== null) {
        const candidate = tokenMatch[1];

        // Skip if too short or already caught by a regex pattern
        if (candidate.length < MIN_TOKEN_LENGTH) continue;

        const entropy = shannonEntropy(candidate);
        if (entropy < MIN_ENTROPY) continue;

        const entropyKey = `${relFile}:${lineNum}:entropy`;
        if (seen.has(entropyKey)) continue;

        // Make sure it wasn't already caught by a named pattern above
        const alreadyCaught = SECRET_PATTERNS.some((p) => p.regex.test(candidate));
        if (alreadyCaught) continue;

        seen.add(entropyKey);

        findings.push({
          id: nextFindingId(),
          category: 'secret',
          severity: 'high',
          title: 'High-Entropy Secret / Token',
          description:
            'This string has unusually high randomness (entropy) and looks like a secret token or API key. If this is a real credential, move it to an environment variable.',
          file: relFile,
          line: lineNum,
          column: tokenMatch.index + 1,
          code_snippet: redactLine(line.trimEnd(), candidate),
          rule_id: 'vs-secret-entropy',
          owasp: 'A02:2021 – Cryptographic Failures',
          fix_suggestion:
            'Move this value to a .env file, add .env to .gitignore, and reference it via environment variables.',
          references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
        });
      }
    }
  }

  return findings;
}
