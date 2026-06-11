# VibeSafe — Complete PRD, Architecture & Cursor Build Plan

> Security co-pilot for vibe-coded and AI-generated apps.  
> One command. Plain English. Auto-fix PR.

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [User Personas](#2-user-personas)
3. [Core User Story](#3-core-user-story)
4. [Feature Specification](#4-feature-specification)
5. [Technical Architecture](#5-technical-architecture)
6. [Monorepo Structure](#6-monorepo-structure)
7. [Data Models](#7-data-models)
8. [CLI Design & UX](#8-cli-design--ux)
9. [GitHub Action Design](#9-github-action-design)
10. [LLM Fix Generation Pipeline](#10-llm-fix-generation-pipeline)
11. [API Server](#11-api-server)
12. [Safety Score Algorithm](#12-safety-score-algorithm)
13. [README & GitHub Strategy](#13-readme--github-strategy)
14. [Cursor Prompting Plan](#14-cursor-prompting-plan)
15. [Build Order (Sprint Plan)](#15-build-order-sprint-plan)
16. [Environment Variables](#16-environment-variables)
17. [Open Source Launch Checklist](#17-open-source-launch-checklist)

---

## 1. Product Overview

### What it is

VibeSafe is a CLI tool and GitHub Action that scans any vibe-coded or AI-generated repository for:

- OWASP Top 10 vulnerabilities (SQL injection, XSS, broken auth, etc.)
- Hardcoded secrets and API keys
- Outdated/vulnerable dependencies
- Misconfigured infrastructure files

And then:

- Explains every finding in plain English (no security jargon)
- Generates a concrete fix using an LLM that reads your actual code
- Opens a GitHub PR with the fix automatically
- Produces a Safety Score (0–100) you can put in your README

### One-line pitch

`npx vibesafe scan` — know if your app is safe to ship in under 5 minutes.

### Who it is NOT for

Enterprise security teams. They have SonarQube, Snyk, Wiz. VibeSafe is for the solo founder who shipped on Lovable last night and has zero security knowledge.

---

## 2. User Personas

### Primary: The Vibe Coder
- Built their MVP with Cursor, Lovable, v0, or Bolt
- Zero formal security training
- Ships fast, worries about security only after something breaks
- Pain: doesn't know what they don't know

### Secondary: The Hackathon Team
- 2–4 people, 24–48 hours, ships something real
- Nobody reviews code for security
- Pain: gets roasted at demo day or worse, leaves secrets in a public repo

### Tertiary: The BTech/CS Student
- Building projects for placement or startup
- May have enterprise clients or internship evaluations
- Pain: needs a badge/certificate showing they care about security

---

## 3. Core User Story

```
As a solo founder who just shipped my MVP with Cursor/Lovable,
I want to run a single command that scans my repo for security issues,
explains them in plain English,
and opens a PR with the fixes already written,
so I can ship with confidence without becoming a security expert.
```

**Acceptance Criteria:**

- `npx vibesafe scan` works with zero config on any Node.js, Python, or full-stack repo
- Output appears in the terminal within 60 seconds for repos under 50k LOC
- Each finding has: severity, file+line, plain English explanation, concrete fix suggestion
- A Safety Score (0–100) is printed at the end
- `vibesafe fix` creates a real GitHub PR with LLM-generated code patches

---

## 4. Feature Specification

### MVP (v0.1 — GitHub launch, star-grinding phase)

| Feature | Description | Priority |
|---|---|---|
| `vibesafe scan` | CLI scan with SAST + secrets + deps | P0 |
| Safety Score | 0–100 score with breakdown | P0 |
| Plain English output | Each finding explained in non-jargon | P0 |
| `vibesafe fix` (dry run) | Shows what fixes would be applied | P0 |
| JSON output mode | `--json` flag for CI integration | P1 |
| `.vibesafeignore` | Ignore file patterns | P1 |
| Config file | `vibesafe.config.js` for custom rules | P1 |

### v0.2 — Auto-fix PR (monetization hook)

| Feature | Description |
|---|---|
| `vibesafe fix --pr` | LLM reads code, writes fix, opens GitHub PR |
| GitHub token support | Uses `GITHUB_TOKEN` from env |
| Fix explanation | PR description explains what was changed and why |

### v0.3 — GitHub Action + CI gate

| Feature | Description |
|---|---|
| `vibesafe.yml` action | Runs on every PR |
| Blocking mode | Fails CI if critical vulns found |
| Summary comment | Posts scan results as PR comment |
| README badge | `![VibeSafe](badge-url)` for star-bait |

### v0.4 — Dashboard (SaaS conversion point)

| Feature | Description |
|---|---|
| Web dashboard | vibesafe.dev — history, trends, team view |
| Repo health over time | Track score improvement |
| Team plan | Multiple repos, Slack notifications |

---

## 5. Technical Architecture

### High-level overview

```
User's repo
    │
    ▼
vibesafe scan (CLI)
    │
    ├── Layer 1: SAST Engine
    │       └── Semgrep (via @semgrep/semgrep-js or semgrep binary)
    │           Custom rules for AI-generated code patterns
    │
    ├── Layer 2: Secrets Scanner
    │       └── Custom regex patterns + entropy detection
    │           Covers: API keys, tokens, connection strings, JWTs
    │
    ├── Layer 3: Dependency Scanner
    │       ├── npm audit (Node.js)
    │       ├── pip-audit (Python)
    │       └── CVE database lookup via OSV.dev API (free)
    │
    └── Layer 4: LLM Fix Engine (vibesafe fix)
            └── Groq (fast, free tier) / OpenAI fallback
                Reads actual file content
                Outputs patch + explanation
                Opens PR via GitHub API
```

### What runs where

| Component | Runtime | Why |
|---|---|---|
| CLI (`vibesafe`) | Node.js 18+ | npm installable, cross-platform |
| SAST | Semgrep binary (spawned subprocess) | Best-in-class rules, free |
| Secrets scan | Pure JS/TS (built-in) | Zero deps, fast |
| Dep scan | npm audit / pip-audit subprocess | Native tools, authoritative |
| LLM fix | HTTP to Groq/OpenAI API | No model hosting needed |
| GitHub PR | GitHub REST API v3 | Simple, no OAuth needed for CLI |
| Badge server | Cloudflare Worker (later) | Edge, free tier |

### Key design principles

1. **Zero config by default.** Auto-detect project type (Node/Python/both) from `package.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`.
2. **Fast.** Total scan under 30 seconds for most repos. Semgrep is parallelised by default.
3. **Offline-first.** SAST, secrets, deps all run locally. LLM is opt-in (`vibesafe fix`).
4. **No data exfiltration.** Your code never leaves your machine for `scan`. Only `fix` sends code snippets to LLM API (with clear opt-in warning).
5. **Composable.** JSON output for every command so CI pipelines can consume it.

---

## 6. Monorepo Structure

```
vibesafe/
├── packages/
│   ├── cli/                    # Main CLI package (published as `vibesafe` on npm)
│   │   ├── src/
│   │   │   ├── index.ts        # CLI entry point (commander.js)
│   │   │   ├── commands/
│   │   │   │   ├── scan.ts     # `vibesafe scan` command
│   │   │   │   ├── fix.ts      # `vibesafe fix` command
│   │   │   │   └── init.ts     # `vibesafe init` (create config file)
│   │   │   ├── scanners/
│   │   │   │   ├── sast.ts     # Semgrep wrapper
│   │   │   │   ├── secrets.ts  # Regex + entropy secrets scanner
│   │   │   │   └── deps.ts     # npm/pip audit wrapper
│   │   │   ├── fix/
│   │   │   │   ├── llm.ts      # LLM API client (Groq/OpenAI)
│   │   │   │   ├── patcher.ts  # Apply patches to files
│   │   │   │   └── github.ts   # GitHub PR creation
│   │   │   ├── output/
│   │   │   │   ├── terminal.ts # Rich terminal output (chalk, boxen)
│   │   │   │   ├── json.ts     # JSON formatter
│   │   │   │   └── score.ts    # Safety Score calculator
│   │   │   ├── config/
│   │   │   │   ├── loader.ts   # Load vibesafe.config.js
│   │   │   │   └── defaults.ts # Default scan config
│   │   │   └── utils/
│   │   │       ├── detect.ts   # Project type detection
│   │   │       ├── git.ts      # Git helpers (current branch, remote URL)
│   │   │       └── ignore.ts   # .vibesafeignore parser
│   │   ├── rules/              # Custom Semgrep YAML rules
│   │   │   ├── ai-generated/   # Rules specific to AI codegen patterns
│   │   │   │   ├── sql-injection.yaml
│   │   │   │   ├── hardcoded-creds.yaml
│   │   │   │   ├── xss-patterns.yaml
│   │   │   │   ├── broken-auth.yaml
│   │   │   │   └── insecure-deserialization.yaml
│   │   │   ├── javascript/
│   │   │   └── python/
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   └── action/                 # GitHub Action
│       ├── action.yml
│       ├── src/
│       │   └── main.ts         # Action entrypoint
│       └── package.json
│
├── apps/
│   └── web/                    # Future: vibesafe.dev dashboard (Next.js)
│
├── docs/                       # Documentation site (for stars)
│   ├── index.md
│   ├── getting-started.md
│   ├── rules/
│   └── api.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml              # Run tests on PR
│       ├── release.yml         # Publish to npm on tag
│       └── self-scan.yml       # VibeSafe scans itself (great marketing)
│
├── README.md                   # Star-bait README
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE                     # MIT
├── package.json                # Workspace root (pnpm workspaces)
├── pnpm-workspace.yaml
└── turbo.json                  # Turborepo config
```

---

## 7. Data Models

### ScanResult (core data structure flowing through the whole system)

```typescript
// packages/cli/src/types.ts

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  | 'sast'          // Static analysis (OWASP patterns)
  | 'secret'        // Hardcoded secrets
  | 'dependency'    // Vulnerable dependency
  | 'config';       // Misconfigured infra

export interface Finding {
  id: string;                  // Unique ID for this finding (e.g. "vs-001")
  category: FindingCategory;
  severity: Severity;
  title: string;               // Short title: "SQL Injection in user query"
  description: string;         // Plain English explanation (1 paragraph)
  file: string;                // Relative path: "src/routes/users.ts"
  line: number;                // Line number
  column?: number;
  code_snippet: string;        // The vulnerable line(s), max 5 lines
  rule_id: string;             // Semgrep rule ID or custom ID
  owasp?: string;              // e.g. "A03:2021 – Injection"
  cve?: string;                // e.g. "CVE-2024-12345" (for deps)
  fix_suggestion?: string;     // Plain English fix description
  fix_patch?: string;          // Actual code fix (populated by LLM)
  references: string[];        // Links to OWASP docs etc.
}

export interface DependencyFinding extends Finding {
  package_name: string;
  installed_version: string;
  patched_version: string;
  ecosystem: 'npm' | 'pip' | 'cargo';
}

export interface ScanResult {
  meta: {
    repo_path: string;
    scanned_at: string;          // ISO 8601
    duration_ms: number;
    project_type: string[];      // ['nodejs', 'python']
    vibesafe_version: string;
    commit_sha?: string;
    branch?: string;
  };
  findings: Finding[];
  summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_category: Record<FindingCategory, number>;
  };
  score: SafetyScore;
}

export interface SafetyScore {
  value: number;               // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  label: string;               // "SAFE TO SHIP" / "FIX BEFORE SHIPPING" etc.
  breakdown: {
    secrets: { score: number; issues: number };
    sast: { score: number; issues: number };
    dependencies: { score: number; issues: number };
    config: { score: number; issues: number };
  };
}
```

### Config (vibesafe.config.js)

```typescript
export interface VibeSafeConfig {
  // Which scanners to run (all enabled by default)
  scanners: {
    sast: boolean;
    secrets: boolean;
    dependencies: boolean;
    config: boolean;
  };

  // Minimum severity to report (default: 'low')
  minSeverity: Severity;

  // Fail exit code if any finding at or above this severity
  failOn: Severity | 'none';

  // Custom Semgrep rule directories
  customRules: string[];

  // LLM config for `vibesafe fix`
  llm: {
    provider: 'groq' | 'openai' | 'anthropic';
    model?: string;            // Default: 'llama-3.3-70b-versatile' for Groq
    maxTokens?: number;
  };

  // Paths to exclude (in addition to .vibesafeignore)
  exclude: string[];
}
```

---

## 8. CLI Design & UX

### Commands

```bash
# Scan current directory
npx vibesafe scan

# Scan specific path
npx vibesafe scan ./my-project

# Output as JSON (for CI)
npx vibesafe scan --json > results.json

# Only show critical and high
npx vibesafe scan --severity high

# Dry-run fix (show what would be fixed, no changes)
npx vibesafe fix --dry-run

# Generate fixes and open PR
vibesafe fix --pr

# Create config file
vibesafe init

# Show version
vibesafe --version
```

### Terminal Output Design

```
╔══════════════════════════════════════════════════════╗
║           VibeSafe v0.1.0 — Security Scanner         ║
╚══════════════════════════════════════════════════════╝

Scanning: /Users/dev/my-app
Detected: Node.js + Python project

[1/3] Running SAST scan...         ✓ (2.3s)
[2/3] Scanning for secrets...      ✓ (0.4s)
[3/3] Checking dependencies...     ✓ (1.1s)

─────────────────────────────────────────────────────

🔴 CRITICAL  SQL Injection
   src/routes/users.ts:47

   Your code builds a database query by directly inserting
   user input into the query string. An attacker can type
   something like "'; DROP TABLE users;--" into the input
   field and delete your entire database.

   Vulnerable code:
   │  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

   Fix: Use parameterised queries — pass the user input as
   a separate argument, never as part of the query string.

   → OWASP A03:2021 | Rule: vs-sqli-001

─────────────────────────────────────────────────────

🔴 CRITICAL  Hardcoded API Key
   .env.example:12

   Your OpenAI API key is hardcoded directly in a file that
   is committed to your repo. Anyone who finds your repo
   (public or private — repos get leaked) can use your API
   key and rack up charges on your account.

   Vulnerable code:
   │  OPENAI_API_KEY=sk-proj-abc123...xyz

   Fix: Move this to a .env file, add .env to .gitignore,
   and load it with process.env.OPENAI_API_KEY.

─────────────────────────────────────────────────────

📊 SCAN COMPLETE

   Issues found:
   ├── 🔴 Critical:  2
   ├── 🟠 High:      5
   ├── 🟡 Medium:    3
   └── 🔵 Low:       1

   ┌─────────────────────────────────┐
   │   VibeSafe Score: 34 / 100      │
   │   Grade: F                      │
   │   ⛔ FIX BEFORE SHIPPING        │
   └─────────────────────────────────┘

   Breakdown:
   Secrets:      ████░░░░░░  20/100 (2 exposed)
   OWASP issues: ███░░░░░░░  30/100 (5 high, 3 med)
   Dependencies: ██████░░░░  60/100 (2 critical CVEs)
   Config:       ████████░░  80/100 (1 issue)

Run `vibesafe fix` to auto-generate fixes.
Run `vibesafe fix --pr` to open a GitHub PR with fixes applied.
```

---

## 9. GitHub Action Design

### `vibesafe.yml` (users add this to their repo)

```yaml
name: VibeSafe Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    name: VibeSafe Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # Needed to post PR comments

    steps:
      - uses: actions/checkout@v4

      - name: Run VibeSafe
        uses: vibesafe/vibesafe-action@v1
        with:
          fail-on: 'high'          # Fail CI if high or critical issues found
          post-comment: true       # Post results as PR comment
          token: ${{ secrets.GITHUB_TOKEN }}
```

### action.yml (our action definition)

```yaml
name: 'VibeSafe'
description: 'Security scanner for vibe-coded and AI-generated apps'
branding:
  icon: 'shield'
  color: 'red'

inputs:
  fail-on:
    description: 'Minimum severity to fail the action (none/low/medium/high/critical)'
    required: false
    default: 'high'
  post-comment:
    description: 'Post scan results as a PR comment'
    required: false
    default: 'true'
  token:
    description: 'GitHub token for posting comments'
    required: false
    default: ${{ github.token }}
  path:
    description: 'Path to scan (default: repo root)'
    required: false
    default: '.'

outputs:
  score:
    description: 'Safety score (0-100)'
  findings-count:
    description: 'Total number of findings'
  critical-count:
    description: 'Number of critical findings'

runs:
  using: 'node20'
  main: 'dist/index.js'
```

---

## 10. LLM Fix Generation Pipeline

This is the novel part of VibeSafe. Here's exactly how it works.

### Flow

```
Finding (with file + line + code_snippet)
    │
    ▼
Read full file from disk
    │
    ▼
Build context window:
  - File content (up to 200 lines around the finding)
  - Finding description
  - OWASP context
    │
    ▼
LLM prompt (see below)
    │
    ▼
Parse response:
  - Fix explanation (plain English)
  - Code patch (unified diff format)
    │
    ▼
Apply patch to file (dry-run or live)
    │
    ▼
Create GitHub PR:
  - Branch: vibesafe/fix-{finding-id}
  - Commit: "fix: [VibeSafe] {finding title}"
  - PR title: "🛡️ [VibeSafe] Fix {N} security issues"
  - PR body: full explanation of each fix
```

### LLM Prompt Template

```typescript
// packages/cli/src/fix/llm.ts

export function buildFixPrompt(finding: Finding, fileContent: string): string {
  return `You are a security engineer reviewing code for vulnerabilities.

A security scanner found this issue:

VULNERABILITY: ${finding.title}
SEVERITY: ${finding.severity}
FILE: ${finding.file}
LINE: ${finding.line}
CATEGORY: ${finding.owasp || finding.category}

VULNERABLE CODE:
\`\`\`
${finding.code_snippet}
\`\`\`

FULL FILE CONTEXT (around the vulnerability):
\`\`\`
${fileContent}
\`\`\`

Your task:
1. Write a FIXED VERSION of the vulnerable code
2. Explain in 2-3 sentences (plain English, no jargon) WHY the fix works

IMPORTANT RULES:
- Only change what is necessary to fix the vulnerability
- Do not refactor unrelated code
- Keep the same language, framework, and style as the original
- The fix must be production-ready, not pseudocode

Respond in this EXACT JSON format:
{
  "fixed_code": "...the corrected code snippet only...",
  "explanation": "...plain English explanation of why this fix works...",
  "pr_description": "...one paragraph for the GitHub PR body..."
}`;
}
```

### GitHub PR Creation

```typescript
// packages/cli/src/fix/github.ts

export async function createFixPR(
  findings: Finding[],
  patches: Patch[],
  repoInfo: RepoInfo
): Promise<string> {
  const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

  // 1. Create a new branch from current HEAD
  const branchName = `vibesafe/fix-${Date.now()}`;
  await octokit.rest.git.createRef({
    owner: repoInfo.owner,
    repo: repoInfo.repo,
    ref: `refs/heads/${branchName}`,
    sha: repoInfo.currentSha,
  });

  // 2. Commit each patched file
  for (const patch of patches) {
    const encoded = Buffer.from(patch.newContent).toString('base64');
    await octokit.rest.repos.createOrUpdateFileContents({
      owner: repoInfo.owner,
      repo: repoInfo.repo,
      path: patch.file,
      message: `fix: [VibeSafe] ${patch.findingTitle}`,
      content: encoded,
      branch: branchName,
      sha: patch.existingFileSha,
    });
  }

  // 3. Open the PR
  const pr = await octokit.rest.pulls.create({
    owner: repoInfo.owner,
    repo: repoInfo.repo,
    title: `🛡️ [VibeSafe] Fix ${findings.length} security issue${findings.length > 1 ? 's' : ''}`,
    body: buildPRBody(findings, patches),
    head: branchName,
    base: repoInfo.defaultBranch,
  });

  return pr.data.html_url;
}
```

---

## 11. API Server

The API server is optional for v0.1 but needed for the badge and future SaaS.

### Endpoints (v0.1)

```
POST /v1/scan
  Body: { repo_url: string, ref?: string }
  Response: ScanResult

GET /v1/badge/:owner/:repo
  Response: SVG badge (for README)

GET /v1/results/:scan_id
  Response: ScanResult
```

### Stack

- **Runtime:** Node.js + Fastify (fast, TypeScript-native)
- **Database:** PostgreSQL (Supabase) — scan results, user accounts
- **Queue:** BullMQ + Redis — async scan jobs
- **Deploy:** Railway or Fly.io (simple, not Vercel — need long-running processes)

---

## 12. Safety Score Algorithm

```typescript
// packages/cli/src/output/score.ts

const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
};

const CATEGORY_WEIGHTS = {
  secret: 1.5,      // Secrets are the worst — multiplied 1.5x
  sast: 1.0,
  dependency: 0.8,
  config: 0.6,
};

export function calculateScore(findings: Finding[]): SafetyScore {
  if (findings.length === 0) {
    return { value: 100, grade: 'A', label: 'SAFE TO SHIP', breakdown: ... };
  }

  // Calculate raw penalty
  const penalty = findings.reduce((acc, finding) => {
    const severityPenalty = SEVERITY_WEIGHTS[finding.severity];
    const categoryMultiplier = CATEGORY_WEIGHTS[finding.category];
    return acc + (severityPenalty * categoryMultiplier);
  }, 0);

  // Cap penalty at 100 and invert
  const rawScore = Math.max(0, 100 - Math.min(penalty, 100));

  // Apply exponential smoothing so a single critical doesn't
  // immediately tank the score to 0 — it should be severe but not terminal
  const score = Math.round(rawScore);

  const grade =
    score >= 90 ? 'A' :
    score >= 75 ? 'B' :
    score >= 60 ? 'C' :
    score >= 40 ? 'D' : 'F';

  const label =
    score >= 75 ? '✅ SAFE TO SHIP' :
    score >= 50 ? '⚠️  REVIEW BEFORE SHIPPING' :
    '⛔ FIX BEFORE SHIPPING';

  return { value: score, grade, label, breakdown: calculateBreakdown(findings) };
}
```

---

## 13. README & GitHub Strategy

The README IS the marketing. For a developer tool trying to get stars, the README is the landing page.

### README Structure (star-optimised)

```markdown
# VibeSafe 🛡️

> Security co-pilot for vibe-coded and AI-generated apps.

![VibeSafe Score](badge)
![npm version](badge)
![License: MIT](badge)
![Stars](badge)

**Built with Cursor? Shipped on Lovable? Vibe-coded your MVP?**  
VibeSafe scans your repo in 5 minutes and tells you if it's safe to ship — in plain English.

## Quick demo (GIF here — this is critical)

## Why VibeSafe

45% of AI-generated code contains OWASP Top 10 vulnerabilities.
Most vibe-coders have no idea.

## What it finds

## What the output looks like (full terminal screenshot)

## Getting started

npx vibesafe scan

## Custom rules for AI-generated code

## How the Safety Score works

## GitHub Action

## Contributing (Rules wanted!)

## Used by
```

### Tactics for stars

1. **Self-scan badge** — VibeSafe scans its own repo and shows the badge. Meta and credible.
2. **Real CVE examples** — Show a Lovable app with a real SQL injection. Not a toy example.
3. **Twitter/X thread on launch day** — Post the Georgia Tech stat (35 CVEs in March 2026 from vibe-coded apps). Attach a real terminal demo GIF.
4. **Show HN post** — Title: "VibeSafe – I built a security scanner specifically for Cursor/Lovable apps after seeing how many leaked secrets". Post on a Tuesday 9am EST.
5. **Product Hunt launch** — Schedule for after 200 stars so you have social proof.
6. **Contribute rules back to Semgrep** — This gets VibeSafe mentioned in their community.

---

## 14. Cursor Prompting Plan

Use this exact prompt sequence in Cursor. Each prompt builds on the last.

### Prompt 0 — Project setup

```
Create a new Node.js monorepo using pnpm workspaces and Turborepo.

Structure:
- packages/cli — TypeScript CLI tool
- packages/action — GitHub Action

Root package.json with workspaces configured.
Root turbo.json with build and test pipelines.
Root tsconfig.json with strict mode.

Use:
- TypeScript 5.x
- ESLint + Prettier
- Vitest for tests
- tsup for building (outputs to dist/)

In packages/cli:
- commander.js for CLI argument parsing
- chalk for terminal colours
- boxen for boxed output
- ora for spinners

Create the entry point at packages/cli/src/index.ts
that registers three commands: scan, fix, init.
Each command imports from its own file in src/commands/.
```

### Prompt 1 — Project type detection

```
In packages/cli/src/utils/detect.ts, implement a function:

detectProjectType(repoPath: string): Promise<ProjectType[]>

Where ProjectType = 'nodejs' | 'python' | 'rust' | 'go' | 'unknown'

Detection rules:
- 'nodejs' if package.json exists at root or any subdirectory
- 'python' if requirements.txt, Pipfile, pyproject.toml, or setup.py exists
- 'rust' if Cargo.toml exists
- 'go' if go.mod exists

Return ALL detected types (a repo can be both nodejs and python).

Also implement:

getIgnorePatterns(repoPath: string): Promise<string[]>

Reads .vibesafeignore (same format as .gitignore) from repo root.
Also always ignores: node_modules/, .git/, dist/, build/, __pycache__/

Export both functions. Add unit tests in __tests__/detect.test.ts.
```

### Prompt 2 — Secrets scanner

```
In packages/cli/src/scanners/secrets.ts, implement a secrets scanner.

The scanner should:
1. Walk all files in the repo (respecting ignore patterns)
2. Check each file against a list of regex patterns
3. Also run Shannon entropy check on strings that look like tokens

Export:
  scanSecrets(repoPath: string, ignorePatterns: string[]): Promise<Finding[]>

Patterns to detect (at minimum):
- OpenAI API keys: sk-[A-Za-z0-9]{48}
- Anthropic keys: sk-ant-[A-Za-z0-9\-]{95}
- AWS access key: AKIA[0-9A-Z]{16}
- GitHub tokens: ghp_[A-Za-z0-9]{36} or github_pat_...
- Generic: password = "..." or secret = "..." or api_key = "..."
- Stripe keys: sk_live_[A-Za-z0-9]{24}
- Supabase service keys: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... with service_role

For each match, return a Finding with:
- category: 'secret'
- severity: 'critical'
- file and line number
- code_snippet: the matching line (redacted — show only first 8 chars of the actual key)
- description: plain English explanation for that specific key type
  e.g. "Your OpenAI API key is hardcoded. Anyone with access to this repo
       can use your API and charge your account."

Skip binary files. Skip files larger than 1MB.
Skip lines that are comments containing "example", "placeholder", "fake", "test".

Add unit tests with mock files containing fake keys.
```

### Prompt 3 — Dependency scanner

```
In packages/cli/src/scanners/deps.ts, implement a dependency scanner.

Export:
  scanDependencies(repoPath: string, projectTypes: ProjectType[]): Promise<Finding[]>

For Node.js projects:
- Run: npm audit --json (in the repo directory)
- Parse the JSON output
- For each vulnerability: create a Finding with severity mapped from npm's
  'critical'/'high'/'moderate'/'low'

For Python projects:
- Check if pip-audit is installed: run `pip-audit --version`
- If installed: run `pip-audit --format json`
- If not installed: log a warning and skip
- Parse JSON output similarly

Also:
- Check package.json "dependencies" and "devDependencies" for known problematic
  packages (hardcoded list of 10 worst offenders with known CVEs)

For each finding:
- category: 'dependency'
- Include package name, installed version, patched version in description
- Link to the CVE where available
- Plain English: "The [package] package you're using has a known security
  vulnerability (CVE-XXXX-XXXX) that allows attackers to [brief impact].
  Update to version X.X.X to fix this."

Handle the case where npm/pip are not in PATH gracefully — return empty array
with a warning, don't crash.
```

### Prompt 4 — SAST with Semgrep

```
In packages/cli/src/scanners/sast.ts, implement the SAST scanner.

This scanner wraps Semgrep. Semgrep is invoked as a subprocess.

Export:
  scanSAST(repoPath: string, ignorePatterns: string[]): Promise<Finding[]>

Implementation:
1. Check if `semgrep` is installed (run `semgrep --version`)
2. If NOT installed, use the built-in custom rules only
   (we will have our own regex-based rules as fallback)
3. If installed, run:
   semgrep scan --config=auto --json --quiet {repoPath}
   + our custom rules from packages/cli/rules/

Parse Semgrep's JSON output (semgrep-output-schema).
Map Semgrep severity (ERROR/WARNING/INFO) to our Severity type.
Map OWASP tags from Semgrep rule metadata.

For each finding:
- Truncate code_snippet to the 3 lines around the match
- Generate a plain English description based on rule_id
  (we will maintain a mapping in src/config/rule-descriptions.ts)

Fallback (when Semgrep not installed):
- Run our own regex-based rules from packages/cli/rules/
- These are lighter but catch the most common issues

Add a note in terminal output if Semgrep is not installed:
"💡 Install Semgrep for deeper scanning: brew install semgrep"
```

### Prompt 5 — Safety Score + Terminal output

```
Implement the scan command that ties everything together.

In packages/cli/src/commands/scan.ts:

1. Show a spinner for each scanner phase
2. Run all 3 scanners in parallel where possible (SAST is slow, secrets + deps are fast)
3. Deduplicate findings (same file + line + rule = one finding)
4. Calculate Safety Score
5. Output to terminal

Use chalk colours:
- 🔴 critical → chalk.red.bold
- 🟠 high → chalk.hex('#FF6600')
- 🟡 medium → chalk.yellow
- 🔵 low → chalk.blue
- ✅ pass → chalk.green

The Safety Score box should use boxen with:
- Score >= 75: green border
- Score 50-74: yellow border
- Score < 50: red border

At the bottom, always print:
"Run `vibesafe fix` to auto-generate fixes."

If --json flag is passed, skip all the pretty output and just
console.log(JSON.stringify(result, null, 2))

Exit code:
- 0 if no findings at or above failOn severity
- 1 if findings found at or above failOn severity
- 2 if scan itself errored
```

### Prompt 6 — LLM fix engine

```
Implement the fix command in packages/cli/src/commands/fix.ts

This command:
1. Runs the scan first (same as `vibesafe scan`)
2. For each finding above medium severity:
   a. Reads the full file content
   b. Builds the prompt (see src/fix/llm.ts)
   c. Calls Groq API (llama-3.3-70b-versatile model)
   d. Parses the JSON response
   e. Shows the proposed fix in the terminal
3. In --dry-run mode: show the fix, ask for confirmation, don't write anything
4. In live mode: apply all fixes, show diff of each change

LLM client in src/fix/llm.ts:
- Primary: Groq (fast, generous free tier)
  API endpoint: https://api.groq.com/openai/v1/chat/completions
  Auth: GROQ_API_KEY env var
- Fallback: OpenAI (OPENAI_API_KEY env var)
- Show error if neither key is set, with instructions

Show a progress bar as findings are processed:
"Generating fixes... [████░░░░░░] 4/10"

After all fixes:
Show a summary of all changes.
Ask: "Apply these fixes? (y/N)"
If yes: write the files.
Print: "✅ 4 files updated. Run `git diff` to review changes."
Print: "Run `vibesafe fix --pr` to open a GitHub PR with these changes."
```

### Prompt 7 — GitHub PR creation

```
Implement GitHub PR creation in packages/cli/src/fix/github.ts

Use @octokit/rest package.

Export:
  createFixPR(findings, patches, options): Promise<string>

Steps:
1. Detect GitHub remote from `git remote get-url origin`
   Parse owner/repo from the URL (handles both HTTPS and SSH formats)
2. Get current commit SHA: `git rev-parse HEAD`
3. Get default branch from GitHub API
4. Create a new branch: vibesafe/fix-YYYYMMDD-HHMMSS
5. For each patched file:
   - Get existing file SHA from GitHub API
   - Create/update file via GitHub API
6. Create the PR with:
   Title: "🛡️ [VibeSafe] Fix {N} security issues"
   Body: see buildPRBody function below
   Labels: ["security", "vibesafe"] (create labels if they don't exist)

buildPRBody should include:
- VibeSafe badge showing the new score
- Table of issues fixed (severity | file | issue)
- For each finding: plain English explanation + what the fix does
- Footer: "Generated by VibeSafe — security scanner for vibe-coded apps"

Auth: GITHUB_TOKEN env var. If not set, show instructions.

Handle errors gracefully (rate limits, repo not found, no push access).
```

---

## 15. Build Order (Sprint Plan)

### Week 1 — Core scanner (the thing that gets stars)

| Day | Task | Cursor Prompt |
|---|---|---|
| 1 | Monorepo setup, TypeScript config, CLI scaffold | Prompt 0 |
| 1 | Project type detection + ignore patterns | Prompt 1 |
| 2 | Secrets scanner (this is the demo-able thing) | Prompt 2 |
| 2 | Dependency scanner | Prompt 3 |
| 3 | SAST with Semgrep wrapper | Prompt 4 |
| 3 | Safety Score + beautiful terminal output | Prompt 5 |
| 4 | `npx vibesafe scan` works end-to-end on a real repo | Integration |
| 4 | Write 10 custom Semgrep rules for AI-generated patterns | Manual |
| 5 | Record GIF demo. Write README. Push to GitHub | Launch prep |

### Week 2 — Fix generation (the wow factor)

| Day | Task | Cursor Prompt |
|---|---|---|
| 6 | LLM fix engine (Groq) | Prompt 6 |
| 7 | `vibesafe fix --dry-run` works | Integration |
| 8 | GitHub PR creation | Prompt 7 |
| 9 | `vibesafe fix --pr` works end-to-end | Integration |
| 10 | Show HN post + Twitter/X thread | Launch |

### Week 3 — GitHub Action + polish

| Day | Task |
|---|---|
| 11 | GitHub Action (packages/action) |
| 12 | PR comment posting |
| 13 | README badge server (Cloudflare Worker) |
| 14 | `vibesafe init` command |
| 15 | Documentation site |

---

## 16. Environment Variables

```bash
# Required for `vibesafe fix` (LLM)
GROQ_API_KEY=          # Get free at console.groq.com
OPENAI_API_KEY=        # Fallback if Groq not available

# Required for `vibesafe fix --pr`
GITHUB_TOKEN=          # Your GitHub personal access token (repo scope)

# Optional
VIBESAFE_TELEMETRY=false   # Disable anonymous usage metrics
VIBESAFE_LOG_LEVEL=debug   # Verbose logging
```

VibeSafe stores no credentials. Keys are read from env only. Never transmitted except to the respective LLM/GitHub API.

---

## 17. Open Source Launch Checklist

### Repository health (GitHub will surface this)
- [ ] README with demo GIF (mandatory — no GIF = 60% fewer stars)
- [ ] CONTRIBUTING.md (how to add new rules — community engagement)
- [ ] SECURITY.md (ironically essential for a security tool)
- [ ] CODE_OF_CONDUCT.md
- [ ] Issue templates (Bug report, New rule request, Feature request)
- [ ] PR template
- [ ] GitHub Topics: `security`, `cli`, `devtools`, `vibe-coding`, `owasp`, `semgrep`, `sast`

### Quality signals
- [ ] 100% of public functions have JSDoc comments
- [ ] Tests pass in CI (even basic ones)
- [ ] `npx vibesafe scan` works with zero setup on Node 18+
- [ ] Clear error messages for every failure mode
- [ ] Works on macOS, Linux, Windows (WSL)

### Launch day
- [ ] Post on Show HN (Tuesday 9am EST)
- [ ] Twitter/X thread with real demo + Georgia Tech CVE stat
- [ ] Post in: r/webdev, r/netsec, r/SideProject, Indie Hackers
- [ ] DM 10 people in the Cursor/Lovable community
- [ ] Add to awesome-security-tools (GitHub list)
- [ ] Cross-post on Hacker News, Dev.to, Hashnode

### Week 2 (after first 100 stars)
- [ ] Product Hunt launch
- [ ] Contact Cursor/Lovable/v0 communities for feature mention
- [ ] Blog post: "I scanned 100 Lovable apps and found..."
- [ ] Reach out to Georgia Tech Vibe Security Radar team

---

*VibeSafe PRD v0.1 — Built for Cursor*  
*Start with Prompt 0. Build in order. Ship fast.*
