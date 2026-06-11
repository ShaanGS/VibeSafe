# Contributing to VibeSafe

Thanks for your interest in contributing. VibeSafe is a security scanner built for AI-generated code, and every contribution makes it better at catching the vulnerabilities that LLMs introduce.

## Prerequisites

- **Node.js** >= 18
- **pnpm** >= 9 (`npm install -g pnpm`)
- **Git**

## Getting Started

```bash
# Fork and clone
git clone https://github.com/<your-username>/VibeSafe.git
cd VibeSafe

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test
```

## Project Structure

```
VibeSafe/
├── packages/
│   ├── cli/                    # Main CLI tool (npm: vibesafe)
│   │   ├── src/
│   │   │   ├── index.ts        # CLI entry point (commander.js)
│   │   │   ├── types.ts        # All TypeScript types
│   │   │   ├── commands/       # scan, fix, init commands
│   │   │   ├── scanners/       # secrets, deps, sast scanners
│   │   │   ├── config/         # Rule definitions
│   │   │   ├── output/         # Terminal output, scoring, JSON
│   │   │   ├── utils/          # Project detection, ignore patterns
│   │   │   └── fix/            # LLM fix engine (WIP)
│   │   ├── __tests__/          # Vitest test suites
│   │   └── rules/              # Custom Semgrep YAML rules
│   └── action/                 # GitHub Action (WIP)
├── turbo.json                  # Turborepo config
└── pnpm-workspace.yaml         # Workspace config
```

## Development Workflow

```bash
# Build everything
pnpm build

# Run tests
pnpm test

# Watch mode (rebuild on changes)
pnpm dev

# Run the CLI locally
node packages/cli/dist/index.js scan <path>

# Or link it globally for easier testing
cd packages/cli && npm link
vibesafe scan <path>
```

## Adding a New Security Rule

VibeSafe's fallback regex rules live in [`packages/cli/src/config/rule-descriptions.ts`](packages/cli/src/config/rule-descriptions.ts). Each rule implements the `RegexRule` interface:

```typescript
interface RegexRule {
  id: string;            // e.g., 'vs-sast-sqli'
  title: string;         // Human-readable name
  pattern: RegExp;       // The detection regex
  fileTypes: string[];   // e.g., ['.ts', '.js']
  severity: Severity;    // 'critical' | 'high' | 'medium' | 'low'
  owasp: string;         // OWASP Top 10 reference
  description: string;   // Why this is a problem
  fix: string;           // How to fix it
}
```

To add a new rule:

1. Add your `RegexRule` to the `FALLBACK_REGEX_RULES` array in `rule-descriptions.ts`
2. Add test cases in `__tests__/sast.test.ts`
3. Run `pnpm test` to verify
4. Submit a PR

## Adding a New Scanner

Scanners live in `packages/cli/src/scanners/`. Each scanner exports a function that returns `Promise<Finding[]>`. Look at `secrets.ts` or `sast.ts` for the pattern.

1. Create your scanner in `src/scanners/`
2. Wire it into `src/commands/scan.ts`
3. Add a test file in `__tests__/`
4. Update the types in `src/types.ts` if you need a new `FindingCategory`

## Code Style

- TypeScript with strict mode
- No `any` types — use proper typing
- Test every rule and edge case
- Keep functions focused and small
- Use descriptive variable names

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Rust cargo-audit integration
fix: false positive on JWT in test comments
docs: update README with new scanner info
test: add edge case for entropy detection
chore: update dependencies
```

## Pull Request Process

1. Fork the repo and create a feature branch from `main`
2. Implement your changes
3. Add or update tests as needed
4. Run `pnpm build && pnpm test` — everything must pass
5. Open a PR with a clear description of what and why

## Reporting Issues

- **Bugs**: Use the [bug report template](https://github.com/shaangurushankar/VibeSafe/issues/new?template=bug_report.yml)
- **Features**: Use the [feature request template](https://github.com/shaangurushankar/VibeSafe/issues/new?template=feature_request.yml)
- **Security**: See [SECURITY.md](SECURITY.md) for responsible disclosure

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Be respectful.
