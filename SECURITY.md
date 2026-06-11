# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | ✅ Active development |

## Reporting a Vulnerability

If you find a security vulnerability in VibeSafe itself (not in code that VibeSafe scans), please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

Please report security vulnerabilities through GitHub's **Private Vulnerability Reporting** feature in the repository settings. 

Alternatively, if you prefer email, contact the maintainers at **security@vibesafe.dev**.

Please include:

1. A description of the vulnerability
2. Steps to reproduce
3. The potential impact
4. Any suggested fixes (optional but appreciated)

### What to Expect

- **48 hours** — We'll acknowledge receipt of your report
- **7 days** — We'll provide an initial assessment and action plan
- **30 days** — We aim to release a fix for confirmed vulnerabilities

### Scope

The following are in scope:

- The `vibesafe` npm package
- The `@vibesafe/action` GitHub Action
- Custom Semgrep rules distributed with VibeSafe
- The VibeSafe documentation (if it could lead to insecure usage)

The following are out of scope:

- Vulnerabilities in code that VibeSafe scans (that's your problem, VibeSafe is trying to help)
- Vulnerabilities in third-party dependencies (report those upstream, but let us know)
- Issues requiring physical access to a machine

### Recognition

We'll credit all responsible disclosures in our release notes (unless you prefer to remain anonymous). If you report a valid vulnerability, we'd like to thank you publicly — just let us know your preferred name or handle.

## Security Best Practices for Contributors

If you're contributing to VibeSafe:

- Never commit real API keys or credentials, even in tests
- Use obviously fake values in test fixtures (`AKIAIOSFODNN7EXAMPLE`)
- Run `vibesafe scan .` on the VibeSafe repo itself before submitting a PR
