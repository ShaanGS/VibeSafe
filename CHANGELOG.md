# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-20

### Added
- Secrets scanner with 13 regex patterns and Shannon entropy detection
- Dependency scanner with npm audit, pip-audit, and known malicious package detection
- SAST scanner with Semgrep integration and 8 fallback regex rules
- Safety Score algorithm (0-100) with A-F grading
- Beautiful terminal output with severity-colored findings
- Project type auto-detection (Node.js, Python, Rust, Go)
- `.vibesafeignore` support for excluding files
- JSON output mode (`--json`) for CI/CD integration
- 95 unit tests across all scanners
