# Changelog

All notable changes to PhishGuard AI are documented here.

## [Unreleased]

### Added

- Optional SPF, DKIM, and DMARC `Authentication-Results` parsing with
  conservative, explainable email risk signals.
- A one-minute demo, first-contribution guide, support policy, and structured
  documentation issue template.

### Changed

- Started the `0.5.0` development cycle and added direct release-wheel installation guidance.
- Refreshed the roadmap with scoped Python API, email-authentication, and benchmark tasks.

## [0.4.0] - 2026-06-09

### Added

- Conservative punycode and Unicode hostname indicators for URL analysis
- Public-safe URL regression fixture and deterministic benchmark metrics
- Standards-based Python packaging with an installed `phishguard` command
- Isolated distribution build, metadata, wheel-installation, and CLI checks
- CodeQL analysis using pinned GitHub Actions
- Tag-gated release automation with checksums and signed build provenance
- Detection-model documentation and evidence requirements for scoring changes
- Reproducible contributor setup, verification, safe-data, and review guidance
- Structured issue routing for design discussions and private security reports
- Branch protection and confidential GitHub vulnerability reporting

### Changed

- Clarified that current scores are explainable heuristics rather than
  statistically calibrated probabilities
- Expanded contributor coordination and evaluation benchmark requirements

## [0.3.0] - 2026-06-08

### Added

- Dependency-free SARIF 2.1.0 export for URL, email, and batch results
- GitHub Code Scanning workflow template and integration guide
- Stable finding fingerprints, severity mapping, and explainable SARIF properties
- CLI and serializer regression tests for JSON and SARIF output

### Changed

- Added `--format json|sarif` to every CLI scan command
- Standardized report files as UTF-8 with a trailing newline

## [0.2.0] - 2026-06-08

### Added

- Regression tests for URL scoring, email scoring, and limited console encodings
- Continuous integration across Python 3.10 through 3.13
- Contributor guide, security policy, governance, roadmap, and issue templates
- Project citation metadata and an MIT open-source license

### Changed

- Calibrated URL and email scoring to reduce false positives on legitimate input
- Made CLI output resilient on Windows consoles with limited encodings
- Established Omobolaji Adeyan as creator and lead maintainer

## [0.1.0] - 2025-04-20

- Initial explainable URL and email phishing detector
- Single-target and batch CLI workflows
- JSON output for downstream analysis
