# Changelog

All notable changes to PhishGuard AI are documented here.

## [0.5.1] - 2026-06-12

### Added

- Optional SPF, DKIM, and DMARC `Authentication-Results` parsing with
  conservative, explainable email risk signals.
- A one-minute demo, first-contribution guide, support policy, and structured
  documentation issue template.
- A CI smoke test that executes the root `action.yml` and validates its SARIF
  output before release.

### Changed

- Renamed the Marketplace action to `PhishGuard AI Phishing Detector` using
  Marketplace-compatible characters.
- Made the composite action install PhishGuard from its checked-out action
  directory, so consumers receive the implementation pinned by their selected
  tag instead of code from a moving branch.
- Pinned the action's Python setup dependency to a reviewed commit.
- Refreshed the roadmap with scoped Python API, email-authentication, and
  benchmark tasks.

## [0.5.0] - 2026-06-11

### Added

- **URL redirect chain tracing** (`--follow-redirects N`): follow up to N HTTP
  hops using only the Python standard library and score the final destination
  URL. Flags when a redirect chain crosses domain boundaries. Degrades
  gracefully when the network is unavailable — the tool remains fully offline
  without the flag.
- **Typosquatting / lookalike detection**: a pure-Python Levenshtein comparison
  against 50 well-known brand domains. Edit-distance-1 matches score 1.0,
  distance-2 matches score 0.6. Exact legitimate domain matches are excluded
  from scoring.
- **`.eml` file analysis** (`phishguard eml <file>`): parse RFC 5322 email
  files using the Python standard library `email` module. Extracts subject,
  body, and `Authentication-Results` header automatically, then runs both
  email scoring and a URL scan of every link found in the body.
- **Reusable GitHub Action** (`action.yml`): any repository can use
  `omobolajiadeyan/phishguard-ai@main` in a workflow to scan URLs and upload
  SARIF findings to GitHub Code Scanning.
- **Self-scan CI workflow** (`.github/workflows/phishguard-self-scan.yml`):
  PhishGuard scans its own test URLs on every push and pull request, uploading
  results to GitHub Code Scanning.
- `redirect_crossed_domain` and `redirect_hops` optional model features,
  active only when redirect tracing is used.

### Changed

- `score_url` now accepts an optional `extra_features` dict for injecting
  redirect chain signals without modifying the feature extractor.
- `phishguard eml` verbose output includes a per-feature breakdown for both
  the email body analysis and each embedded URL.
- `pyproject.toml` version bumped from `0.5.0.dev0` to `0.5.0`.
- `redirect` module added to `py-modules` in `pyproject.toml`.

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
