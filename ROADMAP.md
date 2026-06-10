# PhishGuard AI Roadmap

The roadmap is maintained by
[Omobolaji Adeyan](https://github.com/omobolajiadeyan). Implementation work is
tracked in GitHub issues so contributors can discuss and claim scoped tasks.

## Current Priorities

| Priority | Work | Status |
| --- | --- | --- |
| Integration | [Batch source locations in SARIF](https://github.com/omobolajiadeyan/phishguard-ai/issues/5) | In progress in PR #6 |
| API | [Stable public Python API guide](https://github.com/omobolajiadeyan/phishguard-ai/issues/16) | Help wanted |
| Evaluation | [Public-data benchmark provenance](https://github.com/omobolajiadeyan/phishguard-ai/issues/18) | Research help wanted |

## Recently Shipped

- SARIF 2.1.0 output for GitHub Code Scanning and CI security pipelines
- Calibrated scoring with regression coverage for common legitimate URLs
- Windows-safe output handling and Python 3.10-3.13 continuous integration
- Public-safe URL regression fixture with reproducible confusion-matrix metrics
- Conservative IDN and punycode indicators with false-positive regressions
- Plain ASCII output mode contributed by BeauDevCode
- Versioned wheel and source releases with checksums and build provenance

## Ready for Next Release

- Conservative SPF, DKIM, and DMARC `Authentication-Results` signals,
  merged to `main` but not included in the v0.4.0 package

## Next

- URL redirect-chain and hostname-normalization analysis
- Expand installation and integration examples for SOC and CI workflows

## Later

- Optional trained model support while preserving the explainable heuristic mode
- REST API wrapper for SOC integrations
- Browser integration after the detection benchmark is mature

Roadmap items are not promises or deadlines. Priorities may change when
testing, security review, or contributor feedback reveals a better direction.
