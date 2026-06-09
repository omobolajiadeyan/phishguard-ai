# PhishGuard AI Roadmap

The roadmap is maintained by
[Omobolaji Adeyan](https://github.com/omobolajiadeyan). Implementation work is
tracked in GitHub issues so contributors can discuss and claim scoped tasks.

## Current Priorities

| Priority | Work | Status |
| --- | --- | --- |
| Portability | [Plain ASCII output mode](https://github.com/omobolajiadeyan/phishguard-ai/issues/1) | In progress in PR #7 |
| Integration | [Batch source locations in SARIF](https://github.com/omobolajiadeyan/phishguard-ai/issues/5) | In progress in PR #6 |
| Detection | [IDN and punycode signals](https://github.com/omobolajiadeyan/phishguard-ai/issues/2) | Help wanted |
| Quality | [Labeled evaluation benchmark](https://github.com/omobolajiadeyan/phishguard-ai/issues/3) | Initial fixture implemented |

## Recently Shipped

- SARIF 2.1.0 output for GitHub Code Scanning and CI security pipelines
- Calibrated scoring with regression coverage for common legitimate URLs
- Windows-safe output handling and Python 3.10-3.13 continuous integration
- Public-safe URL regression fixture with reproducible confusion-matrix metrics

## Next

- Email-header analysis for SPF, DKIM, and DMARC indicators
- URL redirect-chain and hostname-normalization analysis
- A documented Python API in addition to the command-line interface
- Reproducible evaluation against public-safe labeled datasets

## Later

- Optional trained model support while preserving the explainable heuristic mode
- REST API wrapper for SOC integrations
- Browser integration after the detection benchmark is mature

Roadmap items are not promises or deadlines. Priorities may change when
testing, security review, or contributor feedback reveals a better direction.
