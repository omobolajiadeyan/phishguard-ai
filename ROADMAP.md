# PhishGuard AI Roadmap

The roadmap is maintained by
[Omobolaji Adeyan](https://github.com/omobolajiadeyan). Implementation work is
tracked in GitHub issues so contributors can discuss and claim scoped tasks.

## Current Priorities

| Priority | Work | Status |
| --- | --- | --- |
| Community feedback | [SPF/DKIM/DMARC scoring and SARIF output feedback](https://github.com/omobolajiadeyan/phishguard-ai/issues/45) | Feedback wanted |
| Evaluation | [Improve public benchmark recall without increasing false positives](https://github.com/omobolajiadeyan/phishguard-ai/issues/46) | Help wanted |
| API | [Stable public Python API guide](https://github.com/omobolajiadeyan/phishguard-ai/issues/16) | Help wanted |
| Evaluation | [Public-data benchmark provenance](https://github.com/omobolajiadeyan/phishguard-ai/issues/18) | Research help wanted |

## Recently Shipped (v0.5.0)

- **URL redirect chain tracing** — follow short links and URL shorteners to
  their real destination using only the Python standard library
- **Typosquatting detection** — pure-Python Levenshtein distance against 50
  well-known brand domains catches `paypa1.com`, `g00gle.com`, `githab.com`
- **`.eml` file analysis** — parse full RFC 5322 email files, extract auth
  headers automatically, and scan all embedded URLs in one command
- **Reusable GitHub Action** — `uses: omobolajiadeyan/phishguard-ai@v0.5.1` lets
  any repo integrate phishing URL scanning into their CI pipeline
- SARIF 2.1.0 output for GitHub Code Scanning and CI security pipelines
- Calibrated scoring with regression coverage for common legitimate URLs
- Windows-safe output handling and Python 3.10–3.13 continuous integration
- Plain ASCII output mode contributed by BeauDevCode
- Versioned wheel and source releases with checksums and build provenance

## Next

- REST API / `--serve` mode for SIEM and proxy integrations
- Improve public benchmark recall while preserving false-positive discipline
  (#46)
- Expand the benchmark with public-data provenance (#18)
- Stable public Python API documentation (#16)

## Later

- Optional trained model support while preserving the explainable heuristic mode
- Browser extension once the detection benchmark is mature
- RDAP domain-age signal (newly registered domains)

Roadmap items are not promises or deadlines. Priorities may change when
testing, security review, or contributor feedback reveals a better direction.
