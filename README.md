# PhishGuard AI

[![Tests](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/tests.yml)
[![CodeQL](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/codeql.yml/badge.svg)](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/omobolajiadeyan/phishguard-ai?style=flat-square)](https://github.com/omobolajiadeyan/phishguard-ai/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Marketplace](https://img.shields.io/badge/GitHub-Marketplace-2088FF?style=flat-square&logo=github)](https://github.com/marketplace/actions/phishguard-ai-phishing-detector)
[![Contributions](https://img.shields.io/badge/Contributions-Welcome-2ea44f?style=flat-square)](CONTRIBUTING.md)

Explainable phishing detection for URLs and email—offline by default, with no
API key and no runtime dependencies.

PhishGuard AI turns structural URL signals and email indicators into a
reviewable risk score, verdict, and feature-level explanation. Run it from a
terminal, embed it in Python, add it to GitHub Actions, export JSON or SARIF,
or use the browser demo.

[Try the live demo](https://omobolajiadeyan.github.io/phishguard-ai/) ·
[Install v0.5.1](#quick-start) ·
[View on Marketplace](https://github.com/marketplace/actions/phishguard-ai-phishing-detector) ·
[Review the evidence](docs/PROJECT_EVIDENCE.md) ·
[Read the detection model](docs/DETECTION_MODEL.md)

![Current PhishGuard AI CLI validation using public-safe inputs](docs/assets/phishguard-demo.svg?v=20260824-3)

The image shows current CLI output from reserved, public-safe inputs. The
latest validation completed 199 tests with 2 skips and 1 tracked expected
failure. Reproduction commands and limitations are recorded in
[Project Evidence](docs/PROJECT_EVIDENCE.md).

## Why PhishGuard

| Capability | What it provides |
| --- | --- |
| Explainable scoring | `SAFE`, `SUSPICIOUS`, or `PHISHING` with the signals that affected the result |
| Private by default | URL and email scoring runs locally; only opt-in RDAP domain-age checks use a third party |
| Automation-ready | Native JSON, SARIF 2.1.0, GitHub Action, Code Scanning, and batch scanning |
| Multiple interfaces | CLI, Python API, browser demo, Chromium extension prototype, and REST server |
| Reviewable implementation | Standard-library Python, documented weights, regression fixtures, and cross-language parity tests |

PhishGuard is designed as a lightweight supporting signal for security
engineers, SOC analysts, developers, and educators. It is not a replacement
for enterprise email security, threat-intelligence feeds, asset context, or a
statistically trained production model.

## Quick Start

Python 3.10 or later is required. Install the verified `v0.5.1` wheel from
GitHub Releases:

```bash
python -m pip install \
  https://github.com/omobolajiadeyan/phishguard-ai/releases/download/v0.5.1/phishguard_ai-0.5.1-py3-none-any.whl
phishguard --help
```

Run a safe example and a suspicious synthetic example:

```bash
phishguard url "https://www.example.com/account" --plain
phishguard url "http://192.0.2.10/secure-login/verify" --verbose --plain
```

Both inputs are reserved for documentation and do not contact live phishing
infrastructure. See the [one-minute demo](docs/QUICK_DEMO.md) or the
[five-minute evaluator guide](docs/EVALUATOR_GUIDE.md) for a guided review.

## Common Workflows

### URLs, email, and saved messages

```bash
# URL with an explainable feature breakdown
phishguard url "http://paypa1-secure-login.xyz/verify" --verbose

# Email with authentication evidence from a trusted receiver
phishguard email \
  --subject "URGENT: Your account has been suspended" \
  --body "Click here immediately to verify your account." \
  --authentication-results "mx.example; spf=fail; dkim=fail; dmarc=fail"

# Saved email; trust only the named receiver's Authentication-Results header
phishguard eml suspicious.eml --trusted-authserv-id mx.example --verbose
```

SPF, DKIM, and DMARC failures are supporting evidence—not automatic proof of
phishing. PhishGuard parses supplied results; it does not perform DNS policy
validation or cryptographic signature verification.

### JSON, SARIF, and batch output

```bash
phishguard batch data/urls.txt --output results.json
phishguard batch data/urls.txt --format sarif --output phishguard.sarif
```

See [GitHub Code Scanning](docs/GITHUB_CODE_SCANNING.md) and the
[email output examples](docs/EMAIL_OUTPUT_EXAMPLES.md) for integration-ready
examples.

### GitHub Action

```yaml
- name: Scan URL with PhishGuard AI
  uses: omobolajiadeyan/phishguard-ai@v0.5.1
  with:
    url: https://example.com
    sarif-output: phishguard-results.sarif
```

The [Marketplace listing](https://github.com/marketplace/actions/phishguard-ai-phishing-detector)
documents all inputs. Teams evaluating the action can follow the
[adoption guide](docs/ADOPTION.md).

### Python API

```python
from model import classify, score_url

probability, features = score_url("https://www.example.com/account")
print(classify(probability), probability, features)
```

See the [Python API guide](docs/PYTHON_API.md) for supported URL, email, and
extra-feature contracts.

### Browser and REST API

The [live browser demo](https://omobolajiadeyan.github.io/phishguard-ai/)
runs the JavaScript scoring port entirely in the browser. Python/JavaScript
parity tests guard against model drift. The
[Chromium extension prototype](docs/BROWSER_EXTENSION.md) uses the same local
scoring model and does not request browsing history.

For local service integrations:

```bash
phishguard serve --port 8765
curl http://127.0.0.1:8765/healthz
curl -X POST http://127.0.0.1:8765/v1/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure-login.xyz/verify"}'
```

The server binds to `127.0.0.1` by default and has no authentication. Review
the network controls before exposing it beyond the local machine.

## Detection Model and Privacy

PhishGuard applies a hand-tuned heuristic model to explainable URL and email
features, including:

- hostname structure, entropy, IP literals, suspicious TLDs, and path depth;
- phishing keywords, typosquatting distance, IDN signals, and free hosting;
- email urgency, link density, attachment language, and capitalization;
- optional SPF, DKIM, and DMARC results supplied by a trusted receiver.

Default scoring is local. The opt-in `--check-domain-age` option performs an
RDAP lookup through `rdap.org`; failures degrade to “no signal.” Redirect
resolution also requires network access and includes SSRF protections.

Read [Detection Model](docs/DETECTION_MODEL.md) for weights, trust boundaries,
known blind spots, and the requirements for scoring changes.

## Evidence and Limitations

The checked-in regression fixture currently reports 7 true positives, 7 true
negatives, 0 false positives, and 0 false negatives. A separate public-safe
fixture reports 5 true positives and 5 true negatives. These small fixtures
detect regressions; they are not population-level accuracy or calibration
claims.

Realistic stress testing also preserves three known false-positive cases in an
eight-case branded-path fixture. Those gaps are documented instead of hidden.
For dated live-traffic results, methodology, and rerun commands, see:

- [Project Evidence](docs/PROJECT_EVIDENCE.md)
- [Benchmark](docs/BENCHMARK.md)
- [Public Evidence and Adoption](docs/PUBLIC_EVIDENCE.md)
- [Detection Model](docs/DETECTION_MODEL.md)

Run the local verification yourself:

```bash
python -m unittest discover -s tests -v
python tools/repository_policy.py
python tools/evaluate_url_benchmark.py
python tools/evaluate_url_benchmark.py data/public_benchmark_urls.jsonl
```

## Documentation

| Guide | Purpose |
| --- | --- |
| [Use Cases](docs/USE_CASES.md) | CI, SOC triage, education, email authentication, and benchmark workflows |
| [Development](docs/DEVELOPMENT.md) | Local setup, verification, and architecture boundaries |
| [Browser Extension](docs/BROWSER_EXTENSION.md) | Install and evaluate the Chrome/Edge prototype |
| [Windows Install](docs/WINDOWS_INSTALL.md) | Verify the release on Windows |
| [Support](SUPPORT.md) | Ask questions, report bugs, or disclose vulnerabilities |
| [Roadmap](ROADMAP.md) | Current priorities and planned work |

## Contributing

Contributions from security analysts, Python developers, students, researchers,
and first-time open-source contributors are welcome.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), the
[first-contribution guide](docs/FIRST_CONTRIBUTION.md), and a scoped
[`good first issue`](https://github.com/omobolajiadeyan/phishguard-ai/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22).
Security issues should follow [SECURITY.md](SECURITY.md), not a public issue.

## Maintainer and License

Created and maintained by
[Omobolaji Adeyan](https://github.com/omobolajiadeyan), cybersecurity engineer.

[GitHub](https://github.com/omobolajiadeyan) ·
[Website](https://omobolajiadeyan.com) ·
[LinkedIn](https://www.linkedin.com/in/oeadeyan) ·
[Security contact](mailto:omobolaji.adeyan@gmail.com)

A [FreNiMi](https://frenimi.com) product, released under the
[MIT License](LICENSE). Citation metadata is available in [CITATION.cff](CITATION.cff).
