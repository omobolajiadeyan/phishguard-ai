# PhishGuard AI

[![Tests](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/tests.yml)
[![CodeQL](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/codeql.yml/badge.svg)](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/omobolajiadeyan/phishguard-ai?style=flat-square)](https://github.com/omobolajiadeyan/phishguard-ai/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Maintainer](https://img.shields.io/badge/Maintainer-Omobolaji_Adeyan-0A66C2?style=flat-square)](https://github.com/omobolajiadeyan)
[![Contributions](https://img.shields.io/badge/Contributions-Welcome-2ea44f?style=flat-square)](CONTRIBUTING.md)

An explainable phishing detection engine that analyzes URLs and emails in real
time using feature engineering and heuristic risk scoring. It works offline
and requires no API key.

Created and maintained by
[Omobolaji Adeyan](https://github.com/omobolajiadeyan), a cybersecurity
engineer focused on practical Python security tooling, threat detection, and
security automation.

Built because most phishing detection tools are either black-box cloud services or require expensive ML training pipelines. PhishGuard runs entirely offline and explains exactly *why* it flagged something.

## How It Works

Rather than relying only on blocklists, PhishGuard extracts behavioral and
structural features from URLs and email content, then applies an explainable,
hand-tuned heuristic model. The current weights are informed by common
phishing indicators and protected by regression tests; they have not yet been
validated as a statistically trained model.

**URL features analyzed:**
- Domain entropy (randomly generated domains score high)
- IP address in URL (almost always malicious)
- Suspicious TLDs (`.xyz`, `.tk`, `.ml`, `.ga`, `.click`)
- Phishing keyword density (`verify`, `suspended`, `account`, `secure`, etc.)
- Subdomain depth, path depth, digit ratio, special character density
- Punycode and Unicode hostname indicators, weighted conservatively as context

**Email features analyzed:**
- Urgency language (`action required`, `account suspended`, `verify now`)
- Link and URL density
- ALL CAPS word usage
- Attachment mentions
- Exclamation mark frequency

## Features

- Real-time URL and email scoring with probability output
- Batch scan a list of URLs from a file
- Explainable results — see which features triggered the alert
- Three verdict levels: `SAFE`, `SUSPICIOUS`, `PHISHING`
- JSON export for integration into SOC workflows
- SARIF 2.1.0 export for GitHub Code Scanning and CI security pipelines
- Zero dependencies — pure Python standard library
- Offline — no data sent anywhere

## Installation

```bash
git clone https://github.com/omobolajiadeyan/phishguard-ai.git
cd phishguard-ai
python --version  # Python 3.10+ required
python -m pip install .
python -m unittest discover -s tests -v
```

Installation provides a `phishguard` command. Running the source file directly
remains supported for development.

## Usage

```bash
# Analyze a single URL
phishguard url "http://paypa1-secure-login.xyz/verify"

# Analyze with feature breakdown
phishguard url "https://google.com" --verbose

# Analyze an email
phishguard email \
  --subject "URGENT: Your account has been suspended" \
  --body "Click here immediately to verify your account or it will be deleted."

# Batch scan a list of URLs
phishguard batch data/urls.txt

# Use ASCII-only output in legacy terminals or CI logs
python phishguard.py url "https://google.com" --plain
python phishguard.py batch data/urls.txt --no-unicode

# Export results to JSON
phishguard batch data/urls.txt --output results.json

# Export actionable findings to SARIF 2.1.0
phishguard batch data/urls.txt \
  --format sarif \
  --output phishguard.sarif
```

See the [GitHub Code Scanning guide](docs/GITHUB_CODE_SCANNING.md) for a
copy-ready workflow using GitHub's official SARIF upload action.
See the [detection model documentation](docs/DETECTION_MODEL.md) for feature
semantics, limitations, and the evidence required for scoring changes.

## Reproducible Benchmark

Run the public-safe URL regression fixture with:

```bash
python tools/evaluate_url_benchmark.py
```

The command reports ordered predictions, confusion-matrix counts, precision,
recall, and false-positive rate. These are fixture metrics for detecting
regressions, not population-level accuracy or calibration estimates. See the
[benchmark documentation](docs/BENCHMARK.md) for the data scope and reporting
rules.

## Example Output

```
  PHISHGUARD AI
  AI-powered phishing detection

────────────────────────────────────────────────────────────
  URL     : http://paypa1-secure-login.xyz/verify
  Verdict : PHISHING
  Risk    : ████████████████████  94.2%

  Feature breakdown:
    url_length           : 38
    has_ip_address       : 0
    suspicious_tld       : 1   *
    phishing_keywords    : 2   *
    has_https            : 0   *
    url_entropy          : 3.84 *
```

## Architecture

```
phishguard-ai/
├── phishguard.py    # CLI entrypoint — commands: url, email, batch
├── features.py      # Feature extraction (URL + email)
├── model.py         # Weighted scoring model + sigmoid normalisation
├── reporting.py     # Native JSON and SARIF 2.1.0 serialization
├── data/
│   └── urls.txt     # Sample URLs for batch testing
└── README.md
```

## Contributing

Contributions are welcome from security analysts, Python developers, students,
researchers, and first-time open-source contributors.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before starting.
- Follow the reproducible [development workflow](docs/DEVELOPMENT.md).
- Pick a scoped task from the
  [open issues](https://github.com/omobolajiadeyan/phishguard-ai/issues).
- Use [Discussions](https://github.com/omobolajiadeyan/phishguard-ai/discussions)
  for design questions and detection ideas.
- See [ROADMAP.md](ROADMAP.md) for current priorities.
- Accepted contributors are credited in [AUTHORS.md](AUTHORS.md).
- Releases and notable changes are recorded in [CHANGELOG.md](CHANGELOG.md).
- Release artifacts follow the documented [release process](docs/RELEASING.md)
  with checksums and signed build provenance.

## Project Leadership

- **Creator and Lead Maintainer:** [Omobolaji Adeyan](https://github.com/omobolajiadeyan)
- **LinkedIn:** [linkedin.com/in/oeadeyan](https://www.linkedin.com/in/oeadeyan)
- **Security contact:** [omobolaji.adeyan@gmail.com](mailto:omobolaji.adeyan@gmail.com)

## Author

**Omobolaji Adeyan** - Cybersecurity Engineer
[GitHub](https://github.com/omobolajiadeyan)

## License and Citation

PhishGuard AI is available under the [MIT License](LICENSE). The project may
be cited using the metadata in [CITATION.cff](CITATION.cff).
