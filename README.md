# PhishGuard AI

[![Tests](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/tests.yml/badge.svg)](https://github.com/omobolajiadeyan/phishguard-ai/actions/workflows/tests.yml)

An explainable phishing detection engine that analyzes URLs and emails in real
time using feature engineering and calibrated probabilistic scoring. It works
offline and requires no API key.

Built because most phishing detection tools are either black-box cloud services or require expensive ML training pipelines. PhishGuard runs entirely offline and explains exactly *why* it flagged something.

## How It Works

Rather than relying on blocklists (which are always out of date), PhishGuard extracts behavioral and structural features from URLs and email content, then scores them using weights derived from phishing research datasets (PhishTank, APWG eCrime reports).

**URL features analyzed:**
- Domain entropy (randomly generated domains score high)
- IP address in URL (almost always malicious)
- Suspicious TLDs (`.xyz`, `.tk`, `.ml`, `.ga`, `.click`)
- Phishing keyword density (`verify`, `suspended`, `account`, `secure`, etc.)
- Subdomain depth, path depth, digit ratio, special character density

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
- Zero dependencies — pure Python standard library
- Offline — no data sent anywhere

## Installation

```bash
git clone https://github.com/oadeyan/phishguard-ai.git
cd phishguard-ai
python --version  # Python 3.10+ required
```

## Usage

```bash
# Analyze a single URL
python phishguard.py url "http://paypa1-secure-login.xyz/verify"

# Analyze with feature breakdown
python phishguard.py url "https://google.com" --verbose

# Analyze an email
python phishguard.py email \
  --subject "URGENT: Your account has been suspended" \
  --body "Click here immediately to verify your account or it will be deleted."

# Batch scan a list of URLs
python phishguard.py batch data/urls.txt

# Export results to JSON
python phishguard.py batch data/urls.txt --output results.json
```

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
├── data/
│   └── urls.txt     # Sample URLs for batch testing
└── README.md
```

## Roadmap

- [ ] Train a proper scikit-learn Random Forest on PhishTank dataset
- [ ] Add WHOIS domain age lookup (new domains = higher risk)
- [ ] Browser extension version
- [ ] REST API wrapper for SOC tool integration
- [ ] Add email header analysis (SPF/DKIM/DMARC checks)

## Author

**Omobolaji Adeyan** - Cybersecurity Engineer
[GitHub](https://github.com/omobolajiadeyan)
