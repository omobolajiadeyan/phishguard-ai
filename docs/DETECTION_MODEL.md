# Detection Model

PhishGuard uses an explainable heuristic model. It does not currently ship a
trained machine-learning model, call a remote reputation service, or claim
that a score is a calibrated real-world probability.

## Processing

1. `features.py` extracts structural URL or email indicators.
2. `model.py` multiplies each indicator by a reviewable weight.
3. A bias and sigmoid transform produce a stable score from 0 to 1.
4. `classify()` maps the score to `SAFE`, `SUSPICIOUS`, or `PHISHING`.

The score is useful for ranking and decision support. It should not be treated
as the measured probability that a target is malicious.

## Current URL Indicators

- URL, hostname, path, and subdomain length or depth
- IP-address hosts and explicit ports
- HTTPS presence
- Suspicious top-level domains
- Phishing-related words
- Digit and special-character density
- Hostname entropy
- Punycode labels and Unicode hostname presence

IDN indicators are contextual signals with deliberately modest weights.
Internationalized domains are legitimate and are not classified as phishing
from either indicator alone. Confusable-character and brand-impersonation
matching are not currently implemented.

## Current Email Indicators

- URLs and link-like language
- Urgency phrases
- Exclamation marks and uppercase words
- HTML tags
- Attachment language
- Message length

## Change Standard

A detection change should include:

- A named and explainable feature rather than an opaque score adjustment.
- Synthetic or reserved-domain positive cases.
- Legitimate negative cases that guard against false positives.
- Before-and-after scores and verdicts.
- A rationale for the weight and its interaction with existing features.
- A passing full test suite on every supported Python version.

Threshold or weight changes should be deferred when the available examples
cannot distinguish an improvement from overfitting.

## Known Limitations

- The model does not fetch pages, follow redirects, or inspect certificates.
- It does not query DNS, domain age, blocklists, or threat intelligence.
- It does not validate SPF, DKIM, or DMARC.
- Unicode confusable-character and brand-impersonation matching are not implemented.
- The current regression set is small and is not a population-level accuracy
  benchmark.

Issue #3 tracks a labeled evaluation benchmark for reproducible regression
metrics. Population-level accuracy or calibration claims require a larger,
representative dataset with documented provenance.
