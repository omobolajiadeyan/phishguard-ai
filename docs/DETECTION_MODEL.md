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
- Optional categorical SPF, DKIM, and DMARC results parsed from a trusted
  receiver's `Authentication-Results` header

Authentication failures are supporting signals, not proof of phishing. SPF
failure has a weight of `0.08`, DKIM failure `0.10`, and DMARC failure `0.18`.
SPF softfail contributes half of the SPF failure value. Pass, neutral, none,
missing, malformed, and unsupported results add no risk and never lower the
score. This keeps a legitimate forwarded message with an SPF failure from
being classified as malicious solely because of authentication.

The parser is deliberately limited rather than RFC-complete. It normalizes
SPF, DKIM, and DMARC values to `pass`, `fail`, `softfail`, `neutral`, `none`,
or `unknown`. Callers must provide the final trusted receiver's header:
attacker-supplied `Authentication-Results` values are not independently
trustworthy, and PhishGuard does not validate cryptographic signatures or DNS
policy itself.

For the checked-in regression examples:

| Example | Content only | With authentication results |
| --- | --- | --- |
| Forwarded legitimate message (`spf=fail`, `dkim=pass`, `dmarc=pass`) | `0.3149 SAFE` | `0.3595 SAFE` |
| Synthetic lure (`spf=fail`, `dkim=fail`, `dmarc=fail`) | `0.6525 SUSPICIOUS` | `0.8220 PHISHING` |

These examples demonstrate expected model behavior, not population-level
accuracy. Forwarding and mailing lists can legitimately break SPF or DKIM, so
authentication failures remain modest supporting signals.

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
- It parses supplied authentication results but does not independently
  validate SPF, DKIM, DMARC, DNS policy, or cryptographic signatures.
- Unicode confusable-character and brand-impersonation matching are not implemented.
- The current regression set is small and is not a population-level accuracy
  benchmark.

Issue #3 tracks a labeled evaluation benchmark for reproducible regression
metrics. Population-level accuracy or calibration claims require a larger,
representative dataset with documented provenance.
