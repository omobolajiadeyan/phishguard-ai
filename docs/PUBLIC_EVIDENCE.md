# Public Evidence and Adoption

PhishGuard AI is maintained as a practical security tool, not a black-box
claim. This page records what the project can currently prove, how to reproduce
that evidence, and what would strengthen future adoption.

## Current Public Evidence

| Evidence | Location | Notes |
| --- | --- | --- |
| GitHub Marketplace Action | https://github.com/marketplace/actions/phishguard-ai-phishing-detector | Reusable action for CI-based URL and email scanning. |
| Latest release | https://github.com/omobolajiadeyan/phishguard-ai/releases/tag/v0.5.1 | Published release with installable package artifacts. |
| Project benchmark | [BENCHMARK.md](BENCHMARK.md) | Regression fixture metrics, plus live-traffic validation showing recall improving from 55.0% to 65.7% (2026-08-24) with the opt-in domain-age check enabled. |
| Detection model | [DETECTION_MODEL.md](DETECTION_MODEL.md) | Feature semantics, limitations, scoring-change requirements, and the opt-in RDAP domain-age lookup. |
| Code scanning workflow | [GITHUB_CODE_SCANNING.md](GITHUB_CODE_SCANNING.md) | SARIF integration path for GitHub Code Scanning. |
| Adoption guide | [ADOPTION.md](ADOPTION.md) | Safe path for third-party workflow examples and showcase reports. |
| First contribution guide | [FIRST_CONTRIBUTION.md](FIRST_CONTRIBUTION.md) | Scoped path for new contributors. |

## What the Metrics Mean

The checked-in benchmark is a 14-sample regression fixture. It is useful for
detecting behavior changes across releases, but it is not a population-level
accuracy claim and should not be presented as independent model validation.

Separately, [BENCHMARK.md](BENCHMARK.md) also records live-traffic
validation runs against real, rotating public feeds (OpenPhish phishing
URLs, Tranco top-domain legitimate URLs) — most recently on 2026-08-24,
showing the opt-in domain-age check raising recall from 55.0% to 65.7% with
zero new false positives. This is closer to real-world signal than the
fixture, but it's still a few-hundred-URL sample against two specific public
feeds on one date, not a comprehensive accuracy claim — treat it the same
way: reproducible, dated, and bounded, not definitive.

PhishGuard AI is strongest when used as an explainable supporting signal in a
security workflow:

- flag suspicious URLs or email evidence in CI;
- produce JSON or SARIF for downstream tools;
- explain which features contributed to a score;
- keep data local by avoiding external API calls.

## Adoption Signals to Build Next

The next useful public signals are:

- third-party workflow examples using the Marketplace Action;
- independent issue reports or pull requests from users;
- documented false-positive and false-negative cases;
- release notes tied to reproducible benchmark changes;
- short technical posts explaining trust boundaries and model limitations.

## Maintainer Position

PhishGuard AI should stay conservative. Pass results for SPF, DKIM, or DMARC do
not lower risk on their own because authenticated infrastructure can still send
malicious content. Authentication failures are supporting evidence, not proof of
phishing.

Contributions that improve tests, documentation, parser safety, SARIF output,
or benchmark transparency are preferred over broad model changes.

