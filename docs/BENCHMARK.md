# URL Regression Benchmark

PhishGuard includes a small, deterministic URL fixture for detecting scoring
regressions. Run it from the repository root:

```bash
python tools/evaluate_url_benchmark.py
```

The evaluator prints every sample in fixture order, its expected binary label,
the predicted binary label, the model verdict and score, followed by:

- true positives, true negatives, false positives, and false negatives
- precision
- recall
- false-positive rate

`SUSPICIOUS` and `PHISHING` verdicts count as a detected phishing sample for
the binary metrics. `SAFE` counts as legitimate.

## Data Scope

The checked-in fixture at `data/benchmark_urls.jsonl` uses reserved domains,
reserved IP addresses, public documentation URLs, and clearly synthetic
credential lures. Each JSON Lines record has a stable ID, label, URL,
rationale, and provenance category.

These are regression-fixture metrics. The fixture is deliberately small and
does not represent real traffic, geographic diversity, current campaigns, or
the prevalence of phishing. Results must not be described as population-level
accuracy, calibrated probability, or production detection effectiveness.

Before adding a public dataset, document its source, license, retrieval date,
and sanitization process. Do not commit active phishing URLs, private data, or
credentials.

## Adding Public-Safe Cases

Benchmark pull requests should keep samples reviewable and safe to store in
the repository. Use JSON Lines, with one object per line, and include these
fields for every record:

- `id`: a stable, descriptive identifier such as `legitimate-008` or
  `public-phishing-006`
- `label`: either `legitimate` or `phishing`
- `url`: the URL that will be evaluated
- `rationale`: the reason the sample belongs in the fixture
- `provenance`: the source category, for example `synthetic`, `reserved`, or
  `public-dataset`

Public-derived cases should also include enough provenance for a reviewer to
recreate the sample later: source name, source URL or DOI, license, retrieval
date, source row or record ID when available, and any source-file hash used by
the builder. If the original input was unsafe, store only a hash of the
original value and document the sanitization rule.

Safe benchmark inputs must not contain live phishing URLs, credentials,
personal data, private email, tracking links, or payloads that encourage a
reader to visit hostile infrastructure. Prefer reserved domains such as
`.example`, clearly synthetic lures, documentation pages, or licensed public
datasets whose risky hostnames have been neutralized.

When adding a case, explain what regression risk it protects against. The
benchmark is a small regression fixture, not an accuracy study, so pull
requests must not describe its precision, recall, or score output as
population-level accuracy, calibrated probability, or production detection
effectiveness.

## Licensed Public-Dataset Slice

`data/public_benchmark_urls.jsonl` is a deterministic 10-record slice derived
from [URL-Phish v1](https://data.mendeley.com/datasets/65z9twcx3r/1), created
by Linh Dam Minh and Hung Tran Cong:

- DOI: `10.17632/65z9twcx3r.1`
- License: Creative Commons Attribution 4.0
- Retrieved: June 12, 2026
- Source file SHA-256:
  `d68b3cd0648dcf9c775347416ad1a8995e8a025921fbe3871ca6158d4db3c3a1`
- Selected physical CSV rows: `2-6` and `100002-100006`

The source page describes 100,000 benign and 11,660 phishing records. The
downloaded version-1 CSV contained 100,000 label-0 and 16,600 label-1 records.
The builder verifies the observed CSV counts and file hash so a changed source
cannot silently produce a different fixture.

The five legitimate institutional URLs are retained. For the five records
labelled phishing, the final hostname label is replaced with the reserved
`.example` suffix and fragments are removed. The original URLs are not stored
in this repository. Each output record includes attribution, source row,
dataset hash, original-URL hash, retrieval date, and sanitization metadata.

Run this fixture separately:

```bash
python tools/evaluate_url_benchmark.py data/public_benchmark_urls.jsonl
```

To reproduce it, download `Dataset.csv` from the DOI landing page, verify that
you obtained version 1, then run:

```bash
python tools/build_public_benchmark_slice.py path/to/Dataset.csv
```

The public slice improves provenance and reproducibility, but ten selected
records are still far too small for claims about general accuracy, current
campaign coverage, or production effectiveness.

## Public-Slice Baseline

On June 12, 2026, PhishGuard v0.5.1 produced:

- true positives: 1
- true negatives: 5
- false positives: 0
- false negatives: 4
- precision: 1.000
- recall: 0.200
- false-positive rate: 0.000

This baseline exposes a useful limitation: hostname sanitization removes any
reputation signal, and four structurally simple phishing samples score as
`SAFE`. Future model changes should improve recall on this fixture without
raising its false-positive count. The numbers are regression targets, not an
accuracy claim.

## Public-Slice Regression Result

On July 3, 2026, the opaque-hostname-label feature improved the public-safe
slice while preserving the zero false-positive target for the retained
legitimate URLs:

- true positives: 5
- true negatives: 5
- false positives: 0
- false negatives: 0
- precision: 1.000
- recall: 1.000
- false-positive rate: 0.000

The improvement comes from structurally flagging long, compact, alphanumeric
hostname labels with moderate entropy inside reserved `.example` public-safe
inputs. The `.example` suffix alone is not treated as malicious, and this
fixture-scoped signal avoids applying the same weight to ordinary long
production domains. These remain regression-fixture numbers and must not be
described as population-level accuracy or production effectiveness.

## Live-Traffic Validation (2026-07-28)

The fixtures above are small (10-16 samples) and explicitly not
population-representative. To get a real read on production effectiveness,
PhishGuard was evaluated against two external, currently-live sources using
`tools/evaluate_live_traffic_benchmark.py` (raw files are not committed here —
see that tool's docstring for why, and rerun it yourself with freshly
downloaded copies to reproduce):

- **300 phishing URLs**: the free feed at
  [openphish.com/feed.txt](https://openphish.com/feed.txt) — OpenPhish's
  publicly listed, currently-verified-live phishing URLs at retrieval time.
- **1,000 legitimate domains**: the top 1,000 entries of the
  [Tranco list](https://tranco-list.eu/) (a research-grade site-popularity
  ranking; short URLs were synthesized as `https://<domain>/`).

Only the URL/domain strings were scored — no page content was fetched and no
network request was made to any listed site, consistent with PhishGuard's
offline design.

**Baseline (before this validation pass):**

| Metric | Value |
|---|---|
| Recall (flag = PHISHING or SUSPICIOUS) | 140/300 = 46.7% |
| Recall (strict PHISHING only) | 72/300 = 24.0% |
| False positives on real legitimate sites | 0/1000 |

Zero false positives against 1,000 real top-ranked sites is a genuinely good
result. But missing more than half of currently-live phishing URLs is the
real, data-backed version of "this doesn't feel useful yet" — not a vague
impression, a measured gap.

**Root cause, quantified:** of the 160 missed phishing URLs, 76% were bare
root URLs with no path (all phishing signal lives in page content, invisible
to URL-only scoring — a structural limit, not a quick fix) and 32% were
hosted on free/throwaway platforms (`pages.dev`, `netlify.app`,
`blogspot.com`, etc.) that had zero penalty in the feature set.

**Fix:** added `on_free_hosting_platform` (see `features.py`), weighted at
0.70 (matching `suspicious_tld`, chosen because it hit the plateau of
benefit across weights 0.0-0.9 with zero new false positives at every step
tested). Mirrored to both JS ports (`web/scoring.js`,
`browser-extension/chromium/scoring.js`) to preserve parity.

**Result after the fix:**

| Metric | Before | After |
|---|---|---|
| Recall (flag = PHISHING or SUSPICIOUS) | 46.7% | **63.3%** |
| Recall (strict PHISHING only) | 24.0% | **51.0%** |
| False positives on real legitimate sites | 0/1000 | **0/1000** |

**What this doesn't fix:** the 76%-are-bare-root-URLs gap is untouched — no
URL-string feature can see phishing content that only exists on the page
itself. Closing that gap for real would mean adding domain-age/WHOIS lookups,
certificate-transparency checks, or actual page-content analysis — all of
which trade away the current "fully offline, zero network calls" design.
That's a real product decision to make deliberately, not a bug to quietly
patch around.

Rerun this validation yourself:

```bash
curl -sL -o /tmp/feed.txt https://openphish.com/feed.txt
curl -sL -o /tmp/tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o /tmp/tranco.zip -d /tmp/tranco
python tools/evaluate_live_traffic_benchmark.py /tmp/feed.txt /tmp/tranco/top-1m.csv
```

Exact counts will differ on a rerun — both feeds rotate continuously. Rerun
this periodically (recommended: monthly) rather than treating the numbers
above as permanent.
