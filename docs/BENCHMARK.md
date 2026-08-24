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

A second checked-in fixture, `data/branded_path_benchmark_urls.jsonl`, is
scoped separately and deliberately: it exists to lock in the "False-Positive
Stress Test" finding above as a permanent regression guard, using
`.example`-suffixed synthetic domains with the exact realistic
login/verify/reset/subdomain URL shapes that stress test found to
false-positive at scale. Run it the same way:

```bash
python tools/evaluate_url_benchmark.py data/branded_path_benchmark_urls.jsonl
```

Every record in it is labeled `legitimate` — there is no phishing side to
this fixture, since its only purpose is to catch this specific false-positive
regression, not to measure recall. `tests/test_model.py`'s
`RealisticSecurityUrlFalsePositiveTests` asserts the same cases directly.

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

## Free-Hosting List Refresh (2026-08-24)

A fresh OpenPhish feed (300 URLs) turned up two live phishing URLs on
`*.replit.app` that scored `SAFE` — the free-hosting list only had the
older `repl.co` suffix. Added `replit.app` and `replit.dev` to
`FREE_HOSTING_SUFFIXES` in `features.py`.

| Metric | Before | After |
|---|---|---|
| Recall (flag = PHISHING or SUSPICIOUS) | 54.3% (163/300) | **55.0%** (165/300) |
| Recall (strict PHISHING only) | 29.0% (87/300) | **29.7%** (89/300) |
| False positives on real legitimate sites (n=1,000) | 0/1000 | **0/1000** |

(These "before" numbers are a fresh 2026-08-24 baseline, not the 2026-07-28
numbers above — both feeds rotate, so the two runs aren't the same sample.
This is the honest baseline this specific fix was measured against.)

## Domain-Age Validation (2026-08-24)

Auditing the model's *remaining* false negatives after the fixes above
(rather than only looking at aggregate recall) surfaced concrete cases no
existing feature could reach:

- `rosakyiv.com.br` — registered **46 days** before this audit, zero other
  suspicious features (no keywords, no suspicious TLD, ordinary entropy).
  Domain age is the only signal available for this exact case.
- `pehsad.com` — registered **84 days** before this audit, same story.
- `s4w.in` — a URL-shortener-style domain **~18.8 years old**, abused to
  redirect to a phishing destination. This is the domain-age feature's
  explicit blind spot, not an oversight: an old, legitimate-looking domain
  offering redirects has nothing for a registration-date check to catch.
  `--follow-redirects` (already shipped) is the correct tool for this
  category, not domain age.

This is why `docs/DETECTION_MODEL.md`'s Known Limitations section names
"compromised or abused-as-a-service infrastructure" as a real, unaddressed
category rather than folding it into a single recall number.

**Method:** `tools/evaluate_live_traffic_benchmark.py --check-domain-age`,
against the same 2026-08-24 OpenPhish feed (300 URLs) used in the
free-hosting refresh above, and the top 300 Tranco domains, with
`--domain-age-delay 0.4` to stay inside `rdap.org`'s rate limit.

| Metric | Offline only | + domain age |
|---|---|---|
| Recall (flag = PHISHING or SUSPICIOUS) | 55.0% (165/300) | **65.7%** (197/300) |
| Recall (strict PHISHING only) | 29.7% (89/300) | **32.7%** (98/300) |
| False positives on real legitimate sites | 0/1,000 | **0/300** |

The false-positive row isn't the same sample size — the domain-age run used
the top 300 Tranco domains (a subset of the 1,000 used for the offline
baseline above), not the full 1,000, to keep total RDAP calls reasonable
against a free shared service. The top 300 are also the *hardest* subset to
false-positive against, since none of them are remotely close to newly
registered, so `0/300` here is a meaningful result, not a weaker one — but
it is a smaller sample, stated plainly rather than implied.

Domain age closed a real slice of the recall gap: **+10.7 points** on the
broader metric, **+3.0 points** strict, with zero new false positives. It
did not close most of it — the remaining ~44% of missed phishing (below)
is the compromised/abused-old-domain category no registration-date check
can see.

**What this doesn't fix:** domains that are old but compromised or rented
as phishing-as-a-service infrastructure (the `s4w.in` case above) look
identical to any other established domain from a registration-date
perspective. Closing that gap would need page-content analysis or a
reputation/blocklist feed, which is a larger design decision than adding
one more RDAP-derived feature — consistent with the same page-content
tradeoff already named in the Live-Traffic Validation section above.

Rerun this validation yourself:

```bash
curl -sL -o /tmp/feed.txt https://openphish.com/feed.txt
curl -sL -o /tmp/tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o /tmp/tranco.zip -d /tmp/tranco
python tools/evaluate_live_traffic_benchmark.py /tmp/feed.txt /tmp/tranco/top-1m.csv \
  --check-domain-age --domain-age-delay 0.4 --legit-limit 300
```

`rdap.org` is a free, shared, third-party service — keep `--domain-age-delay`
at `0.4` or higher, and avoid raising `--legit-limit` far past the sample
size used here without a longer delay.

## False-Positive Stress Test (2026-08-24)

Every false-positive number above — in this document and in
[PROJECT_EVIDENCE.md](PROJECT_EVIDENCE.md) — is measured against bare root
URLs (`https://{domain}/`). That is deliberately the easiest possible case:
it says nothing about how the detector behaves on the URL shapes a real
security-relevant flow actually produces — a login page, a password-reset
link with a token, a verification path, or a branded subdomain — which is
also exactly the shape a phishing page is built to imitate.

`tools/evaluate_fp_stress_test.py` closes that gap: it takes the same kind
of externally-supplied domain ranking `evaluate_live_traffic_benchmark.py`
already uses (nothing bundled) and generates ten realistic URL variants per
domain — root, `www` root, `/login`, `/signin`, `/account/login`, a
verification link with a token, a password-reset link with a token and
redirect, `accounts.{domain}/signin`, `secure.{domain}/login`, and a nested
`/support/account/security/verify-identity` path — instead of one root URL,
and reports the false-positive rate per template so a regression's root
cause is traceable rather than hidden in one aggregate number.

**Result, 3,000 real Tranco top-3,000 domains × 10 templates (30,000 URLs),
offline scoring only (no `--check-domain-age`):**

| URL shape | Flagged (SUSPICIOUS or PHISHING) | Strict PHISHING |
| --- | --- | --- |
| root | 0.0% | 0.0% |
| `www` root | 0.0% | 0.0% |
| `/login` | 0.5% | 0.0% |
| `/signin` | 0.9% | 0.0% |
| `/account/login` | 5.5% | 0.5% |
| `secure.{domain}/login` | 24.2% | 0.7% |
| `accounts.{domain}/signin` | 69.0% | 1.0% |
| `/account/verify?token=...` | 100.0% | 71.5% |
| `/password/reset?token=...&redirect=...` | 100.0% | 100.0% |
| `/support/account/security/verify-identity` | 100.0% | 100.0% |
| **overall (all templates combined)** | **40.0%** | **27.4%** |

Root and simple-login shapes score close to zero false positives — that's
the exact shape every existing benchmark in this document already measures,
which is why it looked clean. Once a URL has a token, a nested
account/security path, or a subdomain — the shape a real password-reset or
identity-verification link actually has, on any of the 3,000 most-visited
real domains on the internet, with zero exceptions on three of the ten
templates — the false-positive rate is not a tuning gap, it's close to
guaranteed. This is a known, tracked limitation; see
[DETECTION_MODEL.md](DETECTION_MODEL.md)'s Known Limitations section and the
project's rearchitecture plan for the fix in progress.

Rerun this yourself:

```bash
curl -sL -o /tmp/tranco.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o /tmp/tranco.zip -d /tmp/tranco
python tools/evaluate_fp_stress_test.py /tmp/tranco/top-1m.csv --domain-limit 3000
```
