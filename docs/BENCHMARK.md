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
