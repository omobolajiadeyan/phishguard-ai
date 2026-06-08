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
