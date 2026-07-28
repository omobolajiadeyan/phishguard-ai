# Project Evidence

This page records reproducible technical and community evidence for
PhishGuard AI. Counts are a dated snapshot, not claims of production adoption.

## Technical Evidence

Snapshot verified on July 28, 2026:

- URL regression fixture: 14 public-safe samples
- Confusion matrix: 7 true positives, 7 true negatives, 0 false positives,
  and 0 false negatives
- Fixture precision: 1.000
- Fixture recall: 1.000
- Fixture false-positive rate: 0.000
- Supported Python versions in CI: 3.10, 3.11, 3.12, and 3.13
- Security automation: CodeQL, repository policy checks, and dependency audit
- Release engineering: five tagged releases, with installable artifacts,
  checksums, and build provenance on recent releases
- Integration surfaces: CLI, stable Python API, GitHub Marketplace Action,
  SARIF 2.1.0 output, browser demo, and stdlib REST API server mode
- Trust-boundary coverage: saved-email authentication parsing, SARIF
  validation, parser regression tests, and public-safe demonstration inputs

Run the benchmark yourself:

```bash
python tools/evaluate_url_benchmark.py
```

These results measure the checked-in regression fixture. They are not
population-level accuracy, calibration, or production-effectiveness claims.
See [BENCHMARK.md](BENCHMARK.md) for the fixture limitations.

## Product Readiness Evidence

Recent reviewer-facing improvements:

| Area | Evidence |
| --- | --- |
| Benchmark transparency | [BENCHMARK.md](BENCHMARK.md) records the public-safe baseline, recall improvement, and limits. |
| Python embedding | [PYTHON_API.md](PYTHON_API.md) documents direct `score_url` and `score_email` usage without shelling out. |
| CI and code scanning | [GITHUB_CODE_SCANNING.md](GITHUB_CODE_SCANNING.md) provides SARIF generation and upload guidance. |
| REST integration | The README documents `phishguard serve` with local default binding and endpoint examples. |
| Safe adoption | [ADOPTION.md](ADOPTION.md) and [FIRST_CONTRIBUTION.md](FIRST_CONTRIBUTION.md) give external users low-friction paths to try, report, and contribute. |
| Evaluator experience | [EVALUATOR_GUIDE.md](EVALUATOR_GUIDE.md) gives a five-minute path to run safe examples and inspect trust boundaries. |

## Community Evidence

GitHub snapshot verified on June 9, 2026 and retained as a historical
baseline:

- 3 repository forks
- 1 merged pull request from an external human contributor
- 1 automated dependency-update pull request merged
- 7 open issues offering scoped contribution opportunities
- 3 tagged releases
- 1 recorded download of a v0.4.0 release asset

The external contribution added plain-text CLI output and is preserved in
[pull request #7](https://github.com/omobolajiadeyan/phishguard-ai/pull/7).
Repository counts change over time; use the live badges and GitHub pages for
current values.

## Demonstration

![PhishGuard safe-input and phishing-input terminal comparison](assets/phishguard-demo.svg)

The screenshot was prepared from the real output of:

```bash
python phishguard.py url "https://www.example.com/account" --plain
python phishguard.py url \
  "http://192.0.2.10/secure-login/verify" \
  --verbose \
  --plain
```

Both inputs are public-safe. `example.com` is reserved for documentation, and
`192.0.2.0/24` is the TEST-NET-1 documentation range.

The
[18-second safe demo video](https://github.com/omobolajiadeyan/phishguard-ai/releases/download/v0.4.0/phishguard-demo.mp4)
attached to the
[v0.4.0 release](https://github.com/omobolajiadeyan/phishguard-ai/releases/tag/v0.4.0)
shows the same offline workflow. The commands remain in
[QUICK_DEMO.md](QUICK_DEMO.md) so reviewers can reproduce the result rather
than relying on a recording.

## Evidence Boundaries

PhishGuard is an early-stage open-source project. Stars, traffic, deployments,
and organizational adoption are not claimed unless they can be independently
verified. Future evidence should include dated sources, commands, and
limitations.
