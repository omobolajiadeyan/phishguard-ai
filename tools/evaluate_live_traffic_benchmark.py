"""Evaluate the URL detector against real, currently-live traffic samples.

Unlike the small, checked-in regression fixture (evaluate_url_benchmark.py),
this tool takes two *externally supplied* files so no phishing URLs or
third-party domain rankings are committed to this repository:

  - a phishing feed: one URL per line (e.g. the OpenPhish free feed at
    https://openphish.com/feed.txt)
  - a legitimate-domain ranking CSV: "rank,domain" per line (e.g. the Tranco
    list at https://tranco-list.eu)

Only the URL/domain *strings* are scored. No network request is made to any
listed site, and no page content is fetched -- this stays consistent with
PhishGuard's offline, string-only scoring design.

These are still snapshot metrics, not a permanent population-accuracy claim:
both source lists rotate over time, so exact counts will differ on a rerun
with freshly downloaded files. Document the retrieval date when reporting
results. See docs/BENCHMARK.md for a dated result and full methodology.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from model import classify, score_url


def load_phishing_urls(path: str | Path) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    return [line.strip() for line in text.splitlines() if line.strip()]


def load_legitimate_urls(path: str | Path, limit: int) -> list[str]:
    urls = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for i, row in enumerate(reader):
            if i >= limit:
                break
            if len(row) < 2:
                continue
            urls.append(f"https://{row[1]}/")
    return urls


def evaluate(urls: list[str]) -> list[str]:
    return [classify(score_url(url)[0]) for url in urls]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phishing_feed", help="path to a phishing-feed file, one URL per line")
    parser.add_argument("legit_domains_csv", help="path to a rank,domain CSV (e.g. Tranco)")
    parser.add_argument(
        "--legit-limit", type=int, default=1000,
        help="how many top-ranked legitimate domains to sample (default: 1000)",
    )
    args = parser.parse_args(argv)

    phishing_urls = load_phishing_urls(args.phishing_feed)
    legit_urls = load_legitimate_urls(args.legit_domains_csv, args.legit_limit)

    if not phishing_urls or not legit_urls:
        print("error: both input files must contain at least one entry", file=sys.stderr)
        return 1

    phish_verdicts = evaluate(phishing_urls)
    legit_verdicts = evaluate(legit_urls)

    flagged = {"PHISHING", "SUSPICIOUS"}
    true_positive = sum(1 for v in phish_verdicts if v in flagged)
    false_negative = len(phish_verdicts) - true_positive
    false_positive = sum(1 for v in legit_verdicts if v in flagged)
    true_negative = len(legit_verdicts) - false_positive
    strict_true_positive = sum(1 for v in phish_verdicts if v == "PHISHING")

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive) else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative) else 0.0
    )
    fpr = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative) else 0.0
    )

    print(f"phishing samples: {len(phishing_urls)}  (source: {args.phishing_feed})")
    print(f"legitimate samples: {len(legit_urls)}  (source: {args.legit_domains_csv})")
    print()
    print(
        "confusion_matrix (flag = PHISHING or SUSPICIOUS): "
        f"tp={true_positive} fn={false_negative} fp={false_positive} tn={true_negative}"
    )
    print(f"strict_phishing_only_recall: {strict_true_positive}/{len(phish_verdicts)}")
    print()
    print(f"precision: {precision:.3f}")
    print(f"recall: {recall:.3f}")
    print(f"false_positive_rate: {fpr:.3f}")
    print()
    print(
        "note: these are point-in-time snapshot metrics against real, live "
        "traffic samples -- both source lists rotate over time, so exact "
        "counts will differ on a rerun with freshly downloaded files. This "
        "is stronger evidence than a small synthetic fixture, but still not "
        "a permanent, universal accuracy claim."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
