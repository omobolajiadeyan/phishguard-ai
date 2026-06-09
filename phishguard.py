#!/usr/bin/env python3
"""
PhishGuard AI — Intelligent phishing detection for URLs and emails.
Uses feature engineering + weighted scoring to classify threats in real time.
Author: Omobolaji Adeyan
"""

import argparse
import sys
from model import score_url, score_email, classify, THRESHOLD
from reporting import write_report


def configure_output() -> None:
    """Keep decorative output from crashing on limited console encodings."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


configure_output()

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

VERDICT_COLOR = {
    "PHISHING":   RED,
    "SUSPICIOUS": YELLOW,
    "SAFE":       GREEN,
}

VERDICT_ICON = {
    "PHISHING":   "PHISHING",
    "SUSPICIOUS": "SUSPICIOUS",
    "SAFE":       "SAFE",
}

def style(text: str, *codes: str, plain: bool = False) -> str:
    if plain:
        return text
    return "".join(codes) + text + RESET


def separator(plain: bool = False) -> str:
    return "-" * 60 if plain else "─" * 60


def probability_bar(prob: float, plain: bool = False) -> str:
    filled = round(prob * 20)
    if plain:
        return "#" * filled + "-" * (20 - filled) + f"  {prob*100:.1f}%"

    color = RED if prob >= 0.75 else YELLOW if prob >= THRESHOLD else GREEN
    return color + "█" * filled + GRAY + "░" * (20 - filled) + RESET + f"  {prob*100:.1f}%"


def print_banner(plain: bool = False):
    if plain:
        print("""
  PHISHGUARD AI
  Explainable phishing detection | github.com/omobolajiadeyan
""")
        return

    print(f"""
{CYAN}{BOLD}
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗      █████╗ ██╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗██║
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║    ███████║██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║    ██╔══██║██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝    ██║  ██║██║
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝
{RESET}{GRAY}  Explainable phishing detection | github.com/omobolajiadeyan{RESET}
""")


def analyze_url(url: str, verbose: bool = False, plain: bool = False) -> dict:
    prob, features = score_url(url)
    verdict = classify(prob)

    print(f"\n{separator(plain=plain)}")
    print(f"  URL     : {url}")
    print(f"  Verdict : {style(verdict, VERDICT_COLOR[verdict], BOLD, plain=plain)}")
    print(f"  Risk    : {probability_bar(prob, plain=plain)}")

    if verbose:
        print(f"\n  {style('Feature breakdown:', GRAY, plain=plain)}")
        for feat, val in features.items():
            flag = style("*", RED, plain=plain) if val > 0 and feat != "has_https" else ""
            print(f"    {feat:<22}: {val}  {flag}")

    return {"url": url, "verdict": verdict, "probability": prob, "features": features}


def analyze_email(subject: str, body: str, verbose: bool = False, plain: bool = False) -> dict:
    prob, features = score_email(subject, body)
    verdict = classify(prob)

    print(f"\n{separator(plain=plain)}")
    print(f"  Subject : {subject}")
    print(f"  Verdict : {style(verdict, VERDICT_COLOR[verdict], BOLD, plain=plain)}")
    print(f"  Risk    : {probability_bar(prob, plain=plain)}")

    if verbose:
        print(f"\n  {style('Feature breakdown:', GRAY, plain=plain)}")
        for feat, val in features.items():
            print(f"    {feat:<26}: {val}")

    return {"subject": subject, "verdict": verdict, "probability": prob, "features": features}


def batch_scan_urls(filepath: str, verbose: bool = False, plain: bool = False) -> list:
    results = []
    try:
        with open(filepath, encoding="utf-8") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        print(style(f"Error: File '{filepath}' not found.", RED, plain=plain))
        sys.exit(1)

    urls = [
        (line_num, line.strip())
        for line_num, line in enumerate(raw_lines, start=1)
        if line.strip() and not line.strip().startswith("#")
    ]
    print(style(f"Scanning {len(urls)} URLs...", CYAN, plain=plain))
    phishing_count = 0
    for line_num, url in urls:
        result = analyze_url(url, verbose=verbose, plain=plain)
        # Attach source metadata — additive, doesn't change verdict/probability
        result["source_path"] = filepath
        result["line_number"] = line_num
        results.append(result)
        if result["verdict"] == "PHISHING":
            phishing_count += 1

    print(style(f"\nSummary: {phishing_count}/{len(urls)} URLs classified as PHISHING", BOLD, plain=plain))
    return results


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o", help="Save results to a file")
    parser.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Output format used with --output (default: json)",
    )
    parser.add_argument(
        "--plain",
        "--no-unicode",
        action="store_true",
        help="Use ASCII-only output without color or Unicode decorations.",
    )


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard AI — Phishing detection for URLs and emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishguard.py url "http://paypa1-secure-login.xyz/verify"
  python phishguard.py url "https://google.com" --verbose
  python phishguard.py email --subject "URGENT: Verify your account" --body "Click here immediately"
  python phishguard.py batch data/urls.txt
  python phishguard.py batch data/urls.txt --output results.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # URL command
    url_parser = subparsers.add_parser("url", help="Analyze a single URL")
    url_parser.add_argument("target", help="URL to analyze")
    url_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(url_parser)

    # Email command
    email_parser = subparsers.add_parser("email", help="Analyze an email")
    email_parser.add_argument("--subject", required=True, help="Email subject line")
    email_parser.add_argument("--body", required=True, help="Email body text")
    email_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(email_parser)

    # Batch command
    batch_parser = subparsers.add_parser("batch", help="Scan a list of URLs from a file")
    batch_parser.add_argument("file", help="Path to file with one URL per line")
    batch_parser.add_argument("--verbose", "-v", action="store_true")
    add_output_arguments(batch_parser)

    args = parser.parse_args()

    if args.format == "sarif" and not args.output:
        parser.error("--format sarif requires --output")

    print_banner(plain=args.plain)

    if args.command == "url":
        result = analyze_url(args.target, verbose=args.verbose, plain=args.plain)
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN, plain=args.plain))

    elif args.command == "email":
        result = analyze_email(args.subject, args.body, verbose=args.verbose, plain=args.plain)
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN, plain=args.plain))

    elif args.command == "batch":
        results = batch_scan_urls(args.file, verbose=args.verbose, plain=args.plain)
        if args.output:
            write_report(results, args.output, args.format)
            print(style(f"Results saved to {args.output}", GREEN, plain=args.plain))

    print()


if __name__ == "__main__":
    main()
