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

PLAIN_OUTPUT = False


def set_plain_output(enabled: bool) -> None:
    global PLAIN_OUTPUT
    PLAIN_OUTPUT = enabled


def style(text: str, *codes: str) -> str:
    if PLAIN_OUTPUT:
        return text
    return "".join(codes) + text + RESET


def separator() -> str:
    return "-" * 60 if PLAIN_OUTPUT else "─" * 60


def probability_bar(prob: float) -> str:
    filled = round(prob * 20)
    if PLAIN_OUTPUT:
        return "#" * filled + "-" * (20 - filled) + f"  {prob*100:.1f}%"

    color = RED if prob >= 0.75 else YELLOW if prob >= THRESHOLD else GREEN
    return color + "█" * filled + GRAY + "░" * (20 - filled) + RESET + f"  {prob*100:.1f}%"


def print_banner():
    if PLAIN_OUTPUT:
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


def analyze_url(url: str, verbose: bool = False) -> dict:
    prob, features = score_url(url)
    verdict = classify(prob)

    print(f"\n{separator()}")
    print(f"  URL     : {url}")
    print(f"  Verdict : {style(verdict, VERDICT_COLOR[verdict], BOLD)}")
    print(f"  Risk    : {probability_bar(prob)}")

    if verbose:
        print(f"\n  {style('Feature breakdown:', GRAY)}")
        for feat, val in features.items():
            flag = style("*", RED) if val > 0 and feat != "has_https" else ""
            print(f"    {feat:<22}: {val}  {flag}")

    return {"url": url, "verdict": verdict, "probability": prob, "features": features}


def analyze_email(subject: str, body: str, verbose: bool = False) -> dict:
    prob, features = score_email(subject, body)
    verdict = classify(prob)

    print(f"\n{separator()}")
    print(f"  Subject : {subject}")
    print(f"  Verdict : {style(verdict, VERDICT_COLOR[verdict], BOLD)}")
    print(f"  Risk    : {probability_bar(prob)}")

    if verbose:
        print(f"\n  {style('Feature breakdown:', GRAY)}")
        for feat, val in features.items():
            print(f"    {feat:<26}: {val}")

    return {"subject": subject, "verdict": verdict, "probability": prob, "features": features}


def batch_scan_urls(filepath: str, verbose: bool = False) -> list:
    results = []
    try:
        with open(filepath) as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(style(f"Error: File '{filepath}' not found.", RED))
        sys.exit(1)

    print(style(f"Scanning {len(urls)} URLs...", CYAN))
    phishing_count = 0
    for url in urls:
        result = analyze_url(url, verbose=verbose)
        results.append(result)
        if result["verdict"] == "PHISHING":
            phishing_count += 1

    print(style(f"\nSummary: {phishing_count}/{len(urls)} URLs classified as PHISHING", BOLD))
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
    set_plain_output(args.plain)

    if args.format == "sarif" and not args.output:
        parser.error("--format sarif requires --output")

    print_banner()

    if args.command == "url":
        result = analyze_url(args.target, verbose=args.verbose)
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN))

    elif args.command == "email":
        result = analyze_email(args.subject, args.body, verbose=args.verbose)
        if args.output:
            write_report(result, args.output, args.format)
            print(style(f"\nResult saved to {args.output}", GREEN))

    elif args.command == "batch":
        results = batch_scan_urls(args.file, verbose=args.verbose)
        if args.output:
            write_report(results, args.output, args.format)
            print(style(f"Results saved to {args.output}", GREEN))

    print()


if __name__ == "__main__":
    main()
