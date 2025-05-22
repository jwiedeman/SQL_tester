"""Command line entry point for the SQL injection scanner."""

import argparse

from .core import Scanner
from .report import CSVReporter


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the SQL injection scanner")
    parser.add_argument("url", help="Starting URL to crawl")
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum number of pages to crawl (default: 5)",
    )
    parser.add_argument(
        "--callback-domain",
        default="example.com",
        help="Domain for out-of-band payloads (default: example.com)",
    )
    parser.add_argument(
        "--output",
        default="report.csv",
        help="CSV report filename (default: report.csv)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    scanner = Scanner(
        limit=args.limit,
        callback_domain=args.callback_domain,
        reporter=CSVReporter(args.output),
    )
    scanner.scan(args.url)
    print(f"Scan complete. Results written to {args.output}")


if __name__ == "__main__":
    main()

