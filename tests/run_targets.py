import argparse
import os
import urllib.parse

from scanner.core import Scanner
from scanner.report import CSVReporter


def slugify(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = parsed.path.strip("/").replace("/", "_") or "root"
    return f"{host}_{path}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run scanner against multiple targets")
    parser.add_argument(
        "--targets",
        default="tests/targets.txt",
        help="File containing target URLs (one per line)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum pages to crawl per target",
    )
    parser.add_argument(
        "--callback-domain",
        default="example.com",
        help="Domain for out-of-band payloads",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to store CSV reports",
    )
    args = parser.parse_args()

    with open(args.targets) as f:
        targets = [line.strip() for line in f if line.strip()]

    os.makedirs(args.output_dir, exist_ok=True)

    for target in targets:
        filename = slugify(target) + ".csv"
        output_path = os.path.join(args.output_dir, filename)
        reporter = CSVReporter(output_path)
        scanner = Scanner(limit=args.limit, callback_domain=args.callback_domain, reporter=reporter)
        print(f"Scanning {target}...")
        scanner.scan(target)
        reporter.write()
        print(f"Results saved to {output_path}")


if __name__ == "__main__":
    main()
