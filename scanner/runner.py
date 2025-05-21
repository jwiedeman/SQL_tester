import sys
from urllib.parse import urlparse, parse_qs

from .crawler import crawl
from .detectors import error_based
from .report import CSVReporter


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.runner <url> [limit]")
        sys.exit(1)

    start_url = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    results = crawl(start_url, limit=limit)
    reporter = CSVReporter('report.csv')
    for url, info in results.items():
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for param in query.keys():
            tests = error_based.test_parameter(url, param, query[param][0])
            for t in tests:
                reporter.add_result(
                    url=t['url'],
                    param=t['param'],
                    payload=t['payload'],
                    method='error-based',
                    vulnerable=t['vulnerable'],
                )
    reporter.write()
    print(f"Scan complete. Results written to report.csv")


if __name__ == '__main__':
    main()
