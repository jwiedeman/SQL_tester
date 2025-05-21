# SQL Injection Scanner

This repository contains a simple SQL injection scanner written in Python. It crawls a target website and attempts error-based, UNION-based, boolean-based, time-based, out-of-band, and GraphQL injection payloads. HTML forms are scanned via GET or POST requests and cookies are fuzzed for injection vectors. A lightweight response diffing engine helps detect subtle changes. Results are consolidated into a CSV report.

## Usage

```
python -m scanner.runner <url> [--limit N] [--callback-domain DOMAIN] [--output FILE]
```

- `<url>` is the starting URL to crawl.
- `--limit` optionally specifies the maximum number of pages to crawl (default 5).
- `--callback-domain` optionally provides a domain for OOB payloads (default `example.com`).
- `--output` sets the CSV report filename (default `report.csv`).

Results will be saved to `report.csv` in the current directory.
