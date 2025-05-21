# SQL Injection Scanner

This repository contains a simple SQL injection scanner written in Python. It crawls a target website and attempts error-based, UNION-based, boolean-based, time-based, and out-of-band SQL injection payloads. HTML forms are scanned via GET or POST requests. A lightweight response diffing engine helps detect subtle changes. Results are consolidated into a CSV report.

## Usage

```
python -m scanner.runner <url> [limit] [callback_domain]
```

- `<url>` is the starting URL to crawl.
- `limit` (optional) specifies the maximum number of pages to crawl (default 5).
- `callback_domain` (optional) domain for OOB payloads (default `example.com`).

Results will be saved to `report.csv` in the current directory.
