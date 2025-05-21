# SQL Injection Scanner

This repository contains a simple SQL injection scanner written in Python. It crawls a target website, attempts error-based and UNION-based SQL injection payloads, and generates a CSV report.

## Usage

```
python -m scanner.runner <url> [limit]
```

- `<url>` is the starting URL to crawl.
- `limit` (optional) specifies the maximum number of pages to crawl (default 5).

Results will be saved to `report.csv` in the current directory.
