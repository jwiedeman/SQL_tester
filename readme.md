# SQL Injection Scanner

This repository contains a simple SQL injection scanner written in Python. It crawls a target website and attempts error-based, UNION-based, boolean-based, time-based, out-of-band, and GraphQL injection payloads. HTML forms are scanned via GET or POST requests and cookies are fuzzed for injection vectors. A lightweight response diffing engine helps detect subtle changes. Results are consolidated into a CSV report.

Additional documentation can be found in the [`docs/`](docs) directory:

- [`technical.md`](docs/technical.md) – Module overview and integration notes.
- [`usage.md`](docs/usage.md) – User guide and report interpretation.
- [`ethical.md`](docs/ethical.md) – Ethical and legal usage guidelines.

## Usage

```
python -m scanner.runner <url> [--limit N] [--callback-domain DOMAIN] [--output FILE]
```

- `<url>` is the starting URL to crawl.
- `--limit` optionally specifies the maximum number of pages to crawl (default 5).
- `--callback-domain` optionally provides a domain for OOB payloads (default `example.com`).
- `--output` sets the CSV report filename (default `report.csv`).

Results will be saved to `report.csv` in the current directory.

## Systematic Testing

Use `tests/run_targets.py` to run the scanner against multiple targets listed in `tests/targets.txt`:

```
python tests/run_targets.py --targets tests/targets.txt --output-dir reports
```

Each target will produce a separate CSV file inside the specified output directory.
