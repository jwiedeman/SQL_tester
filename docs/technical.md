# Technical Documentation

This document describes the modules that compose the SQL Injection Scanner and how they interact. It is intended for developers who want to extend or maintain the scanner.

## Package Layout

- **scanner/crawler.py** – Performs a breadth‑first crawl of the target site, collecting forms, cookies and links.
- **scanner/detectors/** – Individual detection modules implementing various SQL injection techniques. Each module exposes a `test_parameter` function.
    - `error_based.py`
    - `union_based.py`
    - `boolean_based.py`
    - `time_based.py`
    - `oob_based.py`
    - `graphql_based.py`
- **scanner/diff.py** – Provides response normalization and diffing helpers used to compare baseline and injected responses.
- **scanner/utils.py** – Utility functions for sending requests, evasion payloads and response stability checks.
- **scanner/core.py** – Coordinates crawling and dispatches each detector against discovered parameters.
- **scanner/report.py** – Gathers results and writes them to CSV.
- **scanner/runner.py** – Command line entry point for invoking the scanner.

## Integration Flow

1. `runner.py` parses command line options and instantiates `core.Scanner`.
2. The scanner uses `crawler.crawl` to enumerate pages, forms and cookies.
3. For every discovered parameter the scanner calls each detector module via `Scanner._scan_param`.
4. Detectors generate payload variations and send requests using `utils.send_request`.
5. Responses are analysed with helpers from `diff` or `utils` to determine if an injection was successful.
6. Findings are recorded by `report.CSVReporter` and written out at the end of the scan.

Each detector is self‑contained, making it straightforward to add new techniques without affecting existing functionality.
