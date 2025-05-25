# User Guide

This guide explains how to run the scanner and interpret its results.

## Running a Scan

```
python -m scanner.runner <url> --limit 10 --output report.csv
```

- `<url>` is the starting point for crawling.
- `--limit` controls how many pages will be crawled.
- `--callback-domain` sets the domain used for out‑of‑band payloads.
- `--output` specifies the CSV file to write.

## Understanding the Report

The CSV report contains the following columns:

- **url** – Request URL that was tested.
- **parameter** – Name of the parameter or location that was fuzzed.
- **payload** – Payload string that was used for the test.
- **method** – Detection method (error‑based, union‑based, etc.).
- **vulnerable** – `Y` if the detector identified a likely vulnerability, otherwise `N`.

A `Y` value indicates that the payload caused a notable change in the response or timing, suggesting that SQL injection may be possible. Manual verification is recommended before taking action.
