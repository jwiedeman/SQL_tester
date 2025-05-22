SQL Injection Scanner Project Implementation Plan

Overview

This project will deliver a comprehensive, passive SQL injection testing tool. It should run on individual pages, entire sites, or crawl and test multiple internal pages (user-defined limit). Each vulnerability detection method must be isolated clearly. Outputs will be consolidated into CSV format.

High-Level Structure

Phase 1: Project Setup

Environment Setup: Python, Requests/aiohttp, BeautifulSoup, Playwright/Puppeteer, Redis or similar queueing system.

Reporting: CSV output library (Pandas recommended).

Crawler Module: URL extraction, page discovery, limit management.

Detection Engine Modules: Response diffing, timing, error detection, OOB listener.

Phase 2: Injection Surface Enumeration

Identify and store all parameters:

URL parameters (GET)

Body parameters (POST, JSON)

GraphQL parameters

Cookies

Headers

Route/path parameters

Hidden form fields

File upload metadata

Detailed Task Breakdown

1. Crawler and Target Enumeration

Crawl the given site (respect robots.txt, rate-limiting).

Extract forms, parameters, headers, cookies from each page.

Store target input points with context (numeric, string, JSON, GraphQL).

2. Payload and Method Implementation

Create isolated modules for each SQL injection method:

Module: Error-Based Detection

Logic: Inject basic syntax-breaking payloads.

Payloads: ', ", ;, --, #, ' OR 1=1, type mismatch strings.

Detection: Response diffing for DB errors (regex matching common DB errors).

Edge Cases: Payload evasion techniques (comments, encodings).

Module: Union-Based Detection

Logic: Column count discovery using ORDER BY and UNION SELECT.

Payloads: ORDER BY 1, increment to detect column count, then union with NULLs or dummy strings.

Detection: Response content checking for injected constants.

Evasion: Obfuscate UNION with comments and casing.

Module: Boolean-Based Blind Detection

Logic: Inject conditions that evaluate to true/false, observe differences.

Payloads: ' OR '1'='1, ' OR '1'='2, numeric variants (123 OR 1=1).

Detection: Response content, status code, redirects.

Edge Cases: Adjust payloads based on context (string vs numeric).

Module: Time-Based Blind Detection

Logic: Inject sleep/delay conditions to detect injection by timing.

Payloads: DB-specific (SLEEP(5), WAITFOR DELAY '0:0:5', etc.).

Detection: Measure response delays against baseline timings.

Evasion: Obfuscated sleep payloads, alternate DB commands.

Module: Out-of-Band (OOB) Detection (optional)

Logic: Trigger DNS/HTTP requests from the DB.

Payloads: DB-specific external lookup commands (xp_dirtree, UTL_HTTP).

Detection: Monitor DNS/HTTP callback server for hits.

Safety: Ensure external listener domain is controlled and safe.

3. Response and Detection Engines

Response Diffing Engine

Implement normalization and difference checks.

Account for dynamic tokens, timestamps.

Timing Detection Engine

High-resolution timer, multiple requests, and statistical analysis.

Set adaptive delay thresholds.

Error Signature Scanning

Regex-based database error identification.

Include comprehensive DB error signature database.

4. Integration and Execution Logic

Modular test execution: Isolate each payload test per input.

Implement controlled parallel execution, with throttling.

Adaptive payload selection based on context.

Safe mode options for production targets (minimal payload, throttling).

5. Output and Reporting

CSV Report Format:

Fields: URL, Parameter Type, Parameter Name, Payload Used, Detection Method, Vulnerability Confirmed (Y/N), Details.

Export results clearly indicating vulnerability type.

Project Workflow

Initial Setup

Setup Dev Environment

Install dependencies (Python, aiohttp, BeautifulSoup, Redis, etc.)

Development Cycle (Repeat for Each Module)

Implement payload injection logic.

Develop detection mechanism.

Unit test individual payloads.

Integrate detection with the response analysis module.

Test against controlled environments (DVWA or OWASP Juice Shop).

Final Integration

Combine modules into scanner core.

Implement crawler integration.

Implement CSV reporting output.

Systematic testing on known vulnerable apps.

QA and Optimization

Performance tuning and optimization.

Improve payload evasion logic.

Reduce false positives through fine-tuning detection.

Documentation

Technical documentation of modules and integration.

Ethical and usage guidelines.

User-facing instructions and report interpretation guidance.

Developer Notes

Clearly isolate each test module; use class or modular functions.

Each test must be repeatable, isolated, and log clearly.

Avoid payloads with data modification commands; strictly detection only.

Maintain careful control of rate limits and ethical usage guidelines.

Ensure payloads are contextually appropriate (numeric, string, JSON).

Ethical and Legal Notes

Explicit permission required for scans.

All methods non-destructive; still, advise clients about potential logging and performance impacts.


## Tasks
- Reduce false positives through fine-tuning detection
- Write technical documentation of modules and integration
- Publish ethical and usage guidelines
- Create user-facing instructions and report interpretation guidance

## Completed Tasks
- Environment setup and project skeleton
- Implement basic crawler to extract links and forms
- Implement error-based detection module
- Implement union-based detection module
- Implement boolean-based detection module
- Create CSV reporting functionality
- Provide command line interface for running scans
- Implement time-based detection module
- Implement out-of-band detection module
- Implement response diffing engine
- Add POST form scanning support
- Add cookie scanning support
- Add header scanning support
- Add path parameter scanning support
- Implement GraphQL-based detection module
- Combine modules into scanner core
- Implement crawler integration
- Systematic testing on known vulnerable apps
- Improve payload evasion logic
- Performance tuning and optimization
