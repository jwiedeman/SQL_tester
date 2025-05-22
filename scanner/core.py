class Scanner:
    """Core scanner that combines the crawler and detection modules."""

    def __init__(self, limit=5, callback_domain="example.com", reporter=None):
        from .report import CSVReporter

        self.limit = limit
        self.callback_domain = callback_domain
        self.reporter = reporter or CSVReporter("report.csv")

    def scan(self, start_url: str):
        """Crawl the target and run all detectors."""
        from urllib.parse import urlparse, parse_qs

        from .crawler import crawl
        from .detectors import (
            error_based,
            union_based,
            boolean_based,
            time_based,
            oob_based,
            graphql_based,
        )

        results = crawl(start_url, limit=self.limit)
        for url, info in results.items():
            cookies = info.get("cookies", {})
            headers = {
                "User-Agent": "SQLScanner",
                "Referer": url,
            }

            parsed = urlparse(url)
            query = parse_qs(parsed.query)

            if "graphql" in parsed.path.lower():
                g_tests = graphql_based.test_endpoint(
                    url,
                    method="post",
                    cookies=cookies,
                    headers=headers,
                )
                for t in g_tests:
                    self.reporter.add_result(
                        url=t["url"],
                        param=t["param"],
                        payload=t["payload"],
                        method="graphql-based",
                        vulnerable=t["vulnerable"],
                    )

            path_segments = [p for p in parsed.path.split("/") if p]
            for idx, segment in enumerate(path_segments):
                param_name = f"path_{idx}"
                self._scan_param(
                    url,
                    param_name,
                    segment,
                    method="get",
                    cookies=cookies,
                    headers=headers,
                    location="path",
                    path_index=idx + (1 if parsed.path.startswith("/") else 0),
                )

            for param in query.keys():
                self._scan_param(
                    url,
                    param,
                    query[param][0],
                    method="get",
                    cookies=cookies,
                    headers=headers,
                )

            for form in info.get("forms", []):
                action_url = form.get("action") or url
                method = form.get("method", "get").lower()
                form_data = {i["name"]: "1" for i in form.get("inputs", []) if i.get("name")}
                if "graphql" in action_url.lower():
                    g_tests = graphql_based.test_endpoint(
                        action_url,
                        method=method,
                        cookies=cookies,
                        headers=headers,
                    )
                    for t in g_tests:
                        self.reporter.add_result(
                            url=t["url"],
                            param=t["param"],
                            payload=t["payload"],
                            method="graphql-based",
                            vulnerable=t["vulnerable"],
                        )
                    continue
                for param in list(form_data.keys()):
                    self._scan_param(
                        action_url,
                        param,
                        form_data[param],
                        method=method,
                        data=form_data,
                        cookies=cookies,
                        headers=headers,
                    )

            for cookie_name, cookie_value in cookies.items():
                self._scan_param(
                    url,
                    cookie_name,
                    cookie_value,
                    method="get",
                    cookies=cookies,
                    headers=headers,
                    location="cookie",
                )

            for header_name, header_value in headers.items():
                self._scan_param(
                    url,
                    header_name,
                    header_value,
                    method="get",
                    cookies=cookies,
                    headers=headers,
                    location="header",
                )

        self.reporter.write()

    def _scan_param(
        self,
        url: str,
        param: str,
        value: str,
        method: str = "get",
        data: dict | None = None,
        cookies: dict | None = None,
        headers: dict | None = None,
        location: str = "query",
        path_index: int | None = None,
    ) -> None:
        """Run all detectors against a single parameter."""
        from .detectors import (
            error_based,
            union_based,
            boolean_based,
            time_based,
            oob_based,
        )

        detectors = [
            ("error-based", error_based.test_parameter),
            ("union-based", union_based.test_parameter),
            ("boolean-based", boolean_based.test_parameter),
            ("time-based", time_based.test_parameter),
        ]

        for name, func in detectors:
            tests = func(
                url,
                param,
                value,
                method=method,
                data=data,
                cookies=cookies,
                headers=headers,
                location=location,
                path_index=path_index,
            )
            for t in tests:
                self.reporter.add_result(
                    url=t["url"],
                    param=t["param"],
                    payload=t["payload"],
                    method=name,
                    vulnerable=t["vulnerable"],
                )

        o_tests = oob_based.test_parameter(
            url,
            param,
            value,
            callback_domain=self.callback_domain,
            method=method,
            data=data,
            cookies=cookies,
            headers=headers,
            location=location,
            path_index=path_index,
        )
        for t in o_tests:
            self.reporter.add_result(
                url=t["url"],
                param=t["param"],
                payload=t["payload"],
                method="oob-based",
                vulnerable=t["vulnerable"],
            )

