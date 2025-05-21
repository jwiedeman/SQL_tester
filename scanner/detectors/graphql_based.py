import re
import urllib.parse

from ..utils import send_request
from ..diff import is_significant_diff

# Simple error patterns that may indicate GraphQL syntax errors
ERROR_PATTERNS = [
    re.compile(r"syntax error", re.I),
    re.compile(r"parse error", re.I),
    re.compile(r"Cannot query field", re.I),
]

# Baseline and injection payloads
BASE_QUERY = "{ __typename }"
PAYLOADS = ["{ __typename }'", '{ __typename }"']


def test_endpoint(url, method="post", cookies=None, headers=None):
    """Attempt a basic GraphQL injection by breaking the query syntax."""
    cookies = cookies or {}
    headers = headers or {}
    method = method.lower()

    results = []

    if method == "get":
        base_params = urllib.parse.urlencode({"query": BASE_QUERY})
        base_url = f"{url}?{base_params}"
        base_resp = send_request(base_url, cookies=cookies, headers=headers)
    else:
        base_resp = send_request(
            url,
            method="post",
            data={"query": BASE_QUERY},
            cookies=cookies,
            headers=headers,
        )

    for payload in PAYLOADS:
        if method == "get":
            params = urllib.parse.urlencode({"query": payload})
            new_url = f"{url}?{params}"
            resp = send_request(new_url, cookies=cookies, headers=headers)
        else:
            resp = send_request(
                url,
                method="post",
                data={"query": payload},
                cookies=cookies,
                headers=headers,
            )
        vulnerable = any(p.search(resp) for p in ERROR_PATTERNS) or is_significant_diff(base_resp, resp)
        results.append({
            "url": url,
            "param": "query",
            "payload": payload,
            "vulnerable": vulnerable,
        })

    return results
