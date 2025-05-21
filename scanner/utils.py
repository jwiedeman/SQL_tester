import urllib.parse
import urllib.request
from typing import Dict, Optional


def send_request(
    url: str,
    method: str = "get",
    data: Optional[dict] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> str:
    """Send an HTTP request and return the response body as text."""
    method = method.lower()
    req_headers = headers.copy() if headers else {}
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req_headers["Cookie"] = cookie_str

    if method == "get":
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="replace")
    else:
        encoded = urllib.parse.urlencode(data or {}).encode()
        req = urllib.request.Request(url, data=encoded, headers=req_headers)
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="replace")
