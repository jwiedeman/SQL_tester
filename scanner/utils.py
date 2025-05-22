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


def evasion_variants(payload: str) -> list[str]:
    """Return basic evasion variants for a payload."""
    variants = [payload]
    if " " in payload:
        variants.append(payload.replace(" ", "/**/"))
    mixed = []
    upper = True
    for c in payload:
        if c.isalpha():
            mixed.append(c.upper() if upper else c.lower())
            upper = not upper
        else:
            mixed.append(c)
    variants.append("".join(mixed))
    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique
