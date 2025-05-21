import urllib.parse
import urllib.request


def send_request(url: str, method: str = "get", data: dict | None = None) -> str:
    """Send an HTTP request and return the response body as text."""
    method = method.lower()
    if method == "get":
        with urllib.request.urlopen(url) as resp:
            return resp.read().decode("utf-8", errors="replace")
    else:
        encoded = urllib.parse.urlencode(data or {}).encode()
        req = urllib.request.Request(url, data=encoded)
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode("utf-8", errors="replace")
