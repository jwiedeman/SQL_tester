import sys
from urllib.parse import urlparse, parse_qs

from .crawler import crawl
from .detectors import (
    error_based,
    union_based,
    boolean_based,
    time_based,
    oob_based,
)
from .report import CSVReporter


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.runner <url> [limit] [callback_domain]")
        sys.exit(1)

    start_url = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    callback_domain = sys.argv[3] if len(sys.argv) > 3 else "example.com"

    results = crawl(start_url, limit=limit)
    reporter = CSVReporter('report.csv')
    for url, info in results.items():
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for param in query.keys():
            tests = error_based.test_parameter(url, param, query[param][0], method="get")
            for t in tests:
                reporter.add_result(
                    url=t['url'],
                    param=t['param'],
                    payload=t['payload'],
                    method='error-based',
                    vulnerable=t['vulnerable'],
                )
            u_tests = union_based.test_parameter(url, param, query[param][0], method="get")
            for t in u_tests:
                reporter.add_result(
                    url=t['url'],
                    param=t['param'],
                    payload=t['payload'],
                    method='union-based',
                    vulnerable=t['vulnerable'],
                )
            b_tests = boolean_based.test_parameter(url, param, query[param][0], method="get")
            for t in b_tests:
                reporter.add_result(
                    url=t['url'],
                    param=t['param'],
                    payload=t['payload'],
                    method='boolean-based',
                    vulnerable=t['vulnerable'],
                )
            t_tests = time_based.test_parameter(url, param, query[param][0], method="get")
            for t in t_tests:
                reporter.add_result(
                    url=t['url'],
                    param=t['param'],
                    payload=t['payload'],
                    method='time-based',
                    vulnerable=t['vulnerable'],
                )
            o_tests = oob_based.test_parameter(
                url,
                param,
                query[param][0],
                callback_domain=callback_domain,
                method="get",
            )
            for t in o_tests:
                reporter.add_result(
                    url=t['url'],
                    param=t['param'],
                    payload=t['payload'],
                    method='oob-based',
                    vulnerable=t['vulnerable'],
                )
        # Scan forms
        for form in info.get('forms', []):
            action_url = form.get('action') or url
            method = form.get('method', 'get').lower()
            form_data = {i['name']: '1' for i in form.get('inputs', []) if i.get('name')}
            for param in list(form_data.keys()):
                tests = error_based.test_parameter(action_url, param, form_data[param], method=method, data=form_data)
                for t in tests:
                    reporter.add_result(
                        url=t['url'],
                        param=t['param'],
                        payload=t['payload'],
                        method='error-based',
                        vulnerable=t['vulnerable'],
                    )
                u_tests = union_based.test_parameter(action_url, param, form_data[param], method=method, data=form_data)
                for t in u_tests:
                    reporter.add_result(
                        url=t['url'],
                        param=t['param'],
                        payload=t['payload'],
                        method='union-based',
                        vulnerable=t['vulnerable'],
                    )
                b_tests = boolean_based.test_parameter(action_url, param, form_data[param], method=method, data=form_data)
                for t in b_tests:
                    reporter.add_result(
                        url=t['url'],
                        param=t['param'],
                        payload=t['payload'],
                        method='boolean-based',
                        vulnerable=t['vulnerable'],
                    )
                t_tests = time_based.test_parameter(action_url, param, form_data[param], method=method, data=form_data)
                for t in t_tests:
                    reporter.add_result(
                        url=t['url'],
                        param=t['param'],
                        payload=t['payload'],
                        method='time-based',
                        vulnerable=t['vulnerable'],
                    )
                o_tests = oob_based.test_parameter(
                    action_url,
                    param,
                    form_data[param],
                    callback_domain=callback_domain,
                    method=method,
                    data=form_data,
                )
                for t in o_tests:
                    reporter.add_result(
                        url=t['url'],
                        param=t['param'],
                        payload=t['payload'],
                        method='oob-based',
                        vulnerable=t['vulnerable'],
                    )
    reporter.write()
    print(f"Scan complete. Results written to report.csv")


if __name__ == '__main__':
    main()
