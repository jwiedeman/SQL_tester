import unittest
from unittest.mock import patch
import urllib.parse

from scanner.detectors import error_based, union_based, boolean_based, time_based, oob_based, graphql_based


class DetectorModuleTests(unittest.TestCase):
    def test_error_based_detection(self):
        with patch('scanner.detectors.error_based.send_request', return_value='You have an error in your SQL syntax'):
            results = error_based.test_parameter('http://example.com/?id=1', 'id', '1')
        self.assertGreater(len(results), 0)
        self.assertTrue(all(r['vulnerable'] for r in results))

    def test_error_based_no_detection(self):
        with patch('scanner.detectors.error_based.send_request', return_value='OK'):
            results = error_based.test_parameter('http://example.com/?id=1', 'id', '1')
        self.assertTrue(all(not r['vulnerable'] for r in results))

    def test_union_based_detection(self):
        def fake_fetch(url, method='get', data=None, cookies=None, headers=None, *, use_cache=False):
            return 'baseline' if use_cache else 'altered'
        with patch('scanner.detectors.union_based.fetch', side_effect=fake_fetch), \
             patch('scanner.detectors.union_based.is_response_stable', return_value=True), \
             patch('scanner.detectors.union_based.diff.is_significant_diff', side_effect=lambda a, b, threshold=0.15: a != b):
            results = union_based.test_parameter('http://example.com/?id=1', 'id', '1')
        self.assertTrue(all(r['vulnerable'] for r in results))

    def test_boolean_based_detection(self):
        def fake_fetch(url, method='get', data=None, cookies=None, headers=None, *, use_cache=False):
            if use_cache:
                return 'baseline'
            target = url if method == 'get' else urllib.parse.urlencode(data or {})
            if '%3D%271' in target or '%3D%221' in target or '%3D1' in target:
                return 'truebody'
            return 'baseline'
        fake_diff = type('D', (), {'is_significant_diff': staticmethod(lambda a, b, threshold=0.15: a != b)})
        with patch('scanner.detectors.boolean_based.fetch', side_effect=fake_fetch), \
             patch('scanner.detectors.boolean_based.is_response_stable', return_value=True), \
             patch.object(boolean_based, 'diff', fake_diff, create=True):
            results = boolean_based.test_parameter('http://example.com/?id=1', 'id', '1')
        self.assertGreater(len(results), 0)
        self.assertTrue(all(r['vulnerable'] for r in results))

    def test_time_based_detection(self):
        with patch('scanner.detectors.time_based.average_response_time', return_value=(0.1, 0.0)), \
             patch('scanner.detectors.time_based.fetch', return_value=('body', 6.0)):
            results = time_based.test_parameter('http://example.com/?id=1', 'id', '1', delay_threshold=5.0)
        self.assertGreater(len(results), 0)
        self.assertTrue(all(r['vulnerable'] for r in results))

    def test_graphql_based_detection(self):
        responses = ['{"data": {"__typename": "Root"}}', 'syntax error', 'syntax error']
        def fake_send(*args, **kwargs):
            return responses.pop(0)
        with patch('scanner.detectors.graphql_based.send_request', side_effect=fake_send):
            results = graphql_based.test_endpoint('http://example.com/graphql')
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r['vulnerable'] for r in results))

    def test_oob_based_generation(self):
        with patch('scanner.detectors.oob_based.send_request'):
            results = oob_based.test_parameter('http://example.com/?id=1', 'id', '1', callback_domain='cb.example')
        self.assertEqual(len(results), len(oob_based.PAYLOADS))
        for r in results:
            self.assertFalse(r['vulnerable'])
            self.assertIn('token', r)
            self.assertEqual(len(r['token']), 32)


if __name__ == '__main__':
    unittest.main()
