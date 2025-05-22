import unittest
from scanner.diff import is_significant_diff


class DiffTests(unittest.TestCase):
    def test_identical(self):
        self.assertFalse(is_significant_diff("abc", "abc"))

    def test_small_difference(self):
        self.assertFalse(is_significant_diff("abc1", "abc2"))

    def test_large_difference(self):
        self.assertTrue(is_significant_diff("abc", "defghi"))

    def test_normalization(self):
        a = "2024-01-01 00:00:00 token 0123456789abcdef"
        b = "2025-02-02 01:01:01 token fedcba9876543210"
        self.assertFalse(is_significant_diff(a, b, threshold=0.5))


if __name__ == "__main__":
    unittest.main()
