"""Tests for the redirect chain tracer.

Network calls are not made in these tests. The module's error handling and
data-structure contracts are verified with local assertions only.
"""

import unittest

from redirect import follow_redirects, _domain


class DomainExtractionTests(unittest.TestCase):
    def test_extracts_hostname_from_https_url(self):
        self.assertEqual(_domain("https://example.com/path"), "example.com")

    def test_extracts_hostname_from_http_url(self):
        self.assertEqual(_domain("http://paypal.com"), "paypal.com")

    def test_lowercases_hostname(self):
        self.assertEqual(_domain("https://EXAMPLE.COM/path"), "example.com")

    def test_returns_empty_string_for_invalid_url(self):
        self.assertEqual(_domain("not-a-url"), "")


class RedirectResultContractTests(unittest.TestCase):
    """
    Verify the result dict always contains the required keys and that the
    function degrades gracefully when the target is unreachable.
    """

    REQUIRED_KEYS = {"final_url", "hops", "chain", "crossed_domain", "error"}

    def _assert_contract(self, result: dict, original_url: str) -> None:
        self.assertEqual(set(result.keys()), self.REQUIRED_KEYS)
        self.assertIsInstance(result["final_url"], str)
        self.assertIsInstance(result["hops"], int)
        self.assertIsInstance(result["chain"], list)
        self.assertIsInstance(result["crossed_domain"], bool)
        self.assertGreaterEqual(result["hops"], 0)
        self.assertGreaterEqual(len(result["chain"]), 1)
        self.assertEqual(result["chain"][0], original_url)

    def test_result_contract_on_unreachable_host(self):
        url = "http://127.0.0.1:19999/unreachable"
        result = follow_redirects(url, timeout=1)
        self._assert_contract(result, url)
        self.assertEqual(result["final_url"], url)
        self.assertEqual(result["hops"], 0)
        self.assertIsNotNone(result["error"])

    def test_result_contract_on_invalid_scheme(self):
        url = "ftp://example.com/file"
        result = follow_redirects(url, timeout=1)
        self._assert_contract(result, url)

    def test_chain_starts_with_original_url(self):
        url = "http://127.0.0.1:19999/test"
        result = follow_redirects(url, timeout=1)
        self.assertEqual(result["chain"][0], url)

    def test_hops_equals_chain_length_minus_one(self):
        url = "http://127.0.0.1:19999/test"
        result = follow_redirects(url, timeout=1)
        self.assertEqual(result["hops"], len(result["chain"]) - 1)

    def test_no_cross_domain_for_single_unreachable_url(self):
        url = "http://127.0.0.1:19999/test"
        result = follow_redirects(url, timeout=1)
        self.assertFalse(result["crossed_domain"])


if __name__ == "__main__":
    unittest.main()
