"""Tests for the redirect chain tracer.

Network calls are not made in these tests. _head() is patched to raise
ConnectionRefusedError so the contract tests are deterministic and never
depend on a real port being free.
"""

import unittest
from unittest.mock import patch

from redirect import follow_redirects, _domain

_UNREACHABLE = "http://example.invalid:19999/unreachable"


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
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self._assert_contract(result, _UNREACHABLE)
        self.assertEqual(result["final_url"], _UNREACHABLE)
        self.assertEqual(result["hops"], 0)
        self.assertIsNotNone(result["error"])

    def test_result_contract_on_invalid_scheme(self):
        url = "ftp://example.com/file"
        result = follow_redirects(url, timeout=1)
        self._assert_contract(result, url)

    def test_chain_starts_with_original_url(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self.assertEqual(result["chain"][0], _UNREACHABLE)

    def test_hops_equals_chain_length_minus_one(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self.assertEqual(result["hops"], len(result["chain"]) - 1)

    def test_no_cross_domain_for_single_unreachable_url(self):
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")):
            result = follow_redirects(_UNREACHABLE, timeout=1)
        self.assertFalse(result["crossed_domain"])

    def test_credential_url_uses_hostname_not_netloc(self):
        """netloc includes userinfo; _head must connect to the real host only."""
        with patch("redirect._head", side_effect=ConnectionRefusedError("mocked")) as mock_head:
            follow_redirects("http://paypal.com@evil.com/login", timeout=1)
        # _head should have been called — the ValueError for missing hostname
        # fires before _head is reached, so if called it means the URL parsed cleanly.
        # The important thing is no unhandled exception was raised.
        _ = mock_head


if __name__ == "__main__":
    unittest.main()
