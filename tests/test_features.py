import unittest

from features import (
    has_opaque_hostname_label,
    has_punycode,
    has_unicode_hostname,
)


class IdnFeatureTests(unittest.TestCase):
    def test_detects_punycode_hostname_label(self):
        self.assertEqual(has_punycode("https://xn--bcher-kva.example/catalog"), 1)
        self.assertEqual(has_unicode_hostname("https://xn--bcher-kva.example/catalog"), 0)

    def test_detects_unicode_hostname(self):
        url = "https://b\u00fccher.example/catalog"

        self.assertEqual(has_unicode_hostname(url), 1)
        self.assertEqual(has_punycode(url), 0)

    def test_ignores_idn_markers_outside_hostname(self):
        self.assertEqual(has_punycode("https://example.com/xn--bcher-kva"), 0)
        self.assertEqual(has_unicode_hostname("https://example.com/\u00fcber"), 0)


class OpaqueHostnameFeatureTests(unittest.TestCase):
    def test_detects_long_compact_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://chillicancorne.example/"), 1)
        self.assertEqual(has_opaque_hostname_label("https://nycmydreamx.example/client"), 1)

    def test_ignores_short_or_structured_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://example.com"), 0)
        self.assertEqual(has_opaque_hostname_label("https://docs.python.org"), 0)
        self.assertEqual(has_opaque_hostname_label("https://secure-login.example"), 0)

    def test_ignores_long_non_reserved_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://stackoverflow.com/questions"), 0)
        self.assertEqual(has_opaque_hostname_label("https://randomsitexyz.io/login"), 0)

    def test_ignores_punycode_hostname_labels(self):
        self.assertEqual(has_opaque_hostname_label("https://xn--bcher-kva.example/catalog"), 0)


if __name__ == "__main__":
    unittest.main()
