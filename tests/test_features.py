import unittest

from features import has_punycode, has_unicode_hostname


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


if __name__ == "__main__":
    unittest.main()
