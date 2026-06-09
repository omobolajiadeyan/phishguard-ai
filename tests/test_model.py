import unittest

from model import classify, score_email, score_url


class UrlScoringTests(unittest.TestCase):
    def test_known_legitimate_urls_are_safe(self):
        urls = (
            "https://www.google.com",
            "https://github.com/omobolajiadeyan",
            "https://www.bbc.co.uk/news",
            "https://stackoverflow.com/questions",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, _ = score_url(url)
                self.assertEqual(classify(probability), "SAFE")

    def test_obvious_phishing_urls_are_phishing(self):
        urls = (
            "http://paypa1-secure-login.xyz/account/verify?id=12345",
            "http://192.168.1.1/banking/login.php",
            "http://amazon-security-alert.tk/confirm-account",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, _ = score_url(url)
                self.assertEqual(classify(probability), "PHISHING")

    def test_legitimate_idn_signals_are_safe(self):
        urls = (
            "https://xn--bcher-kva.example/catalog",
            "https://b\u00fccher.example/catalog",
        )

        for url in urls:
            with self.subTest(url=url):
                probability, features = score_url(url)
                self.assertEqual(classify(probability), "SAFE")
                self.assertEqual(
                    features["has_punycode"] + features["has_unicode_hostname"],
                    1,
                )

    def test_punycode_combines_with_credential_lure_signals(self):
        probability, features = score_url(
            "https://xn--pple-43d.example/login/verify"
        )

        self.assertEqual(classify(probability), "SUSPICIOUS")
        self.assertEqual(features["has_punycode"], 1)
        self.assertEqual(features["phishing_keywords"], 2)


class EmailScoringTests(unittest.TestCase):
    def test_normal_email_is_safe(self):
        probability, _ = score_email(
            "Meeting reminder",
            "Our meeting is scheduled for tomorrow at 10 AM.",
        )

        self.assertEqual(classify(probability), "SAFE")

    def test_urgent_account_lure_is_phishing(self):
        probability, _ = score_email(
            "URGENT: Account suspended",
            "Click here immediately to verify your account or it will expire!",
        )

        self.assertEqual(classify(probability), "PHISHING")


if __name__ == "__main__":
    unittest.main()
