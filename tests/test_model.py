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
