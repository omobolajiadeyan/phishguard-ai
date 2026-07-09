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

    def test_forwarded_legitimate_email_stays_safe_with_spf_failure(self):
        probability, features = score_email(
            "Project update",
            "Here is the project update from yesterday's working session.",
            "forwarder.example; spf=fail; dkim=pass; dmarc=pass",
        )

        self.assertEqual(classify(probability), "SAFE")
        self.assertEqual(features["spf_result"], "fail")

    def test_combined_authentication_failures_raise_phishing_score(self):
        subject = "Security alert"
        body = "Click here to verify your account."
        baseline, _ = score_email(subject, body)
        authenticated, features = score_email(
            subject,
            body,
            "mx.example; spf=fail; dkim=fail; dmarc=fail",
        )

        self.assertGreater(authenticated, baseline)
        self.assertEqual(classify(authenticated), "PHISHING")
        self.assertEqual(features["dmarc_result"], "fail")

    def test_authenticated_sender_can_still_be_phishing(self):
        # A fully SPF/DKIM/DMARC-passing sender (e.g. a compromised mailbox
        # or an attacker's own properly configured domain) must not have
        # its phishing score reduced by passing authentication. Passing
        # auth proves message-transport authenticity, not sender intent.
        subject = "URGENT: Account suspended"
        body = (
            "Click here immediately to verify your account or it will "
            "expire! See attachment."
        )
        baseline, _ = score_email(subject, body)
        authenticated, features = score_email(
            subject, body, "mx.example; spf=pass; dkim=pass; dmarc=pass"
        )

        self.assertEqual(authenticated, baseline)
        self.assertEqual(classify(authenticated), "PHISHING")
        self.assertEqual(
            (features["spf_result"], features["dkim_result"], features["dmarc_result"]),
            ("pass", "pass", "pass"),
        )

    def test_missing_authentication_header_matches_explicit_none(self):
        subject = "Weekly newsletter"
        body = "Here are this week's top stories from our editorial team."

        omitted, _ = score_email(subject, body)
        explicit_none, features = score_email(subject, body, None)

        self.assertEqual(omitted, explicit_none)
        self.assertEqual(
            (features["spf_result"], features["dkim_result"], features["dmarc_result"]),
            ("unknown", "unknown", "unknown"),
        )

    def test_malformed_authentication_results_degrades_to_no_header(self):
        subject = "URGENT: Account suspended"
        body = (
            "Click here immediately to verify your account or it will "
            "expire! See attachment."
        )
        baseline, _ = score_email(subject, body)
        malformed, features = score_email(
            subject, body, "totally not a valid header ;;; ==="
        )

        self.assertEqual(malformed, baseline)
        self.assertEqual(
            (features["spf_result"], features["dkim_result"], features["dmarc_result"]),
            ("unknown", "unknown", "unknown"),
        )

    def test_single_authentication_failure_is_proportional_not_decisive(self):
        # A lone DMARC failure (the heaviest-weighted auth signal, 0.18) on
        # an otherwise mild email should nudge the score up without being
        # enough on its own to flip a SAFE email to PHISHING.
        subject = "Weekly newsletter"
        body = "Here are this week's top stories from our editorial team."

        baseline, _ = score_email(subject, body)
        dmarc_fail_only, features = score_email(
            subject, body, "mx.example; spf=pass; dkim=pass; dmarc=fail"
        )

        self.assertGreater(dmarc_fail_only, baseline)
        self.assertEqual(classify(baseline), "SAFE")
        self.assertEqual(classify(dmarc_fail_only), "SAFE")
        self.assertEqual(features["dmarc_result"], "fail")


if __name__ == "__main__":
    unittest.main()
