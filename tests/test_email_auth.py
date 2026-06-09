import unittest

from email_auth import (
    extract_authentication_features,
    parse_authentication_results,
)


class AuthenticationResultsParserTests(unittest.TestCase):
    def test_parses_case_insensitive_pass_results(self):
        results = parse_authentication_results(
            "mx.example; SPF=PASS smtp.mailfrom=example.com; "
            "DKIM=pass header.d=example.com; DMARC=Pass"
        )

        self.assertEqual(
            results,
            {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        )

    def test_parses_mixed_results(self):
        results = parse_authentication_results(
            "mx.example; spf=softfail; dkim=neutral; dmarc=fail"
        )

        self.assertEqual(
            results,
            {"spf": "softfail", "dkim": "neutral", "dmarc": "fail"},
        )

    def test_missing_and_malformed_values_are_unknown(self):
        expected = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

        self.assertEqual(parse_authentication_results(None), expected)
        self.assertEqual(
            parse_authentication_results("mx.example; spf=; dkim=(broken)"),
            expected,
        )

    def test_unsupported_results_are_unknown(self):
        results = parse_authentication_results(
            "mx.example; spf=temperror; dkim=permerror; dmarc=bestguesspass"
        )

        self.assertEqual(
            results,
            {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        )

    def test_first_supported_result_wins_for_duplicate_methods(self):
        results = parse_authentication_results(
            "mx.example; spf=pass; spf=fail; dkim=pass"
        )

        self.assertEqual(results["spf"], "pass")

    def test_extracts_conservative_numeric_risk(self):
        features = extract_authentication_features(
            "mx.example; spf=softfail; dkim=fail; dmarc=pass"
        )

        self.assertEqual(features["spf_auth_risk"], 0.5)
        self.assertEqual(features["dkim_auth_risk"], 1.0)
        self.assertEqual(features["dmarc_auth_risk"], 0.0)


if __name__ == "__main__":
    unittest.main()
