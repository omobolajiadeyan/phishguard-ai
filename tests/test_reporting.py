import unittest

from reporting import SARIF_SCHEMA, build_sarif


class SarifReportingTests(unittest.TestCase):
    def test_safe_results_are_omitted(self):
        sarif = build_sarif(
            {
                "url": "https://example.com",
                "verdict": "SAFE",
                "probability": 0.1,
                "features": {},
            }
        )

        self.assertEqual(sarif["$schema"], SARIF_SCHEMA)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_phishing_result_is_an_error_with_explainable_properties(self):
        result = {
            "url": "http://paypa1-secure-login.xyz/verify",
            "verdict": "PHISHING",
            "probability": 0.98,
            "features": {"suspicious_tld": 1},
        }

        sarif_result = build_sarif(result)["runs"][0]["results"][0]

        self.assertEqual(sarif_result["ruleId"], "PHISHGUARD_PHISHING")
        self.assertEqual(sarif_result["level"], "error")
        self.assertEqual(sarif_result["properties"]["probability"], 0.98)
        self.assertEqual(
            sarif_result["properties"]["features"],
            {"suspicious_tld": 1},
        )
        self.assertEqual(
            sarif_result["locations"][0]["logicalLocations"][0]["kind"],
            "url",
        )

    def test_fingerprints_are_deterministic(self):
        result = {
            "subject": "Urgent account warning",
            "verdict": "SUSPICIOUS",
            "probability": 0.65,
            "features": {"urgency_word_count": 1},
        }

        first = build_sarif(result)["runs"][0]["results"][0]
        second = build_sarif(result)["runs"][0]["results"][0]

        self.assertEqual(first["level"], "warning")
        self.assertEqual(first["partialFingerprints"], second["partialFingerprints"])
        self.assertEqual(
            first["locations"][0]["logicalLocations"][0]["kind"],
            "email",
        )

    # ── new regression tests for issue #5 ────────────────────────────────────

    def test_safe_email_omitted_from_sarif(self):
        sarif = build_sarif(
            {"subject": "Hello", "verdict": "SAFE", "probability": 0.05, "features": {}}
        )
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_single_suspicious_email_produces_warning(self):
        sarif = build_sarif(
            {"subject": "Win a prize!", "verdict": "SUSPICIOUS", "probability": 0.55, "features": {}}
        )
        finding = sarif["runs"][0]["results"][0]
        self.assertEqual(finding["ruleId"], "PHISHGUARD_SUSPICIOUS")
        self.assertEqual(finding["level"], "warning")

    def test_line_number_preserved_exactly(self):
        """A URL on line 4 (after comments/blanks) must report startLine=4."""
        result = {
            "url": "http://evil.xyz",
            "verdict": "PHISHING",
            "probability": 0.9,
            "features": {},
            "source_path": "urls.txt",
            "line_number": 4,
        }
        sarif = build_sarif(result)
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], 4)

    def test_comment_lines_do_not_shift_line_number(self):
        """Two URLs at lines 2 and 5 must keep those exact positions."""
        results = [
            {"url": "http://a.xyz", "verdict": "PHISHING", "probability": 0.9,
             "features": {}, "source_path": "batch.txt", "line_number": 2},
            {"url": "http://b.xyz", "verdict": "PHISHING", "probability": 0.9,
             "features": {}, "source_path": "batch.txt", "line_number": 5},
        ]
        sarif = build_sarif(results)
        findings = sarif["runs"][0]["results"]
        lines = [
            f["locations"][0]["physicalLocation"]["region"]["startLine"]
            for f in findings
        ]
        self.assertEqual(lines, [2, 5])

    def test_no_physical_location_without_metadata(self):
        """Results without source_path/line_number must have no physicalLocation."""
        result = {
            "url": "http://evil.xyz",
            "verdict": "PHISHING",
            "probability": 0.9,
            "features": {},
        }
        sarif = build_sarif(result)
        location = sarif["runs"][0]["results"][0]["locations"][0]
        self.assertNotIn("physicalLocation", location)

    def test_artifact_location_is_basename_only(self):
        """Full paths must be reduced to filename only in artifactLocation.uri."""
        result = {
            "url": "http://evil.xyz",
            "verdict": "PHISHING",
            "probability": 0.9,
            "features": {},
            "source_path": "/home/user/data/urls.txt",
            "line_number": 7,
        }
        sarif = build_sarif(result)
        uri = (
            sarif["runs"][0]["results"][0]["locations"][0]
            ["physicalLocation"]["artifactLocation"]["uri"]
        )
        self.assertEqual(uri, "urls.txt")
       
if __name__ == "__main__":
    unittest.main()
