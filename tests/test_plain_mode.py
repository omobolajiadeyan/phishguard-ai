"""Regression tests for plain ASCII output mode."""

import io
import sys
import unittest
from contextlib import redirect_stdout

from phishguard import probability_bar, print_banner, analyze_url, analyze_email, batch_scan_urls


class TestPlainModeOutput(unittest.TestCase):
    """Test plain ASCII output mode."""

    def test_probability_bar_plain_mode(self):
        """Verify plain mode uses ASCII characters only."""
        # Test various probability values
        test_cases = [
            (0.0, "[--------------------]"),   # 0% risk
            (0.5, "[==========----------]"),     # 50% risk
            (0.75, "[===============-----]"),    # 75% risk
            (1.0, "[====================]"),     # 100% risk
        ]

        for prob, expected_bar_start in test_cases:
            result = probability_bar(prob, plain=True)
            # Verify no Unicode block characters are present
            self.assertNotIn("█", result, f"Plain mode should not contain Unicode blocks")
            self.assertNotIn("░", result, f"Plain mode should not contain Unicode blocks")
            # Verify ASCII characters are present
            self.assertIn("[", result, "Plain mode should contain brackets")
            self.assertIn("]", result, "Plain mode should contain brackets")

    def test_probability_bar_unicode_mode(self):
        """Verify Unicode mode uses block characters."""
        result = probability_bar(0.5, plain=False)
        # Should contain Unicode block characters
        self.assertIn("█", result, "Unicode mode should contain filled blocks")
        self.assertIn("░", result, "Unicode mode should contain empty blocks")
        # Should not contain plain mode characters (except percentage)
        lines_with_equals = result.count("=")
        lines_with_dashes = result.count("-")
        self.assertEqual(lines_with_equals, 0, "Unicode mode should not contain equals signs")
        self.assertEqual(lines_with_dashes, 0, "Unicode mode should not contain dash separators")

    def test_banner_plain_mode(self):
        """Verify plain banner contains no Unicode art."""
        output = io.StringIO()
        with redirect_stdout(output):
            print_banner(plain=True)
        banner_text = output.getvalue()
        
        # Plain mode should have simple text
        self.assertIn("PHISHGUARD AI", banner_text)
        # Should not contain box-drawing characters
        self.assertNotIn("█", banner_text)
        self.assertNotIn("╗", banner_text)
        self.assertNotIn("║", banner_text)

    def test_banner_unicode_mode(self):
        """Verify Unicode banner contains ASCII art."""
        output = io.StringIO()
        with redirect_stdout(output):
            print_banner(plain=False)
        banner_text = output.getvalue()
        
        # Unicode mode should have ASCII art with block characters
        self.assertIn("█", banner_text, "Unicode mode should contain block characters (ASCII art)")
        # Should contain the tagline (this is always there)
        self.assertIn("Explainable phishing detection", banner_text, "Should contain tagline")

    def test_analyze_url_plain_mode_output(self):
        """Verify analyze_url in plain mode produces no Unicode."""
        output = io.StringIO()
        with redirect_stdout(output):
            result = analyze_url("http://example.xyz", verbose=False, plain=True)
        
        analysis_output = output.getvalue()
        # Plain mode should use dashes for separator
        self.assertIn("-----", analysis_output, "Plain mode should use dashes for separator")
        # Should not contain Unicode separator
        self.assertNotIn("──", analysis_output, "Plain mode should not contain Unicode separators")
        # Should not contain Unicode block characters
        self.assertNotIn("█", analysis_output)
        self.assertNotIn("░", analysis_output)
        
        # Result dictionary should still be complete
        self.assertIn("url", result)
        self.assertIn("verdict", result)
        self.assertIn("probability", result)
        self.assertIn("features", result)

    def test_analyze_url_unicode_mode_output(self):
        """Verify analyze_url in Unicode mode produces decorations."""
        output = io.StringIO()
        with redirect_stdout(output):
            result = analyze_url("http://example.xyz", verbose=False, plain=False)
        
        analysis_output = output.getvalue()
        # Unicode mode should use fancy separator
        self.assertIn("─", analysis_output, "Unicode mode should use fancy separator")
        # Should contain Unicode separator line
        lines = [l.strip() for l in analysis_output.split("\n") if l.strip()]
        separator_line = [l for l in lines if "─" in l]
        self.assertTrue(separator_line, "Should find Unicode separator line")
        
        # Result dictionary should still be complete
        self.assertIn("url", result)
        self.assertIn("verdict", result)
        self.assertIn("probability", result)
        self.assertIn("features", result)

    def test_analyze_email_plain_mode(self):
        """Verify analyze_email in plain mode produces no Unicode."""
        output = io.StringIO()
        with redirect_stdout(output):
            result = analyze_email(
                subject="Account verification required",
                body="Click here to verify",
                verbose=False,
                plain=True
            )
        
        analysis_output = output.getvalue()
        # Plain mode checks
        self.assertNotIn("█", analysis_output)
        self.assertNotIn("░", analysis_output)
        self.assertIn("-----", analysis_output)
        
        # Result should be complete
        self.assertIn("subject", result)
        self.assertIn("verdict", result)
        self.assertIn("probability", result)

    def test_plain_mode_preserves_verdicts(self):
        """Verify plain mode doesn't affect verdict classification."""
        # Test that the same input produces same verdict in both modes
        output_plain = io.StringIO()
        with redirect_stdout(output_plain):
            result_plain = analyze_url("http://example.xyz", plain=True)
        
        output_unicode = io.StringIO()
        with redirect_stdout(output_unicode):
            result_unicode = analyze_url("http://example.xyz", plain=False)
        
        # Verdicts and probabilities should be identical
        self.assertEqual(result_plain["verdict"], result_unicode["verdict"])
        self.assertEqual(result_plain["probability"], result_unicode["probability"])


if __name__ == "__main__":
    unittest.main()
