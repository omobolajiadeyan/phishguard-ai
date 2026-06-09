from contextlib import redirect_stdout
from io import StringIO
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import phishguard


class CliTests(unittest.TestCase):
    def assert_plain_output(self, output):
        self.assertTrue(output.isascii(), output)
        self.assertNotIn("\033[", output)
        self.assertIn("-" * 60, output)

    def test_url_command_handles_limited_console_encoding(self):
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "cp1252"

        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://www.google.com",
            ],
            capture_output=True,
            text=True,
            encoding="cp1252",
            env=environment,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SAFE", result.stdout)

    def test_plain_url_command_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://www.google.com",
                "--verbose",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_plain_output(result.stdout)
        self.assertIn("Feature breakdown:", result.stdout)
        self.assertIn("#", result.stdout)

    def test_plain_email_command_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "email",
                "--subject",
                "Meeting reminder",
                "--body",
                "Our meeting is scheduled for tomorrow.",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_plain_output(result.stdout)
        self.assertIn("Subject : Meeting reminder", result.stdout)

    def test_email_command_accepts_authentication_results(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "email",
                "--subject",
                "Security alert",
                "--body",
                "Click here to verify your account.",
                "--authentication-results",
                "mx.example; spf=fail; dkim=fail; dmarc=fail",
                "--verbose",
                "--plain",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dmarc_result              : fail", result.stdout)

    def test_no_unicode_batch_command_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "batch",
                "data/urls.txt",
                "--no-unicode",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_plain_output(result.stdout)
        self.assertIn("Scanning", result.stdout)
        self.assertIn("Summary:", result.stdout)

    def test_plain_mode_keeps_json_report_unchanged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "result.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "phishguard.py",
                    "url",
                    "https://www.google.com",
                    "--plain",
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["url"], "https://www.google.com")
            self.assertEqual(payload["verdict"], "SAFE")
            self.assertIsInstance(payload["probability"], float)
            self.assertIsInstance(payload["features"], dict)

    def test_plain_mode_does_not_persist_between_in_process_calls(self):
        plain_output = StringIO()
        with redirect_stdout(plain_output):
            phishguard.analyze_url("https://www.google.com", plain=True)

        decorated_output = StringIO()
        with redirect_stdout(decorated_output):
            phishguard.analyze_url("https://www.google.com")

        plain_text = plain_output.getvalue()
        decorated_text = decorated_output.getvalue()

        self.assert_plain_output(plain_text)
        self.assertIn("\033[", decorated_text)
        self.assertIn(phishguard.separator(), decorated_text)

    def test_batch_command_writes_sarif_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "results.sarif"
            result = subprocess.run(
                [
                    sys.executable,
                    "phishguard.py",
                    "batch",
                    "data/urls.txt",
                    "--format",
                    "sarif",
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertTrue(payload["runs"][0]["results"])
            self.assertTrue(
                all(
                    finding["level"] in {"warning", "error"}
                    for finding in payload["runs"][0]["results"]
                )
            )

    def test_sarif_format_requires_output_path(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://example.com",
                "--format",
                "sarif",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("--format sarif requires --output", result.stderr)


if __name__ == "__main__":
    unittest.main()
