import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
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

    def test_url_command_plain_mode_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "url",
                "https://www.google.com",
                "--plain",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertIn("SAFE", result.stdout)

        self.assertNotIn("█", result.stdout)
        self.assertNotIn("░", result.stdout)
        self.assertNotIn("─", result.stdout)

    def test_email_command_plain_mode_uses_ascii_output(self):
        result = subprocess.run(
            [
                sys.executable,
                "phishguard.py",
                "email",
                "--subject",
                "Hello",
                "--body",
                "Test email",
                "--plain",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertNotIn("█", result.stdout)
        self.assertNotIn("░", result.stdout)
        self.assertNotIn("─", result.stdout)

        self.assertIn("Risk", result.stdout)


if __name__ == "__main__":
    unittest.main()