"""Tests for the .eml file parsing command."""

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


SAFE_EML = textwrap.dedent("""\
    From: colleague@company.com
    To: you@company.com
    Subject: Project update
    Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8

    Hi,

    Here is the project update from yesterday's working session.
    Everything is on track. See you at the meeting tomorrow.

    Best,
    Colleague
""")

PHISHING_EML = textwrap.dedent("""\
    From: security@paypa1-secure.xyz
    To: victim@example.com
    Subject: URGENT: Your account has been suspended
    Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
    MIME-Version: 1.0
    Content-Type: text/plain; charset=utf-8

    URGENT ACTION REQUIRED

    Your account has been suspended due to unusual activity.
    Click here immediately to verify your account:
    http://paypa1-secure-login.xyz/account/verify?id=99999

    Failure to act will result in permanent account termination.
""")


def _write_eml(content: str, directory: str) -> str:
    path = Path(directory) / "test.eml"
    path.write_text(content, encoding="utf-8")
    return str(path)


def _run_eml(eml_path: str, *extra_args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "phishguard.py", "eml", eml_path, "--plain", *extra_args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


class EmlCommandTests(unittest.TestCase):
    def test_safe_eml_returns_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(SAFE_EML, td)
            result = _run_eml(path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_safe_eml_shows_subject(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(SAFE_EML, td)
            result = _run_eml(path)
        self.assertIn("Project update", result.stdout)

    def test_safe_eml_shows_safe_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(SAFE_EML, td)
            result = _run_eml(path)
        self.assertIn("SAFE", result.stdout)

    def test_phishing_eml_shows_phishing_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path)
        self.assertIn("PHISHING", result.stdout)

    def test_phishing_eml_reports_embedded_url(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path)
        self.assertIn("Embedded URLs", result.stdout)

    def test_phishing_eml_shows_source_path(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path)
        self.assertIn("Source", result.stdout)

    def test_missing_eml_file_exits_nonzero(self):
        result = _run_eml("/nonexistent/path/file.eml")
        self.assertNotEqual(result.returncode, 0)

    def test_verbose_flag_shows_feature_breakdown(self):
        with tempfile.TemporaryDirectory() as td:
            path = _write_eml(PHISHING_EML, td)
            result = _run_eml(path, "--verbose")
        self.assertIn("Feature breakdown:", result.stdout)

    def test_eml_output_saved_to_json(self):
        import json
        with tempfile.TemporaryDirectory() as td:
            eml_path = _write_eml(SAFE_EML, td)
            out_path = Path(td) / "result.json"
            result = _run_eml(eml_path, "--output", str(out_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIn("verdict", payload)
            self.assertIn("probability", payload)


if __name__ == "__main__":
    unittest.main()
