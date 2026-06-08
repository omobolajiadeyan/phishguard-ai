import os
import subprocess
import sys
import unittest


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


if __name__ == "__main__":
    unittest.main()
