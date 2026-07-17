"""
web/scoring.js is an independent JavaScript port of model.py + features.py +
email_auth.py, used by the static (no-backend) browser demo. This test runs
both implementations on the same inputs and fails the suite if they ever
disagree, so the JS port can't silently drift from the Python original it's
supposed to mirror.

Requires `node` on PATH; skipped (not failed) if it isn't available, since
the Python implementation is authoritative and CI environments without
Node.js can still run the rest of the suite.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from model import classify, score_email, score_url

ROOT = Path(__file__).resolve().parents[1]
SCORING_JS = ROOT / "web" / "scoring.js"

URL_CASES = [
    "https://www.google.com/search?q=test",
    "http://paypa1-secure-login.xyz/verify",
    "https://bit.ly/abc123",
    "http://192.168.1.1/login",
    "http://192.0.2.10:8080/admin?token=abc123",
    "https://accounts.google.com.security-check.top/signin",
    "http://xn--e1aybc.xn--p1ai/",
    "http://paypal.com@evil.com/login",
    "https://github.com/omobolajiadeyan/phishguard-ai",
    "http://amaz0n-account-suspended.click/verify?user=1&token=" + "a" * 40,
    "https://sub.sub2.sub3.example.com/a/b/c/d",
    "http://EXAMPLE.COM/Path/To/Resource",
    "ftp://example.com/not-http",
    "not-a-url-at-all",
    "https://example.com",
    "http://xjr7f2k9qz.example/",
    "https://xn--pple-43d.com/signin",
    "http://" + "a" * 63 + ".example.com/",
    "https://example.com:65535/",
    "http://User:Pa%40ss@example.com/path?x=1#frag",
    "https://xn--e1aybc.xn--p1ai/login",
    "http://256.1.1.1/notanip",
    "http://0177.0.0.1/",
    "   https://example.com/   ",
    "http://[::1]:8080/path",
    "http://a@b@evil.com/",
    "https://exa mple.com/path",
    "\t\thttps://example.com/path",
]

EMAIL_CASES = [
    ("URGENT: Your account has been suspended", "Click here immediately to verify your account.", None),
    ("Meeting notes", "Let's catch up next week about the roadmap.", None),
    ("Re: Invoice #4521", "Please see the attached file for your records.", None),
    (
        "Security Alert",
        "We detected unusual activity!!! Please confirm your identity immediately.",
        "mx.example; spf=fail; dkim=fail; dmarc=fail",
    ),
    ("", "", None),
    ("Newsletter", "<html><body><h1>Big News</h1><p>Read more at www.example.com</p></body></html>", None),
    (
        "Password reset",
        "Someone requested a password reset. If this wasn't you, ignore this email.",
        "mx.example; spf=pass; dkim=pass; dmarc=pass",
    ),
]


def _run_js(payload: dict) -> dict:
    script = """
      const PhishGuardScoring = require(process.argv[1]);
      const input = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
      const out = { urls: [], emails: [] };
      for (const url of input.urls) {
        const { probability, features } = PhishGuardScoring.scoreUrl(url);
        out.urls.push({ probability, verdict: PhishGuardScoring.classify(probability), features });
      }
      for (const [subject, body, auth] of input.emails) {
        const { probability, features } = PhishGuardScoring.scoreEmail(subject, body, auth);
        out.emails.push({ probability, verdict: PhishGuardScoring.classify(probability), features });
      }
      process.stdout.write(JSON.stringify(out));
    """
    result = subprocess.run(
        ["node", "-e", script, str(SCORING_JS)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which("node"), "node is not available on PATH")
class JsPortParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js_results = _run_js({"urls": URL_CASES, "emails": EMAIL_CASES})

    def test_url_scoring_matches_python(self):
        for url, js_result in zip(URL_CASES, self.js_results["urls"]):
            with self.subTest(url=url):
                py_probability, py_features = score_url(url)
                py_verdict = classify(py_probability)

                self.assertAlmostEqual(
                    js_result["probability"], py_probability, places=3,
                    msg=f"probability mismatch for {url!r}",
                )
                self.assertEqual(
                    js_result["verdict"], py_verdict, msg=f"verdict mismatch for {url!r}"
                )
                for key, py_value in py_features.items():
                    self.assertIn(key, js_result["features"], msg=f"missing feature {key!r} for {url!r}")
                    js_value = js_result["features"][key]
                    if isinstance(py_value, float):
                        self.assertAlmostEqual(
                            js_value, py_value, places=3,
                            msg=f"feature {key!r} mismatch for {url!r}",
                        )
                    else:
                        self.assertEqual(
                            js_value, py_value, msg=f"feature {key!r} mismatch for {url!r}"
                        )

    def test_email_scoring_matches_python(self):
        for (subject, body, auth), js_result in zip(EMAIL_CASES, self.js_results["emails"]):
            with self.subTest(subject=subject):
                py_probability, py_features = score_email(subject, body, authentication_results=auth)
                py_verdict = classify(py_probability)

                self.assertAlmostEqual(
                    js_result["probability"], py_probability, places=3,
                    msg=f"probability mismatch for {subject!r}",
                )
                self.assertEqual(
                    js_result["verdict"], py_verdict, msg=f"verdict mismatch for {subject!r}"
                )
                for key, py_value in py_features.items():
                    self.assertIn(key, js_result["features"], msg=f"missing feature {key!r} for {subject!r}")
                    js_value = js_result["features"][key]
                    if isinstance(py_value, float):
                        self.assertAlmostEqual(
                            js_value, py_value, places=3,
                            msg=f"feature {key!r} mismatch for {subject!r}",
                        )
                    else:
                        self.assertEqual(
                            js_value, py_value, msg=f"feature {key!r} mismatch for {subject!r}"
                        )


if __name__ == "__main__":
    unittest.main()
