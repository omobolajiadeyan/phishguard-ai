import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from server import PhishGuardRequestHandler


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), PhishGuardRequestHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, path, payload, expect_status=200):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._url(path),
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                self.assertEqual(exc.code, expect_status)
                return exc.code, json.loads(exc.read())

    def test_healthz(self):
        with urllib.request.urlopen(self._url("/healthz"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read()), {"status": "ok"})

    def test_unknown_get_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/nope"), timeout=5)
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 404)

    def test_url_scoring_offline(self):
        status, body = self._post(
            "/v1/url", {"url": "http://paypa1-secure-login.xyz/verify"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["url"], "http://paypa1-secure-login.xyz/verify")
        self.assertIn(body["verdict"], {"PHISHING", "SUSPICIOUS", "SAFE"})
        self.assertIn("features", body)
        self.assertNotIn("redirect_chain", body)

    def test_url_missing_field_is_400(self):
        status, body = self._post("/v1/url", {}, expect_status=400)
        self.assertEqual(status, 400)
        self.assertIn("error", body)

    def test_url_invalid_follow_redirects_is_400(self):
        status, body = self._post(
            "/v1/url",
            {"url": "https://example.com", "follow_redirects": -1},
            expect_status=400,
        )
        self.assertEqual(status, 400)

    def test_url_follow_redirects_uses_final_destination(self):
        chain = {
            "final_url": "https://example.com/landing",
            "hops": 2,
            "chain": ["https://bit.ly/abc", "https://example.com/landing"],
            "crossed_domain": True,
            "error": None,
        }
        with patch("server.follow_redirects", return_value=chain):
            status, body = self._post(
                "/v1/url", {"url": "https://bit.ly/abc", "follow_redirects": 3}
            )
        self.assertEqual(status, 200)
        self.assertEqual(body["final_url"], "https://example.com/landing")
        self.assertEqual(body["redirect_chain"], {"hops": 2, "crossed_domain": True})

    def test_email_scoring(self):
        status, body = self._post(
            "/v1/email",
            {
                "subject": "URGENT: verify your account now",
                "body": "Click here immediately!!!",
            },
        )
        self.assertEqual(status, 200)
        self.assertIn(body["verdict"], {"PHISHING", "SUSPICIOUS", "SAFE"})
        self.assertIn("features", body)

    def test_email_missing_fields_is_400(self):
        status, body = self._post("/v1/email", {"subject": "hi"}, expect_status=400)
        self.assertEqual(status, 400)

    def test_post_unknown_path_is_404(self):
        status, body = self._post("/v1/nope", {"a": 1}, expect_status=404)
        self.assertEqual(status, 404)

    def test_malformed_json_is_400(self):
        req = urllib.request.Request(
            self._url("/v1/url"),
            data=b"{not json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        with ctx.exception:
            self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
