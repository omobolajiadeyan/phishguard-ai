"""
PhishGuard AI HTTP server — stdlib-only REST API for URL and email scoring.

Intended for SIEM and proxy integrations that want a long-running scoring
endpoint instead of shelling out to the CLI per lookup. Binds to loopback
(127.0.0.1) by default; only bind to a wider host behind your own network
controls and authentication, since this server has none of its own.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from model import classify, score_email, score_url
from redirect import follow_redirects

MAX_BODY_BYTES = 1_000_000
MAX_FOLLOW_REDIRECTS = 20


class PhishGuardRequestHandler(BaseHTTPRequestHandler):
    server_version = "PhishGuardAI/1"

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/v1/url":
            self._handle_url()
        elif self.path == "/v1/email":
            self._handle_email()
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_url(self):
        data = self._read_json_body()
        if data is None or not isinstance(data.get("url"), str) or not data["url"]:
            self._send_json(
                400, {"error": "expected a JSON body with a non-empty 'url' string"}
            )
            return

        hops = data.get("follow_redirects", 0)
        if not isinstance(hops, int) or isinstance(hops, bool) or not (
            0 <= hops <= MAX_FOLLOW_REDIRECTS
        ):
            self._send_json(
                400,
                {
                    "error": (
                        "'follow_redirects' must be an integer between 0 and "
                        f"{MAX_FOLLOW_REDIRECTS}"
                    )
                },
            )
            return

        url = data["url"]
        chain_info = {}
        if hops > 0:
            chain_info = follow_redirects(url, max_hops=hops)
            final_url = chain_info["final_url"]
            extra = {
                "redirect_hops": chain_info["hops"],
                "redirect_crossed_domain": int(chain_info["crossed_domain"]),
            }
            probability, features = score_url(final_url, extra_features=extra)
        else:
            final_url = url
            probability, features = score_url(url)

        response = {
            "url": url,
            "final_url": final_url,
            "verdict": classify(probability),
            "probability": probability,
            "features": features,
        }
        if chain_info:
            response["redirect_chain"] = {
                "hops": chain_info["hops"],
                "crossed_domain": chain_info["crossed_domain"],
            }
        self._send_json(200, response)

    def _handle_email(self):
        data = self._read_json_body()
        if data is None:
            self._send_json(400, {"error": "expected a JSON body"})
            return

        subject = data.get("subject")
        body = data.get("body")
        if not isinstance(subject, str) or not isinstance(body, str):
            self._send_json(
                400, {"error": "expected 'subject' and 'body' strings"}
            )
            return

        auth_results = data.get("authentication_results")
        if auth_results is not None and not isinstance(auth_results, str):
            self._send_json(
                400, {"error": "'authentication_results' must be a string"}
            )
            return

        probability, features = score_email(
            subject, body, authentication_results=auth_results
        )
        self._send_json(
            200,
            {
                "verdict": classify(probability),
                "probability": probability,
                "features": features,
            },
        )


def run_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), PhishGuardRequestHandler)
    print(f"PhishGuard AI serving on http://{host}:{port}")
    print("Endpoints: GET /healthz, POST /v1/url, POST /v1/email")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
