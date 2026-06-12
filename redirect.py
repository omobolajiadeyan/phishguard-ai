"""Follow HTTP redirect chains to reveal the final destination URL.

Uses only the Python standard library so the zero-dependency promise is kept.
Network access is always optional: every error is caught and returned in the
result dict so the caller can decide whether to surface it or continue silently.
"""

from __future__ import annotations

import http.client
import ssl
import urllib.parse


_USER_AGENT = "PhishGuard-AI/0.5 redirect-tracer (+https://github.com/omobolajiadeyan/phishguard-ai)"
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


def _domain(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _head(url: str, timeout: int) -> tuple[int, str | None]:
    """
    Send a single HEAD request and return (status_code, Location_header).
    Raises on connection failure so the caller can record the error.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported redirect scheme: {parsed.scheme or '(missing)'}")
    if not parsed.hostname:
        raise ValueError("Redirect URL is missing a hostname")

    hostname = parsed.hostname or ""
    port = parsed.port  # None means use the scheme default
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    headers = {"User-Agent": _USER_AGENT, "Connection": "close"}

    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            hostname, port=port, timeout=timeout, context=ctx
        )
    else:
        conn = http.client.HTTPConnection(hostname, port=port, timeout=timeout)

    try:
        conn.request("HEAD", path, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.getheader("Location")
    finally:
        conn.close()


def follow_redirects(
    url: str,
    max_hops: int = 5,
    timeout: int = 5,
) -> dict:
    """
    Follow HTTP redirects up to *max_hops* and return chain metadata.

    Result keys
    -----------
    final_url       : last URL reached (original URL on any error)
    hops            : number of redirects successfully followed
    chain           : ordered list of every URL visited (includes the start)
    crossed_domain  : True when any hop left the original registrable domain
    error           : human-readable error string, or None on clean completion
    """
    chain: list[str] = [url]
    origin = _domain(url)
    crossed = False
    error: str | None = None
    current = url

    for _ in range(max_hops):
        try:
            status, location = _head(current, timeout)
        except Exception as exc:
            error = str(exc)
            break

        if status not in _REDIRECT_CODES:
            break

        if not location:
            error = f"Redirect {status} with no Location header"
            break

        next_url = urllib.parse.urljoin(current, location)
        if _domain(next_url) != origin:
            crossed = True

        chain.append(next_url)
        current = next_url

    return {
        "final_url": chain[-1],
        "hops": len(chain) - 1,
        "chain": chain,
        "crossed_domain": crossed,
        "error": error,
    }
