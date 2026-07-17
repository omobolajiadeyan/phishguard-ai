"""Follow HTTP redirect chains to reveal the final destination URL.

Uses only the Python standard library so the zero-dependency promise is kept.
Network access is always optional: every error is caught and returned in the
result dict so the caller can decide whether to surface it or continue silently.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import urllib.parse

from psl import registrable_domain

_USER_AGENT = "PhishGuard-AI/0.5 redirect-tracer (+https://github.com/omobolajiadeyan/phishguard-ai)"
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_BLOCKED_HOSTNAMES = frozenset({"localhost"})


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _assert_public_host(hostname: str, port: int | None, scheme: str) -> None:
    """Reject hostnames that resolve to a private, loopback, or link-local
    address (including the 169.254.169.254 cloud metadata endpoint).

    The redirect tracer is reachable from an untrusted network caller via
    ``phishguard serve``, so every hop's destination — not just the URL a
    caller typed in directly — must be checked before connecting; otherwise
    a redirect chain could be used to make this process issue requests to
    internal services on the caller's behalf (SSRF). This is a pre-flight
    DNS check, not a guarantee against DNS rebinding between check and
    connect; closing that narrow gap would require connecting to the
    resolved IP directly, which breaks Host-header/SNI-based routing for
    the (common) legitimate case of tracing real redirect chains.
    """
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"Refusing to fetch internal host: {hostname}")

    default_port = 443 if scheme == "https" else 80
    try:
        results = socket.getaddrinfo(hostname, port or default_port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise ValueError(f"Could not resolve host: {hostname}") from exc

    for _family, _kind, _proto, _canon, sockaddr in results:
        if _is_blocked_ip(sockaddr[0]):
            raise ValueError(
                f"Refusing to fetch a redirect target that resolves to a "
                f"private or internal address: {hostname}"
            )


def _domain(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _registrable_domain(url: str) -> str:
    """eTLD+1 for *url*, e.g. "login.example.com" -> "example.com".

    Used for cross-domain redirect comparison so that same-organization
    subdomain redirects (www -> login) are not flagged merely for having
    different hostnames. See docs/DETECTION_MODEL.md and issue #29.
    """
    hostname = _domain(url)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return registrable_domain(hostname)
    return hostname


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

    _assert_public_host(hostname, port, parsed.scheme)

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
    origin = _registrable_domain(url)
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
        if _registrable_domain(next_url) != origin:
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
