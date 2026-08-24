"""Domain-age lookup via RDAP -- an optional, network-dependent signal.

Newly-registered domains are one of the strongest real-world phishing
indicators: most phishing domains are registered within days of a campaign,
but a URL string alone cannot reveal registration date. This module is the
one place PhishGuard makes a network call to a *fixed, trusted* third party
(the RDAP bootstrap at rdap.org) to look up a domain's registration date --
never to the domain being scored itself, so this carries none of the SSRF
exposure that redirect.py guards against (the connection target is always
rdap.org; the scored domain is only ever sent as a URL path segment).

Every failure -- timeout, no RDAP record, rate limiting, a TLD with no
participating registry, malformed JSON -- is caught and turned into
"unknown" rather than raised, so a caller can never have a scan break just
because it opted into this. Opt-in only: the default, offline scan never
calls this module. See docs/BENCHMARK.md's "Domain-Age Validation" section
for the measured recall/false-positive impact and docs/DETECTION_MODEL.md
for the feature weights.

rdap.org's free bootstrap rate-limits aggressively (observed 429s after
roughly ten rapid requests during development). This module does not retry
or back off on 429 -- a rate-limited lookup degrades to "unknown" exactly
like any other failure, which is the honest behavior for a shared public
service. Callers that need to check many domains (see
tools/evaluate_live_traffic_benchmark.py's --check-domain-age) should add
their own delay between lookups; the CLI and REST server intentionally
offer this feature only for single-URL lookups (`url`, `eml`, `POST
/v1/url`), not `batch`, so routine use can't hammer the shared service.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from psl import registrable_domain

_RDAP_BASE = "https://rdap.org/domain/"
_USER_AGENT = (
    "PhishGuard-AI/0.5 domain-age-lookup "
    "(+https://github.com/omobolajiadeyan/phishguard-ai)"
)

# Newly-registered-domain thresholds. Both may be 1 at once (a 10-day-old
# domain is also "newer than 90d"); see model.py for the weight rationale.
_NEW_DOMAIN_DAYS = 30
_RECENT_DOMAIN_DAYS = 90

# Per-process cache keyed by registrable domain, so a single .eml or batch
# run never looks the same domain up twice -- both to spare the shared
# rdap.org service and because repeated lookups add nothing.
_cache: dict[str, int | None] = {}


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _parse_registration_date(payload: dict) -> datetime | None:
    for event in payload.get("events", []) or []:
        if event.get("eventAction") != "registration":
            continue
        raw_date = event.get("eventDate")
        if not raw_date:
            return None
        try:
            return datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _fetch_registration_age_days(domain: str, timeout: float) -> int | None:
    request = urllib.request.Request(
        _RDAP_BASE + domain,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/rdap+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        # Deliberately broad: DNS failure, timeout, HTTP 4xx/5xx (including
        # the 429s this free bootstrap issues under load), TLS errors, and
        # malformed JSON all mean the same thing to a caller -- "unknown".
        return None

    registered = _parse_registration_date(payload)
    if registered is None:
        return None
    return max((datetime.now(timezone.utc) - registered).days, 0)


def lookup_domain_age_days(url: str, timeout: float = 5.0) -> int | None:
    """Return the registrable domain's age in days, or None when unknown."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return None
    if not hostname or _is_ip_literal(hostname):
        return None

    domain = registrable_domain(hostname)
    if domain in _cache:
        return _cache[domain]

    age_days = _fetch_registration_age_days(domain, timeout)
    _cache[domain] = age_days
    return age_days


def domain_age_features(url: str, timeout: float = 5.0) -> dict:
    """Build the extra_features dict `score_url` expects.

    Returns an empty dict when the age is unknown, so the caller's merged
    feature dict behaves exactly like an offline scan -- the weighted sum in
    model.py skips any key that's simply absent, contributing zero risk
    rather than guessing.
    """
    age_days = lookup_domain_age_days(url, timeout=timeout)
    if age_days is None:
        return {}
    return {
        "domain_newer_than_30d": int(age_days < _NEW_DOMAIN_DAYS),
        "domain_newer_than_90d": int(age_days < _RECENT_DOMAIN_DAYS),
    }
