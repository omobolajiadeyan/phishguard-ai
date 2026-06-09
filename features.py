"""
Feature extraction for phishing URL and email detection.
Converts raw URLs and email text into numerical feature vectors.
"""

import re
import math
from urllib.parse import urlparse


# Suspicious keywords commonly found in phishing URLs
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "confirm", "account",
    "banking", "secure", "security", "alert", "suspended", "unusual",
    "password", "credential", "wallet", "paypal", "amazon", "apple",
    "microsoft", "google", "netflix", "bank", "support", "helpdesk",
    "access", "validate", "authorize", "recover", "unlock", "limited",
]

TRUSTED_TLDS = {".com", ".org", ".gov", ".edu", ".co.uk", ".net"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}


# ──────────────────────────────────────────────
# URL Features
# ──────────────────────────────────────────────

def url_length(url: str) -> int:
    return len(url)


def subdomain_count(url: str) -> int:
    try:
        hostname = urlparse(url).hostname or ""
        parts = hostname.split(".")
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def has_ip_address(url: str) -> int:
    ip_pattern = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    )
    return int(bool(ip_pattern.search(url)))


def special_char_count(url: str) -> int:
    return sum(url.count(c) for c in ["@", "-", "_", "~", "%", "=", "?", "&", "#"])


def has_https(url: str) -> int:
    return int(url.startswith("https://"))


def digit_ratio(url: str) -> float:
    if not url:
        return 0.0
    return sum(c.isdigit() for c in url) / len(url)


def phishing_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)


def path_depth(url: str) -> int:
    try:
        path = urlparse(url).path
        return len([p for p in path.split("/") if p])
    except Exception:
        return 0


def suspicious_tld(url: str) -> int:
    try:
        hostname = urlparse(url).hostname or ""
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return 1
        return 0
    except Exception:
        return 0


def domain_length(url: str) -> int:
    try:
        hostname = urlparse(url).hostname or ""
        parts = hostname.split(".")
        if len(parts) >= 2:
            return len(parts[-2])
        return len(hostname)
    except Exception:
        return 0


def entropy(text: str) -> float:
    """Shannon entropy — high entropy in a domain suggests random/generated string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def url_entropy(url: str) -> float:
    try:
        hostname = urlparse(url).hostname or ""
        return round(entropy(hostname), 4)
    except Exception:
        return 0.0


def has_port(url: str) -> int:
    try:
        return int(urlparse(url).port is not None)
    except Exception:
        return 0


def has_punycode(url: str) -> int:
    """Return 1 when a hostname contains an IDNA punycode label."""
    try:
        hostname = urlparse(url).hostname or ""
        return int(any(label.startswith("xn--") for label in hostname.split(".")))
    except Exception:
        return 0


def has_unicode_hostname(url: str) -> int:
    """Return 1 when a parsed hostname contains a non-ASCII code point."""
    try:
        hostname = urlparse(url).hostname or ""
        return int(any(ord(character) > 127 for character in hostname))
    except Exception:
        return 0


def extract_url_features(url: str) -> dict:
    """Extract all URL features and return as a named dict."""
    return {
        "url_length":            url_length(url),
        "subdomain_count":       subdomain_count(url),
        "has_ip_address":        has_ip_address(url),
        "special_char_count":    special_char_count(url),
        "has_https":             has_https(url),
        "digit_ratio":           digit_ratio(url),
        "phishing_keywords":     phishing_keyword_count(url),
        "path_depth":            path_depth(url),
        "suspicious_tld":        suspicious_tld(url),
        "domain_length":         domain_length(url),
        "url_entropy":           url_entropy(url),
        "has_port":              has_port(url),
        "has_punycode":          has_punycode(url),
        "has_unicode_hostname":  has_unicode_hostname(url),
    }


# ──────────────────────────────────────────────
# Email Features
# ──────────────────────────────────────────────

URGENCY_WORDS = [
    "urgent", "immediately", "action required", "account suspended",
    "verify now", "click here", "limited time", "expire", "unusual activity",
    "security alert", "confirm your", "update your", "validate",
]


def extract_email_features(subject: str, body: str) -> dict:
    """Extract features from an email subject + body."""
    text = (subject + " " + body).lower()
    words = text.split()

    url_count = len(re.findall(r"https?://\S+", text))
    link_count = len(re.findall(r"href=|click here|www\.", text, re.IGNORECASE))
    urgency_count = sum(1 for w in URGENCY_WORDS if w in text)
    exclamation_count = body.count("!")
    all_caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    html_tags = len(re.findall(r"<[a-zA-Z]+", body))
    has_attachment_mention = int(bool(re.search(r"attach|download|open.*file", text)))

    return {
        "url_count":              url_count,
        "link_count":             link_count,
        "urgency_word_count":     urgency_count,
        "exclamation_count":      exclamation_count,
        "all_caps_word_count":    all_caps_words,
        "html_tag_count":         html_tags,
        "has_attachment_mention": has_attachment_mention,
        "word_count":             len(words),
    }
