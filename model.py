"""
Lightweight phishing classifier using a hand-tuned decision tree.
No external ML libraries needed — pure Python implementation.

Design: each feature has a reviewable, hand-tuned heuristic weight. The
weights are not the output of a trained statistical model.
"""

from features import extract_url_features, extract_email_features


# Explainable heuristic weights for common phishing indicators.
# Positive weight = increases phishing probability.
URL_WEIGHTS = {
    "url_length":         0.015,   # longer URLs are more suspicious
    "subdomain_count":    0.18,    # subdomains used to fake legitimacy
    "has_ip_address":     0.90,    # IP in URL = very suspicious
    "special_char_count": 0.06,    # many special chars = obfuscation
    "has_https":         -0.20,    # HTTPS slightly reduces suspicion
    "digit_ratio":        0.60,    # high digit ratio = suspicious
    "phishing_keywords":  0.25,    # each matching keyword adds weight
    "path_depth":         0.04,    # deep paths can hide payloads
    "suspicious_tld":     0.70,    # .xyz/.tk etc highly suspicious
    "domain_length":     -0.01,    # short domains slightly safer
    "url_entropy":        0.12,    # high entropy = randomly generated domain
    "has_port":           0.40,    # non-standard port = suspicious
    "has_punycode":       0.10,    # contextual IDNA signal, not malicious alone
    "has_unicode_hostname": 0.08,  # legitimate IDNs exist; keep weight modest
}

EMAIL_WEIGHTS = {
    "url_count":              0.10,
    "link_count":             0.12,
    "urgency_word_count":     0.22,
    "exclamation_count":      0.05,
    "all_caps_word_count":    0.08,
    "html_tag_count":         0.03,
    "has_attachment_mention": 0.30,
    "word_count":            -0.001,  # longer emails slightly less phishy
}

THRESHOLD = 0.55  # score above this = classified as phishing
URL_BIAS = -1.30
EMAIL_BIAS = -0.30


def score_url(url: str) -> tuple[float, dict]:
    """
    Score a URL for phishing likelihood.
    Returns (probability 0.0-1.0, feature breakdown).
    """
    features = extract_url_features(url)
    raw_score = URL_BIAS + sum(
        features[f] * URL_WEIGHTS[f]
        for f in URL_WEIGHTS
        if f in features
    )

    # Sigmoid normalisation to keep output between 0 and 1
    import math
    probability = 1 / (1 + math.exp(-raw_score * 2.5))
    return round(probability, 4), features


def score_email(subject: str, body: str) -> tuple[float, dict]:
    """
    Score an email for phishing likelihood.
    Returns (probability 0.0-1.0, feature breakdown).
    """
    features = extract_email_features(subject, body)
    raw_score = EMAIL_BIAS + sum(
        features[f] * EMAIL_WEIGHTS[f]
        for f in EMAIL_WEIGHTS
        if f in features
    )

    import math
    probability = 1 / (1 + math.exp(-raw_score * 2.5))
    return round(probability, 4), features


def classify(probability: float) -> str:
    if probability >= 0.75:
        return "PHISHING"
    elif probability >= THRESHOLD:
        return "SUSPICIOUS"
    else:
        return "SAFE"
