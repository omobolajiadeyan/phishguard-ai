"""Parse trusted Authentication-Results values into explainable signals."""

import re


AUTH_METHODS = ("spf", "dkim", "dmarc")
AUTH_RESULTS = {"pass", "fail", "softfail", "neutral", "none"}
_RESULT_PATTERN = re.compile(
    r"(?:^|[;\s])(?P<method>spf|dkim|dmarc)\s*=\s*"
    r"(?P<result>[a-z][a-z0-9_-]*)",
    re.IGNORECASE,
)


def parse_authentication_results(value: str | None) -> dict[str, str]:
    """Return normalized SPF, DKIM, and DMARC results from one header value."""
    results = {method: "unknown" for method in AUTH_METHODS}
    if not value:
        return results

    for match in _RESULT_PATTERN.finditer(value):
        method = match.group("method").lower()
        result = match.group("result").lower()
        if results[method] == "unknown" and result in AUTH_RESULTS:
            results[method] = result

    return results


def extract_authentication_features(value: str | None) -> dict[str, str | float]:
    """Return categorical authentication results and conservative risk values."""
    results = parse_authentication_results(value)
    spf_risk = {"fail": 1.0, "softfail": 0.5}.get(results["spf"], 0.0)

    return {
        "spf_result": results["spf"],
        "dkim_result": results["dkim"],
        "dmarc_result": results["dmarc"],
        "spf_auth_risk": spf_risk,
        "dkim_auth_risk": float(results["dkim"] == "fail"),
        "dmarc_auth_risk": float(results["dmarc"] == "fail"),
    }
