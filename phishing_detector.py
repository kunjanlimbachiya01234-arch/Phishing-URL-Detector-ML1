"""
PhishGuard heuristic phishing URL detector — standalone Python port.

This is a faithful port of the TypeScript detector used in the PhishGuard
web app (artifacts/api-server/src/lib/phishing-detector.ts). No third-party
phishing API is used; all detection is local heuristic logic.

Usage:
    python phishing_detector.py "http://paypal-secure-verify-account.tk/login"

Or import it:
    from phishing_detector import analyze_url
    result = analyze_url("https://github.com")
    print(result["verdict"], result["risk_score"])
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from typing import Literal

Severity = Literal["low", "medium", "high"]
Verdict = Literal["safe", "suspicious", "phishing"]

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "tk", "ml", "ga", "cf", "top", "xyz",
    "click", "loan", "download", "men", "win", "bid", "stream", "icu",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "tiny.cc",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "instagram",
    "linkedin", "outlook", "office365", "coinbase", "binance", "irs",
    "usps", "fedex", "dhl", "ebay", "walmart",
]

URGENCY_KEYWORDS = [
    "verify", "suspend", "urgent", "confirm", "secure", "update",
    "locked", "expire", "billing", "signin", "login", "account",
    "reset", "unusual", "alert", "immediately",
]

_SEVERITY_WEIGHT = {"high": 30, "medium": 15, "low": 7}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


@dataclass
class Signal:
    id: str
    label: str
    severity: Severity
    detail: str


@dataclass
class AnalysisResult:
    normalized_url: str
    domain: str
    verdict: Verdict
    risk_score: int
    signals: list[Signal] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "normalizedUrl": self.normalized_url,
            "domain": self.domain,
            "verdict": self.verdict,
            "riskScore": self.risk_score,
            "signals": [s.__dict__ for s in self.signals],
        }


def _add_signal(
    signals: list[Signal],
    score: int,
    id_: str,
    label: str,
    severity: Severity,
    detail: str,
) -> int:
    signals.append(Signal(id=id_, label=label, severity=severity, detail=detail))
    return score + _SEVERITY_WEIGHT[severity]


def analyze_url(raw_url: str) -> AnalysisResult:
    """Analyze a URL and return a risk verdict, score, and detected signals."""
    input_url = raw_url.strip()
    if not _SCHEME_RE.match(input_url):
        input_url = f"http://{input_url}"

    parsed = urlsplit(input_url)
    if not parsed.hostname:
        raise ValueError("The provided value is not a valid URL")

    hostname = parsed.hostname.lower()
    scheme = parsed.scheme.lower()
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    port_suffix = f":{parsed.port}" if parsed.port else ""
    full_url = f"{scheme}://{hostname}{port_suffix}{path}"
    if parsed.fragment:
        full_url += f"#{parsed.fragment}"

    signals: list[Signal] = []
    score = 0

    is_ip_host = bool(_IP_RE.match(hostname)) or ":" in hostname
    if is_ip_host:
        score = _add_signal(
            signals, score, "ip-host", "IP address used as host", "high",
            "Legitimate sites almost never use a raw IP address instead of a domain name.",
        )

    if scheme != "https":
        score = _add_signal(
            signals, score, "no-https", "Not using HTTPS", "medium",
            "The link does not use a secure connection, which is common in phishing pages.",
        )

    labels = hostname.split(".")
    subdomain_count = max(0, len(labels) - 2)
    if subdomain_count >= 3:
        score = _add_signal(
            signals, score, "excess-subdomains", "Excessive subdomains", "medium",
            f"The domain has {subdomain_count} subdomains, a common trick to disguise the real host.",
        )

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        score = _add_signal(
            signals, score, "suspicious-tld", "Uncommon top-level domain", "medium",
            f'The ".{tld}" domain extension is frequently abused for disposable phishing sites.',
        )

    if hostname in URL_SHORTENERS:
        score = _add_signal(
            signals, score, "url-shortener", "URL shortener detected", "medium",
            "Shortened links hide the real destination until you click them.",
        )

    if "xn--" in hostname:
        score = _add_signal(
            signals, score, "punycode", "Punycode / internationalized domain", "high",
            "The domain uses punycode encoding, a technique used to spoof lookalike characters in brand names.",
        )

    if hostname.count("-") >= 3:
        score = _add_signal(
            signals, score, "many-hyphens", "Domain has many hyphens", "low",
            "A domain with several hyphens can be an attempt to mimic a trusted brand name.",
        )

    registrable_domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname
    matched_brand = next((b for b in BRAND_KEYWORDS if b in hostname), None)
    if matched_brand and not registrable_domain.startswith(f"{matched_brand}."):
        score = _add_signal(
            signals, score, "brand-lookalike", "Brand name in a non-official domain", "high",
            f'The name "{matched_brand}" appears in the domain, but the domain does not belong '
            "to that brand's official site.",
        )

    lower_full_url = full_url.lower()
    urgency_hits = [w for w in URGENCY_KEYWORDS if w in lower_full_url]
    if len(urgency_hits) >= 2:
        score = _add_signal(
            signals, score, "urgency-language", "Urgency or account-scare language", "medium",
            f"The link contains pressure-oriented terms ({', '.join(urgency_hits[:3])}) "
            "often used to rush victims.",
        )

    if "@" in hostname or "@" in full_url:
        score = _add_signal(
            signals, score, "at-symbol", "'@' symbol in URL", "high",
            "URLs containing '@' can redirect to a different host than the one visibly displayed.",
        )

    if len(path) > 100:
        score = _add_signal(
            signals, score, "long-path", "Unusually long path or query string", "low",
            "A very long path can be used to obscure the true intent of the link or encode tracking payloads.",
        )

    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count >= 4:
        score = _add_signal(
            signals, score, "many-digits", "Domain contains many digits", "low",
            "A high density of digits in a domain name is unusual for legitimate brands.",
        )

    if not signals:
        signals.append(Signal(
            id="no-signals",
            label="No red flags detected",
            severity="low",
            detail="The URL structure does not match common phishing patterns we check for.",
        ))

    risk_score = max(0, min(100, score))
    verdict: Verdict = "phishing" if risk_score >= 60 else "suspicious" if risk_score >= 25 else "safe"

    return AnalysisResult(
        normalized_url=full_url,
        domain=hostname,
        verdict=verdict,
        risk_score=risk_score,
        signals=signals,
    )


def _main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python phishing_detector.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    try:
        result = analyze_url(url)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print(f"URL:      {result.normalized_url}")
    print(f"Domain:   {result.domain}")
    print(f"Verdict:  {result.verdict.upper()}")
    print(f"Risk:     {result.risk_score}/100")
    print("Signals:")
    for s in result.signals:
        print(f"  - [{s.severity.upper():6}] {s.label}: {s.detail}")


if __name__ == "__main__":
    _main()
