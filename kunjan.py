import math
import re
from urllib.parse import urlparse


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon Entropy of a string to detect algorithmic randomness."""
    if not text:
        return 0.0
    frequencies = {char: text.count(char) for char in set(text)}
    entropy = 0.0
    for count in frequencies.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def analyze_url(url: str):
    """Parses a URL, extracts metadata features, and computes a safety score."""
    # Clean up input strings
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc
    except Exception:
        return {"status": "Error", "message": "Invalid URL string format."}

    # 1. Feature Extraction Engineering
    features = {
        "length": len(url),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "has_at_symbol": 1 if "@" in url else 0,
        "is_ip_address": (
            1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
        ),
        "entropy": calculate_entropy(domain),
    }

    # 2. Heuristic Classification Weights
    risk_score = 0
    reasons = []

    if features["length"] > 75:
        risk_score += 2
        reasons.append("Abnormally long URL string structure.")
    if features["dot_count"] >= 4:
        risk_score += 2
        reasons.append("Excessive subdomains detected.")
    if features["hyphen_count"] > 2:
        risk_score += 1
        reasons.append("High number of hyphens found in domain.")
    if features["has_at_symbol"]:
        risk_score += 3
        reasons.append("Use of '@' token overrides standard browser routing.")
    if features["is_ip_address"]:
        risk_score += 4
        reasons.append("Domain is a raw numerical IP address instead of text.")
    if features["entropy"] > 4.2:
        risk_score += 2
        reasons.append("High domain randomness indicates a computer-generated botnet link.")

    # 3. Final Classification Assignment
    if risk_score <= 1:
        classification = "Safe"
    elif risk_score <= 3:
        classification = "Suspicious"
    else:
        classification = "Phishing Link Flagged"

    return {
        "url": url,
        "classification": classification,
        "risk_score": risk_score,
        "extracted_features": features,
        "warnings": reasons,
    }


# Quick console testing execution
if __name__ == "__main__":
    print("--- Phishing URL Detector Initialized ---")
    test_link = "http://paypal-security-update-login-verification.free-webspace.net/secure/@login"
    result = analyze_url(test_link)

    print(f"\nAnalyzed Link: {result['url']}")
    print(f"Classification: **{result['classification']}** (Score: {result['risk_score']}/14)")
    print("\nTriggered Risk Indicators:")
    for warning in result["warnings"]:
        print(f" - {warning}")