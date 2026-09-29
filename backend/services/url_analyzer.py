"""
Static URL Analysis Engine
Performs forensic static string analysis of URLs WITHOUT contacting or visiting the target.

CRITICAL DEFENSIVE CYBERSECURITY PRINCIPLE:
1. Never automatically visit or fetch suspicious URLs (prevents beaconing, exploit delivery, or IP leaks).
2. The presence of HTTPS (TLS/SSL) does NOT equal website trustworthiness.
   Over 80% of modern phishing websites utilize free automated TLS certificates (e.g., Let's Encrypt)
   to display the padlock icon and mislead victims.
"""

import re
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "cutt.ly", "rb.gy", "tiny.cc"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security", 
    "account", "banking", "update", "confirm", "wallet", "recover",
    "password", "auth", "token", "service-desk", "portal", "claim", "pay-now"
]


def analyze_single_url(url_string: str) -> Dict[str, Any]:
    """
    Performs static lexical analysis of a single URL string.
    Returns structured metrics, indicators, and risk score.
    """
    findings: List[Dict[str, Any]] = []
    risk_score = 0

    if not url_string or not url_string.strip():
        return {
            "url": "",
            "risk_score": 0,
            "findings": []
        }

    raw_url = url_string.strip()
    
    # Parse URL components
    try:
        parsed = urlparse(raw_url)
    except Exception:
        return {
            "url": raw_url,
            "risk_score": 75,
            "findings": [{"type": "INVALID_URL", "severity": "HIGH", "description": "URL failed syntactic parsing."}]
        }

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    # Extract hostname without port
    hostname = netloc.split(":")[0] if ":" in netloc else netloc

    # 1. Scheme Check
    if scheme == "http":
        risk_score += 15
        findings.append({
            "type": "UNENCRYPTED_HTTP",
            "severity": "MEDIUM",
            "description": "URL uses unencrypted HTTP scheme instead of HTTPS."
        })
    elif scheme == "https":
        findings.append({
            "type": "HTTPS_PRESENT",
            "severity": "INFORMATIONAL",
            "description": "URL utilizes HTTPS. Note: HTTPS encrypts transit but does NOT verify site legitimacy."
        })
    elif scheme not in ["http", "https"]:
        risk_score += 30
        findings.append({
            "type": "ANOMALOUS_SCHEME",
            "severity": "HIGH",
            "description": f"URL uses unusual scheme '{scheme}'."
        })

    # 2. Raw IP Address Hostname (e.g. http://198.51.100.10/login)
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    is_raw_ip = bool(re.match(ip_pattern, hostname))
    if is_raw_ip:
        risk_score += 40
        findings.append({
            "type": "RAW_IP_HOSTNAME",
            "severity": "CRITICAL",
            "description": f"Host is a raw numerical IP address ({hostname}), commonly used to bypass domain reputation checks."
        })

    # 3. Known URL Shorteners (Hiding Destination)
    if hostname in SHORTENER_DOMAINS:
        risk_score += 25
        findings.append({
            "type": "URL_SHORTENER",
            "severity": "MEDIUM",
            "description": f"Uses URL shortening service ({hostname}) which obscures the final destination."
        })

    # 4. Excessive Subdomains (Domain obscuration)
    subdomains = hostname.split(".")
    subdomain_count = max(0, len(subdomains) - 2)
    if subdomain_count >= 3:
        risk_score += 20
        findings.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "description": f"Hostname contains {subdomain_count} subdomains ({hostname}), characteristic of phishing redirection."
        })

    # 5. Phishing / Credential Keywords in Path or Hostname
    matched_keywords = []
    full_url_lower = raw_url.lower()
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in full_url_lower:
            matched_keywords.append(kw)

    if matched_keywords:
        kw_penalty = min(len(matched_keywords) * 10, 30)
        risk_score += kw_penalty
        findings.append({
            "type": "SUSPICIOUS_URL_KEYWORDS",
            "severity": "HIGH" if kw_penalty >= 20 else "MEDIUM",
            "description": f"URL contains authentication/action keywords: {', '.join(matched_keywords[:4])}."
        })

    # 6. Deceptive Hostname Structure (Hyphenated brand imitation)
    if "-" in hostname and any(brand in hostname for brand in ["paypal", "microsoft", "google", "apple", "login", "bank"]):
        risk_score += 25
        findings.append({
            "type": "DECEPTIVE_HOSTNAME_HYPHENS",
            "severity": "HIGH",
            "description": f"Hostname uses hyphens alongside brand/security words to mimic legitimate services."
        })

    # 7. Non-standard Port Usage
    if ":" in netloc:
        port = netloc.split(":")[1]
        if port not in ["80", "443", ""]:
            risk_score += 20
            findings.append({
                "type": "NON_STANDARD_PORT",
                "severity": "MEDIUM",
                "description": f"URL directs to non-standard network port :{port}."
            })

    # 8. Excessive URL Length
    if len(raw_url) > 120:
        risk_score += 15
        findings.append({
            "type": "LONG_URL",
            "severity": "LOW",
            "description": f"URL is unusually long ({len(raw_url)} chars), which may be used to hide malicious tokens."
        })

    capped_score = min(max(risk_score, 0), 100)

    return {
        "url": raw_url,
        "scheme": scheme,
        "hostname": hostname,
        "is_raw_ip": is_raw_ip,
        "subdomain_count": subdomain_count,
        "length": len(raw_url),
        "risk_score": capped_score,
        "findings": findings
    }


def analyze_urls(url_list: List[str]) -> Dict[str, Any]:
    """
    Analyzes a list of extracted URLs and aggregates risk signals.
    """
    if not url_list:
        return {
            "total_urls": 0,
            "has_suspicious_urls": False,
            "max_url_risk_score": 0,
            "aggregated_risk_score": 0,
            "url_details": []
        }

    url_details = [analyze_single_url(u) for u in url_list]
    max_score = max((item["risk_score"] for item in url_details), default=0)
    has_suspicious = any(item["risk_score"] >= 40 for item in url_details)

    # Weighted aggregate: highest score + modest boost for multiple risky URLs
    high_risk_count = sum(1 for item in url_details if item["risk_score"] >= 40)
    aggregated = max_score + min(high_risk_count * 5, 15)
    aggregated = min(aggregated, 100)

    return {
        "total_urls": len(url_list),
        "has_suspicious_urls": has_suspicious,
        "max_url_risk_score": max_score,
        "aggregated_risk_score": aggregated,
        "url_details": url_details
    }
