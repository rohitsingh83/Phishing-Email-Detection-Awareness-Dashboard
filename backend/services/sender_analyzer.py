"""
Sender Analysis Engine
Performs forensic inspection of email sender identity, domain characteristics,
display-name mismatch, and typosquatting/lookalike indicators.
"""

import re
from typing import Dict, List, Any
from backend.utils.preprocessor import extract_domain, extract_display_name

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "country", "gq", "work", "top", "xyz", "stream", 
    "download", "racing", "loan", "men", "tk", "ml", "ga", "cf"
}

BRAND_LOOKALIKES = {
    "paypal": ["paypa1", "pay-pal", "paypall", "paypal-security", "paypal-update"],
    "microsoft": ["micr0soft", "rnicrosoft", "micosoft", "ms-security", "office365-verify"],
    "google": ["g00gle", "goog1e", "google-security", "gmail-support"],
    "apple": ["app1e", "apple-id-verify", "apple-support-desk"],
    "amazon": ["amaz0n", "arnazon", "amazon-billing", "prime-renewal"],
    "netflix": ["netf1ix", "netflix-update", "netflix-verify"],
    "bank": ["secure-banking", "verify-bank", "online-banking-auth", "bank-login"]
}


def analyze_sender(sender_raw: str, email_body: str = "") -> Dict[str, Any]:
    """
    Analyzes sender email string and checks for common phishing/spoofing signals.
    Returns sender_risk_score (0-100) and forensic findings.
    """
    findings: List[Dict[str, Any]] = []
    risk_score = 0

    if not sender_raw or not sender_raw.strip():
        findings.append({
            "type": "MISSING_SENDER",
            "severity": "HIGH",
            "description": "Email sender information is missing or completely blank."
        })
        return {
            "sender_raw": "",
            "domain": "",
            "display_name": "",
            "subdomain_count": 0,
            "sender_risk_score": 50,
            "findings": findings
        }

    display_name = extract_display_name(sender_raw)
    domain = extract_domain(sender_raw)

    # 1. Email Format Validation
    # Basic email syntax check on extracted domain
    if not domain or "." not in domain:
        risk_score += 40
        findings.append({
            "type": "MALFORMED_SENDER",
            "severity": "HIGH",
            "description": f"Sender '{sender_raw}' does not have a standard valid domain structure."
        })

    # 2. Excessive Subdomains (e.g. login.verify.support.example.com)
    domain_parts = domain.split(".")
    subdomain_count = max(0, len(domain_parts) - 2)
    if subdomain_count >= 3:
        risk_score += 25
        findings.append({
            "type": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "description": f"Domain contains {subdomain_count} subdomains ({domain}), often used to obscure actual host."
        })

    # 3. Suspicious or High-Abuse TLDs
    tld = domain_parts[-1].lower() if domain_parts else ""
    if tld in SUSPICIOUS_TLDS:
        risk_score += 20
        findings.append({
            "type": "HIGH_ABUSE_TLD",
            "severity": "MEDIUM",
            "description": f"Sender domain uses top-level domain '.{tld}', which has high historical correlation with abuse."
        })

    # 4. Display-Name Spoofing / Impersonation Mismatch
    # If display name says "Google Support" or "Bank of America", but domain is personal or generic
    if display_name:
        for brand, variations in BRAND_LOOKALIKES.items():
            if brand.lower() in display_name.lower():
                if brand.lower() not in domain.lower():
                    risk_score += 35
                    findings.append({
                        "type": "DISPLAY_NAME_SPOOFING",
                        "severity": "HIGH",
                        "description": f"Display name refers to '{display_name}' but the sending domain is '{domain}'."
                    })
                    break

    # 5. Domain Lookalike / Typosquatting heuristics
    clean_domain = domain.lower()
    for brand, lookalikes in BRAND_LOOKALIKES.items():
        for lookalike in lookalikes:
            if lookalike in clean_domain:
                risk_score += 35
                findings.append({
                    "type": "LOOKALIKE_DOMAIN",
                    "severity": "HIGH",
                    "description": f"Domain '{domain}' matches known brand typosquatting / lookalike pattern targeting '{brand}'."
                })
                break

    # 6. Numbers in Domain Name mimicking words (leetspeak, e.g. acc0unt, sec123)
    if re.search(r'[a-z]+[0-9]{3,}[a-z]*\.', domain):
        risk_score += 15
        findings.append({
            "type": "NUMERIC_SUBSTITUTION",
            "severity": "LOW",
            "description": f"Sender domain contains unusual numeric sequences embedded in words: '{domain}'."
        })

    # 7. Reserved Test Domain Notice
    if domain.endswith(".invalid.test") or domain.endswith(".test"):
        findings.append({
            "type": "TEST_DOMAIN",
            "severity": "INFORMATIONAL",
            "description": f"Domain '{domain}' uses RFC 2606 reserved test TLD for safe lab demonstration."
        })

    # Cap score between 0 and 100
    sender_risk_score = min(max(risk_score, 0), 100)

    return {
        "sender_raw": sender_raw,
        "domain": domain,
        "display_name": display_name,
        "subdomain_count": subdomain_count,
        "sender_risk_score": sender_risk_score,
        "findings": findings
    }
