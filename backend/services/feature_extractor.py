"""
Phishing Email Feature Extraction Engine
Extracts forensic, lexical, psychological, and network indicator features
from an email into a structured feature vector for both Rule-Based and Machine Learning analysis.
"""

from typing import Dict, Any, List
from backend.utils.preprocessor import extract_urls, extract_domain
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_urls
from backend.services.attachment_analyzer import analyze_attachment


def extract_email_features(
    sender: str,
    subject: str,
    body: str,
    urls: str = "",
    attachment_name: str = ""
) -> Dict[str, Any]:
    """
    Extracts comprehensive feature dictionary for an email.
    
    Feature Dictionary Explanation:
    - urgent_keyword_count: Frequency of time-coercion phrases (e.g. 'immediately', 'act now').
    - credential_keyword_count: Frequency of login/password harvesting terms.
    - financial_keyword_count: Frequency of payment, invoice, wire, or cryptocurrency references.
    - threat_keyword_count: Frequency of punitive actions (suspension, legal, locked out).
    - url_count: Total count of hyperlinked web addresses extracted.
    - suspicious_url_count: Number of URLs with elevated heuristic risk scores (>= 40).
    - has_ip_url: Binary flag (1/0) indicating URL uses raw numerical IP instead of domain.
    - has_shortened_url_pattern: Binary flag (1/0) indicating use of URL shortener (e.g. bit.ly).
    - sender_domain_length: Character length of the sending domain.
    - subdomain_count: Number of subdomains in sender address.
    - suspicious_attachment: Binary flag (1/0) indicating executable or double extension.
    - generic_greeting: Binary flag (1/0) indicating depersonalized salutation ('Dear Customer').
    - contains_password_request: Binary flag (1/0) specifically checking password confirmation prompts.
    - contains_personal_info_request: Binary flag (1/0) detecting requests for SSN, DOB, or card details.
    - exclamation_count: Total exclamation points in text (indicator of shouting).
    - uppercase_ratio: Proportion of uppercase alphabetic letters across subject and body.
    - body_length: Character count of email body.
    - subject_length: Character count of subject line.
    """
    # 1. Parse URLs from explicit string or extract from body text
    url_list = []
    if urls:
        url_list.extend([u.strip() for u in urls.split() if u.strip()])
    extracted_from_body = extract_urls(body or "")
    for u in extracted_from_body:
        if u not in url_list:
            url_list.append(u)

    # 2. Run Individual Analyzers
    sender_analysis = analyze_sender(sender or "", body or "")
    content_analysis = analyze_email_content(subject or "", body or "")
    url_analysis = analyze_urls(url_list)
    attachment_analysis = analyze_attachment(attachment_name or "")

    # 3. Compute Granular Counts and Flags
    cat_scores = content_analysis.get("category_scores", {})
    snippets = content_analysis.get("matched_snippets", {})
    stats = content_analysis.get("stats", {})

    urgent_kw_count = len(snippets.get("urgency", []))
    cred_kw_count = len(snippets.get("credential_harvesting", []))
    fin_kw_count = len(snippets.get("financial_pressure", []))
    threat_kw_count = len(snippets.get("fear_threats", []))

    suspicious_url_count = sum(1 for u in url_analysis["url_details"] if u.get("risk_score", 0) >= 40)
    has_ip_url = 1 if any(u.get("is_raw_ip", False) for u in url_analysis["url_details"]) else 0
    has_shortener = 1 if any(u.get("hostname", "") in ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"] for u in url_analysis["url_details"]) else 0

    sender_domain = sender_analysis.get("domain", "")
    subdomain_count = sender_analysis.get("subdomain_count", 0)
    suspicious_att = 1 if attachment_analysis.get("risk_score", 0) >= 35 else 0

    generic_greeting = 1 if "generic_greeting" in content_analysis.get("detected_categories", []) else 0
    contains_pw_req = 1 if "credential_harvesting" in content_analysis.get("detected_categories", []) else 0
    contains_pii_req = 1 if "personal_info_harvest" in content_analysis.get("detected_categories", []) else 0

    features = {
        "urgent_keyword_count": urgent_kw_count,
        "credential_keyword_count": cred_kw_count,
        "financial_keyword_count": fin_kw_count,
        "threat_keyword_count": threat_kw_count,
        "url_count": len(url_list),
        "suspicious_url_count": suspicious_url_count,
        "has_ip_url": has_ip_url,
        "has_shortened_url_pattern": has_shortener,
        "sender_domain_length": len(sender_domain),
        "subdomain_count": subdomain_count,
        "suspicious_attachment": suspicious_att,
        "generic_greeting": generic_greeting,
        "contains_password_request": contains_pw_req,
        "contains_personal_info_request": contains_pii_req,
        "exclamation_count": stats.get("exclamation_count", 0),
        "uppercase_ratio": stats.get("uppercase_ratio", 0.0),
        "body_length": stats.get("char_count", 0),
        "subject_length": len(subject or "")
    }

    return {
        "features": features,
        "sender_analysis": sender_analysis,
        "content_analysis": content_analysis,
        "url_analysis": url_analysis,
        "attachment_analysis": attachment_analysis
    }
