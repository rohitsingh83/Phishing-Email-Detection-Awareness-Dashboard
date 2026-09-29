"""
Rule-Based Phishing Risk Scoring & Explainability Engine
Combines multi-vector forensic indicators into an explainable 0-100 threat score,
maps classifications, and generates contextual security recommendations.

SECURITY DESIGN NOTE:
Automated scores assist security teams and end-users; they do not claim absolute certainty.
Thresholds are calibrated baseline assumptions subject to enterprise tuning.
"""

from typing import Dict, List, Any


def calculate_phishing_score(analysis_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a weighted risk score (0-100) based on forensic indicators.
    Generates explainable findings ('WHY?') and recommended defensive actions.
    """
    features = analysis_bundle["features"]
    sender_analysis = analysis_bundle["sender_analysis"]
    content_analysis = analysis_bundle["content_analysis"]
    url_analysis = analysis_bundle["url_analysis"]
    attachment_analysis = analysis_bundle["attachment_analysis"]

    score = 0
    score_breakdown: List[Dict[str, Any]] = []
    indicators_found: List[Dict[str, Any]] = []

    # 1. Suspicious Sender (+15 max)
    sender_score = sender_analysis.get("sender_risk_score", 0)
    if sender_score >= 30:
        pts = round((sender_score / 100) * 20)
        score += pts
        score_breakdown.append({"factor": "Sender Domain / Impersonation Risk", "points": pts})
        for f in sender_analysis.get("findings", []):
            if f.get("severity") in ["HIGH", "CRITICAL"]:
                indicators_found.append({
                    "category": "Sender",
                    "severity": f.get("severity"),
                    "title": "Suspicious Sender Identity",
                    "description": f.get("description")
                })

    # 2. Urgency & Time Pressure (+10 max)
    if features.get("urgent_keyword_count", 0) > 0:
        pts = 10
        score += pts
        score_breakdown.append({"factor": "Urgent Time-Pressure Language", "points": pts})
        snippets = content_analysis.get("matched_snippets", {}).get("urgency", [])
        indicators_found.append({
            "category": "Content",
            "severity": "MEDIUM",
            "title": "Artificial Urgency Detected",
            "description": f"Email pressures recipient with urgent language: {', '.join(snippets[:3])}."
        })

    # 3. Credential Harvesting (+20 max)
    if features.get("contains_password_request", 0) == 1:
        pts = 20
        score += pts
        score_breakdown.append({"factor": "Credential Verification Request", "points": pts})
        snippets = content_analysis.get("matched_snippets", {}).get("credential_harvesting", [])
        indicators_found.append({
            "category": "Content",
            "severity": "CRITICAL",
            "title": "Credential Harvest Request",
            "description": f"Requests user to confirm passwords, 2FA codes, or credentials: {', '.join(snippets[:3])}."
        })

    # 4. Threat / Fear Language (+10 max)
    if features.get("threat_keyword_count", 0) > 0:
        pts = 10
        score += pts
        score_breakdown.append({"factor": "Fear / Coercion Language", "points": pts})
        snippets = content_analysis.get("matched_snippets", {}).get("fear_threats", [])
        indicators_found.append({
            "category": "Content",
            "severity": "HIGH",
            "title": "Threat & Coercion Tactics",
            "description": f"Uses punitive threats (suspension, legal action): {', '.join(snippets[:3])}."
        })

    # 5. Financial Pressure (+10 max)
    if features.get("financial_keyword_count", 0) > 0:
        pts = 10
        score += pts
        score_breakdown.append({"factor": "Financial / Payment Demand", "points": pts})
        snippets = content_analysis.get("matched_snippets", {}).get("financial_pressure", [])
        indicators_found.append({
            "category": "Content",
            "severity": "MEDIUM",
            "title": "Financial Pressure / Gift Cards",
            "description": f"Mentions urgent wire transfers, gift cards, or overdue invoices: {', '.join(snippets[:3])}."
        })

    # 6. Sensitive Personal Info Request (+15 max)
    if features.get("contains_personal_info_request", 0) == 1:
        pts = 15
        score += pts
        score_breakdown.append({"factor": "Personal Information Harvesting", "points": pts})
        snippets = content_analysis.get("matched_snippets", {}).get("personal_info_harvest", [])
        indicators_found.append({
            "category": "Content",
            "severity": "HIGH",
            "title": "PII Harvesting Attempt",
            "description": f"Solicits sensitive personal identity data (SSN, DOB, Banking details): {', '.join(snippets[:3])}."
        })

    # 7. Suspicious URL Analysis (+20 max)
    url_risk = url_analysis.get("aggregated_risk_score", 0)
    if url_risk >= 30:
        pts = round((url_risk / 100) * 20)
        score += pts
        score_breakdown.append({"factor": "Suspicious URL Structure", "points": pts})
        if features.get("has_ip_url", 0) == 1:
            indicators_found.append({
                "category": "URL",
                "severity": "CRITICAL",
                "title": "Raw IP Address in URL",
                "description": "URL links directly to a numerical IP address instead of an authenticated domain."
            })
        for u in url_analysis.get("url_details", []):
            for f in u.get("findings", []):
                if f.get("severity") in ["HIGH", "CRITICAL"]:
                    indicators_found.append({
                        "category": "URL",
                        "severity": f.get("severity"),
                        "title": f.get("type", "Suspicious URL Pattern"),
                        "description": f"{u.get('url')}: {f.get('description')}"
                    })

    # 8. Suspicious Attachment (+25 max)
    att_risk = attachment_analysis.get("risk_score", 0)
    if att_risk >= 30:
        pts = round((att_risk / 100) * 25)
        score += pts
        score_breakdown.append({"factor": "High-Risk Attachment", "points": pts})
        for f in attachment_analysis.get("findings", []):
            indicators_found.append({
                "category": "Attachment",
                "severity": f.get("severity"),
                "title": f.get("type", "Dangerous Attachment"),
                "description": f"{attachment_analysis.get('filename')}: {f.get('description')}"
            })

    # 9. Generic Greeting (+5 max)
    if features.get("generic_greeting", 0) == 1:
        pts = 5
        score += pts
        score_breakdown.append({"factor": "Generic / Impersonal Salutation", "points": pts})
        indicators_found.append({
            "category": "Content",
            "severity": "LOW",
            "title": "Generic Greeting",
            "description": "Uses depersonalized salutation ('Dear Customer'), common in mass phishing campaigns."
        })

    # 10. Shouting / Excessive Punctuation (+5 max)
    if features.get("uppercase_ratio", 0) > 0.30 or features.get("exclamation_count", 0) >= 3:
        pts = 5
        score += pts
        score_breakdown.append({"factor": "Stylistic Shouting / Punctuation", "points": pts})

    # Final Capped Score
    final_score = min(max(score, 0), 100)

    # Classification Mapping
    if final_score <= 20:
        classification = "SAFE / LOW RISK"
        risk_level = "LOW"
    elif final_score <= 40:
        classification = "MODERATE RISK"
        risk_level = "MODERATE"
    elif final_score <= 70:
        classification = "SUSPICIOUS"
        risk_level = "SUSPICIOUS"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"
        risk_level = "HIGH"

    # Contextual Security Recommendations
    recommendations: List[str] = []
    if final_score >= 41:
        recommendations.append("Do NOT click any hyperlinks contained within this email.")
        if attachment_analysis.get("has_attachment"):
            recommendations.append(f"Do NOT download or open the attachment '{attachment_analysis.get('filename')}'.")
        recommendations.append("Verify the sender via an independent, trusted channel (official internal directory or phone).")
        recommendations.append("Report this message immediately to your organization's Security Operations Center (SOC).")
        recommendations.append("Never enter credentials or personal data on pages reached via unexpected email links.")
    elif final_score >= 21:
        recommendations.append("Exercise caution before clicking links or downloading attachments.")
        recommendations.append("Inspect the actual destination URL by hovering over links without clicking.")
        recommendations.append("Verify unfamiliar requests with your internal team lead or IT service desk.")
    else:
        recommendations.append("This message displays normal characteristics. Standard organizational caution still applies.")
        recommendations.append("Always verify unexpected payment or bank account change requests out-of-band.")

    return {
        "risk_score": final_score,
        "classification": classification,
        "risk_level": risk_level,
        "score_breakdown": score_breakdown,
        "indicators": indicators_found,
        "recommendations": recommendations,
        "calibration_note": "Rule thresholds are project baselines and should be continuously calibrated against enterprise telemetry."
    }
