"""
Hybrid Phishing Detection Engine
Fuses Rule-Based Expert Heuristics with Machine Learning Statistical Modeling.

DEFENSIVE ARCHITECTURE:
- Rule-based heuristics guarantee zero-day explainability for known IOCs (raw IPs, double extensions, spoofed headers).
- Machine learning captures subtle contextual language nuances and semantic variations.
- Combining both produces a calibrated hybrid threat score while preventing probability from being mistaken for certainty.
"""

from typing import Dict, Any
from backend.services.feature_extractor import extract_email_features
from backend.services.risk_engine import calculate_phishing_score
from ml.predict import predict_email_ml


def run_hybrid_analysis(
    sender: str,
    subject: str,
    body: str,
    urls: str = "",
    attachment_name: str = "",
    rule_weight: float = 0.55,
    ml_weight: float = 0.45
) -> Dict[str, Any]:
    """
    Performs end-to-end hybrid analysis of an email.
    """
    # 1. Feature Extraction & Rule-based Assessment
    bundle = extract_email_features(sender, subject, body, urls, attachment_name)
    rule_result = calculate_phishing_score(bundle)

    # 2. Machine Learning Inference
    full_text = f"{sender} {subject} {body} {urls} {attachment_name}"
    ml_result = predict_email_ml(full_text)

    # 3. Hybrid Score Fusion
    rule_score = rule_result["risk_score"]
    ml_score = ml_result["ml_risk_score"]

    # Hybrid Weighted Combination
    hybrid_score = int(round((rule_score * rule_weight) + (ml_score * ml_weight)))
    hybrid_score = min(max(hybrid_score, 0), 100)

    # Hybrid Classification
    if hybrid_score <= 20:
        classification = "SAFE / LOW RISK"
        risk_level = "LOW"
    elif hybrid_score <= 40:
        classification = "MODERATE RISK"
        risk_level = "MODERATE"
    elif hybrid_score <= 70:
        classification = "SUSPICIOUS"
        risk_level = "SUSPICIOUS"
    else:
        classification = "HIGH RISK / LIKELY PHISHING"
        risk_level = "HIGH"

    return {
        "hybrid_risk_score": hybrid_score,
        "classification": classification,
        "risk_level": risk_level,
        "rule_engine": {
            "score": rule_score,
            "classification": rule_result["classification"],
            "score_breakdown": rule_result["score_breakdown"],
            "calibration_note": rule_result["calibration_note"]
        },
        "machine_learning": {
            "ml_probability": ml_result["ml_probability"],
            "ml_score": ml_score,
            "ml_label": ml_result["ml_label"],
            "confidence_percent": ml_result["confidence_percent"],
            "matched_phishing_tokens": ml_result["matched_phishing_tokens"]
        },
        "indicators": rule_result["indicators"],
        "recommendations": rule_result["recommendations"],
        "sender_analysis": bundle["sender_analysis"],
        "url_analysis": bundle["url_analysis"],
        "attachment_analysis": bundle["attachment_analysis"],
        "features": bundle["features"]
    }
