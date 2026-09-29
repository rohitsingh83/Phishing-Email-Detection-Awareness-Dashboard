"""
Email Content Analysis Engine
Detects social-engineering psychological triggers:
- Urgency
- Fear / Coercion / Threats
- Financial Pressure
- Credential Harvesting Requests
- Reward / Lottery Lures
- Sensitive Personal Information Harvesting
- Generic Greetings
"""

import re
from typing import Dict, List, Any
from backend.utils.preprocessor import compute_text_statistics

# Keyword & Pattern Dictionaries for Social Engineering Detection
TRIGGERS = {
    "urgency": {
        "label": "Urgency & Artificial Time Pressure",
        "weight": 15,
        "keywords": [
            r"\b(urgent|urgently|immediate|immediately|act now|hurry|right now|limited time|promptly)\b",
            r"\b(within\s+\d+\s+(hours?|minutes?|days?)|expire[sd]?\s+(soon|today|in\s+\d+\s+hours?))\b",
            r"\b(last\s+chance|final\s+notice|time\s+sensitive|deadline\s+approaching)\b"
        ]
    },
    "fear_threats": {
        "label": "Fear, Intimidation & Coercion",
        "weight": 20,
        "keywords": [
            r"\b(suspend(ed|ion)?|terminat(e|ed|ion)|lock(ed)?\s+out|restricted\s+access)\b",
            r"\b(legal\s+action|lawsuit|law\s+enforcement|prosecut(ion|ed)?|court\s+summons)\b",
            r"\b(unauthorized\s+access|security\s+breach|fraudulent\s+activity|compromised)\b",
            r"\b(penalty|forfeit|debt\s+collection|debt\s+collector)\b"
        ]
    },
    "financial_pressure": {
        "label": "Financial Urgency & Unusual Requests",
        "weight": 18,
        "keywords": [
            r"\b(overdue\s+invoice|outstanding\s+balance|remittance\s+voucher|payment\s+due)\b",
            r"\b(wire\s+transfer|gift\s+card|apple\s+gift|google\s+play\s+card|steam\s+card)\b",
            r"\b(bitcoin|cryptocurrency|crypto\s+wallet|btc|ransom)\b",
            r"\b(direct\s+deposit|payroll\s+update|tax\s+refund|overpayment)\b"
        ]
    },
    "credential_harvesting": {
        "label": "Credential & Authentication Harvesting",
        "weight": 25,
        "keywords": [
            r"\b(verify\s+your\s+password|confirm\s+(your\s+)?password|reset\s+password)\b",
            r"\b(enter\s+(your\s+)?credentials|login\s+to\s+(verify|restore|validate))\b",
            r"\b(one-time\s+code|2fa\s+code|otp\s+code|verification\s+pin)\b",
            r"\b(re-authenticate|validate\s+account|upgrade\s+(email\s+)?quota)\b"
        ]
    },
    "reward_lures": {
        "label": "Reward, Lottery & Unrealistic Offers",
        "weight": 15,
        "keywords": [
            r"\b(you\s+have\s+won|lucky\s+winner|lottery\s+draw|cash\s+prize|million\s+dollars)\b",
            r"\b(congratulations!\s+you|claim\s+your\s+(reward|prize|inheritance|funds))\b",
            r"\b(exclusive\s+giveaway|free\s+gift|selected\s+to\s+receive)\b"
        ]
    },
    "personal_info_harvest": {
        "label": "Personal Information Harvesting",
        "weight": 18,
        "keywords": [
            r"\b(social\s+security(\s+number)?|\bssn\b|date\s+of\s+birth|\bdob\b)\b",
            r"\b(routing\s+number|bank\s+account\s+number|credit\s+card\s+number|\bcvv\b)\b",
            r"\b(confirm\s+your\s+(identity|personal\s+details|full\s+name))\b"
        ]
    },
    "generic_greeting": {
        "label": "Generic / Impersonal Salutation",
        "weight": 8,
        "keywords": [
            r"^(dear\s+(customer|valued\s+customer|account\s+holder|member|user|client|sir/madam|employee))\b",
            r"\b(attn:\s*(account\s+owner|accounts\s+payable|all\s+employees|employee))\b",
            r"^(attention\s+(employee|user|member|customer))\b"
        ]
    }
}


def analyze_email_content(subject: str, body: str) -> Dict[str, Any]:
    """
    Scans subject and body for phishing triggers and psychological manipulation.
    Returns detected categories, matching phrases, keyword counts, and content score.
    """
    combined_text = f"{subject or ''}\n{body or ''}"
    stats = compute_text_statistics(combined_text)

    detected_categories = []
    category_scores = {}
    matched_snippets = {}
    total_content_score = 0

    # Scan for each category
    for cat_key, cat_data in TRIGGERS.items():
        matches_found = []
        for pattern in cat_data["keywords"]:
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            found = regex.findall(combined_text)
            if found:
                for match in found:
                    phrase = match if isinstance(match, str) else match[0]
                    if phrase and phrase.lower() not in [m.lower() for m in matches_found]:
                        matches_found.append(phrase.strip())

        if matches_found:
            detected_categories.append(cat_key)
            category_scores[cat_key] = cat_data["weight"]
            matched_snippets[cat_key] = matches_found[:5]  # Cap to top 5
            total_content_score += cat_data["weight"]

    # Forensic stylistic analysis: SHOUTING & excessive exclamation
    stylistic_findings = []
    if stats["uppercase_ratio"] > 0.25 and stats["word_count"] > 10:
        total_content_score += 10
        stylistic_findings.append({
            "type": "EXCESSIVE_UPPERCASE",
            "description": f"High uppercase character ratio ({int(stats['uppercase_ratio']*100)}%), indicating shouting or intimidation pressure."
        })

    if stats["exclamation_count"] >= 3:
        total_content_score += 8
        stylistic_findings.append({
            "type": "EXCESSIVE_EXCLAMATION",
            "description": f"Contains multiple exclamation marks ({stats['exclamation_count']}), commonly used to induce urgency."
        })

    # Subject specific urgency check
    subject_urgent = False
    if subject and re.search(r'\b(urgent|immediate|important|action required|alert|attention)\b', subject, re.IGNORECASE):
        subject_urgent = True
        total_content_score += 5

    capped_score = min(max(total_content_score, 0), 100)

    return {
        "content_score": capped_score,
        "detected_categories": detected_categories,
        "category_scores": category_scores,
        "matched_snippets": matched_snippets,
        "stylistic_findings": stylistic_findings,
        "subject_urgent": subject_urgent,
        "stats": stats
    }
