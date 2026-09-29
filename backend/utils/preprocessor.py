"""
Email Security Preprocessor
Safely normalizes and extracts forensic artifacts from raw email text.

DEFENSIVE SECURITY NOTE:
Standard NLP pipelines often aggressively strip punctuation, numbers, and casing.
In cybersecurity detection, aggressive preprocessing DESTROYS evidence:
- ALL-CAPS (uppercase ratio) indicates urgency/coercion.
- Excessive punctuation ('!!!', '???') indicates artificial pressure.
- Numbers and special characters are core to IP addresses, lookalike domains (paypa1), and order lures.
- URLs and email headers contain vital telemetry.
Therefore, this preprocessor extracts security metadata BEFORE normalizing text.
"""

import re
from typing import Dict, List, Any
from urllib.parse import urlparse


def extract_urls(text: str) -> List[str]:
    """
    Extracts URLs from text using robust regex.
    Matches standard http, https, and raw IP address schemes.
    """
    if not text:
        return []
    # Regex matching http://, https://, or bare domain/IP with path
    url_pattern = re.compile(
        r'(?:https?://|www\.)[^\s<>"\'{}|\\^`]+|(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>"\'{}|\\^`]*)?',
        re.IGNORECASE
    )
    matches = url_pattern.findall(text)
    # Ensure scheme for consistency
    cleaned = []
    for m in matches:
        m = m.strip('.,;:)("[]\'')
        if m:
            if not m.startswith('http://') and not m.startswith('https://'):
                m = 'http://' + m
            cleaned.append(m)
    return list(dict.fromkeys(cleaned))  # deduplicate preserving order


def extract_domain(email_address: str) -> str:
    """
    Extracts the domain portion from an email address (e.g., 'user@dept.example.com' -> 'dept.example.com').
    Handles 'Display Name <email@domain>' format.
    """
    if not email_address:
        return ""
    # Extract email from angle brackets if present
    bracket_match = re.search(r'<([^>]+)>', email_address)
    if bracket_match:
        email_address = bracket_match.group(1)
    
    parts = email_address.strip().split('@')
    if len(parts) >= 2:
        return parts[-1].strip().lower()
    return ""


def extract_display_name(email_address: str) -> str:
    """
    Extracts display name if provided (e.g., 'CEO John Smith <attacker@invalid.test>' -> 'CEO John Smith').
    """
    if not email_address:
        return ""
    match = re.match(r'^(.*?)\s*<.*?>', email_address.strip())
    if match:
        return match.group(1).strip('"\'' )
    return ""


def extract_file_extension(filename: str) -> Dict[str, Any]:
    """
    Safely inspects attachment filename without opening or executing it.
    Detects single extension and dangerous double extensions (e.g. invoice.pdf.exe).
    """
    if not filename:
        return {
            "has_attachment": False,
            "filename": "",
            "primary_extension": "",
            "all_extensions": [],
            "is_double_extension": False
        }
    
    filename = filename.strip()
    dots = filename.split('.')
    if len(dots) <= 1:
        return {
            "has_attachment": True,
            "filename": filename,
            "primary_extension": "",
            "all_extensions": [],
            "is_double_extension": False
        }
    
    extensions = [f".{d.lower()}" for d in dots[1:]]
    primary_ext = extensions[-1]
    is_double = len(extensions) >= 2
    
    return {
        "has_attachment": True,
        "filename": filename,
        "primary_extension": primary_ext,
        "all_extensions": extensions,
        "is_double_extension": is_double
    }


def compute_text_statistics(text: str) -> Dict[str, Any]:
    """
    Extracts stylistic forensic statistics before destructive normalization.
    """
    if not text:
        return {
            "char_count": 0,
            "word_count": 0,
            "uppercase_count": 0,
            "uppercase_ratio": 0.0,
            "exclamation_count": 0,
            "question_count": 0,
            "digit_count": 0
        }
    
    char_count = len(text)
    words = re.findall(r'\b\w+\b', text)
    word_count = len(words)
    uppercase_count = sum(1 for c in text if c.isupper())
    alpha_count = sum(1 for c in text if c.isalpha())
    uppercase_ratio = round(uppercase_count / max(alpha_count, 1), 4)
    exclamation_count = text.count('!')
    question_count = text.count('?')
    digit_count = sum(1 for c in text if c.isdigit())
    
    return {
        "char_count": char_count,
        "word_count": word_count,
        "uppercase_count": uppercase_count,
        "uppercase_ratio": uppercase_ratio,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "digit_count": digit_count
    }


def normalize_text_for_nlp(text: str) -> str:
    """
    Gentle normalization for TF-IDF / NLP tokenization:
    - Lowercases text
    - Replaces URLs with a neutral token
    - Replaces emails with a neutral token
    - Retains alphabetical and numerical tokens
    """
    if not text:
        return ""
    # Normalize URLs
    text = re.sub(r'https?://\S+|www\.\S+', ' url_token ', text)
    # Normalize emails
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' email_token ', text)
    # Lowercase
    text = text.lower()
    # Strip excessive whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text
