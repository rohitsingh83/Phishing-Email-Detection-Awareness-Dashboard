"""
Machine Learning Inference Engine
Loads trained model artifact and provides fast, deterministic phishing probability scoring.
"""

import json
import math
import os
import re
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_FILE = os.path.join(BASE_DIR, "models", "phishing_ml_model.json")

_MODEL_CACHE = None


def load_model():
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE

    if not os.path.exists(MODEL_FILE):
        # Auto-train if model doesn't exist yet
        from ml.train_model import train_and_evaluate
        train_and_evaluate()

    with open(MODEL_FILE, "r", encoding="utf-8") as f:
        _MODEL_CACHE = json.load(f)
    return _MODEL_CACHE


def predict_email_ml(text: str) -> Dict[str, Any]:
    """
    Computes ML-based phishing probability using TF-IDF and Naive Bayes model.
    """
    model = load_model()
    vocab = model["vocabulary"]
    idf = model["idf_weights"]
    priors = model["class_priors"]
    feature_log_probs = model["feature_log_probs"]
    top_terms = model.get("top_phishing_tokens", [])

    # Tokenize
    text_lower = (text or "").lower()
    tokens = re.findall(r'\b[a-z0-9_\-\.]{2,}\b', text_lower)
    all_ngrams = list(tokens)
    for i in range(len(tokens) - 1):
        all_ngrams.append(f"{tokens[i]}_{tokens[i+1]}")

    # Vectorize
    from collections import Counter
    tf = Counter(all_ngrams)
    norm_sq = 0.0
    sparse_vec = {}

    for term, count in tf.items():
        if term in vocab:
            idx = vocab[term]
            sublinear_tf = 1.0 + math.log(count)
            tfidf_val = sublinear_tf * idf[term]
            sparse_vec[idx] = tfidf_val
            norm_sq += tfidf_val ** 2

    # L2 normalize
    if norm_sq > 0:
        norm = math.sqrt(norm_sq)
        for idx in sparse_vec:
            sparse_vec[idx] /= norm

    # Scoring log odds
    # Note: JSON keys are strings
    prior_0 = float(priors.get("0", priors.get(0, -0.693)))
    prior_1 = float(priors.get("1", priors.get(1, -0.693)))

    log_p0 = prior_0
    log_p1 = prior_1

    matched_discriminative_words = []
    log_probs_0 = feature_log_probs.get("0", feature_log_probs.get(0, {}))
    log_probs_1 = feature_log_probs.get("1", feature_log_probs.get(1, {}))

    for idx, val in sparse_vec.items():
        idx_str = str(idx)
        lp0 = float(log_probs_0.get(idx_str, -20.0))
        lp1 = float(log_probs_1.get(idx_str, -20.0))
        log_p0 += lp0 * val
        log_p1 += lp1 * val

        # If term is more indicative of phishing
        if lp1 > lp0:
            inv_term = [k for k, v in vocab.items() if v == idx]
            if inv_term:
                matched_discriminative_words.append(inv_term[0])

    diff = log_p0 - log_p1
    if diff > 100:
        prob_phishing = 0.0001
    elif diff < -100:
        prob_phishing = 0.9999
    else:
        prob_phishing = 1.0 / (1.0 + math.exp(diff))

    prob_phishing = round(prob_phishing, 4)
    ml_label = "PHISHING" if prob_phishing >= 0.5 else "LEGITIMATE"
    confidence = round(max(prob_phishing, 1.0 - prob_phishing) * 100, 2)

    return {
        "ml_probability": prob_phishing,
        "ml_risk_score": int(round(prob_phishing * 100)),
        "ml_label": ml_label,
        "confidence_percent": confidence,
        "matched_phishing_tokens": matched_discriminative_words[:8]
    }
