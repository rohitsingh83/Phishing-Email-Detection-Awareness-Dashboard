"""
Model Evaluation and Confusion Matrix Report
Provides deep quantitative and defensive analysis of model performance,
error types (False Positives vs False Negatives), and threshold sensitivity.
"""

import json
import os
from typing import Dict, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_FILE = os.path.join(BASE_DIR, "models", "phishing_ml_model.json")


def generate_evaluation_report() -> Dict[str, Any]:
    if not os.path.exists(MODEL_FILE):
        from ml.train_model import train_and_evaluate
        train_and_evaluate()

    with open(MODEL_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    tp = metrics.get("tp", 0)
    tn = metrics.get("tn", 0)
    fp = metrics.get("fp", 0)
    fn = metrics.get("fn", 0)

    report_str = f"""
======================================================================
CYBERSECURITY ML MODEL EVALUATION & ERROR ANALYSIS REPORT
======================================================================
Model Architecture : {data.get('model_type')}
Vocabulary Features: {len(data.get('vocabulary', {}))} n-grams
Test Set Size      : {metrics.get('test_size', 0)} samples (Held-out evaluation)

PERFORMANCE METRICS:
----------------------------------------------------------------------
Accuracy  : {metrics.get('accuracy', 0.0) * 100:.2f}%
Precision : {metrics.get('precision', 0.0) * 100:.2f}% (Purity of phishing alerts; reduces false alarms)
Recall    : {metrics.get('recall', 0.0) * 100:.2f}% (Coverage of threat lures; reduces missed intrusions)
F1 Score  : {metrics.get('f1_score', 0.0) * 100:.2f}% (Harmonic balance between Precision and Recall)

CONFUSION MATRIX VISUALIZATION:
----------------------------------------------------------------------
                     Predicted Legitimate    Predicted Phishing
Actual Legitimate :       {tn:<18}    {fp:<18} (False Positive / False Alarm)
Actual Phishing   :       {fn:<18}    {tp:<18} (True Positive / Blocked Threat)

CYBERSECURITY ERROR TYPE ANALYSIS:
----------------------------------------------------------------------
1. TRUE POSITIVE (TP = {tp}):
   Phishing attack was successfully flagged. Incident prevented; user alerted; SOC workload minimized.

2. TRUE NEGATIVE (TN = {tn}):
   Legitimate routine email correctly identified. Normal business productivity maintained.

3. FALSE POSITIVE (FP = {fp}):
   Legitimate email flagged as phishing.
   Operational Impact: Analyst alert fatigue, user annoyance, possible delayed delivery of genuine communications.

4. FALSE NEGATIVE (FN = {fn}) [HIGHEST CYBERSECURITY DANGER]:
   Active phishing lure classified as legitimate!
   Operational Impact: Malicious email lands directly in employee inbox.
   Risk: Credential harvesting, unauthorized initial access, ransomware deployment, enterprise breach.
   Defensive Mitigation: Layered defense (Rule-Based + ML + Email Gateway + User Awareness).

TOP INDICATIVE TOKENS:
----------------------------------------------------------------------
{', '.join(data.get('top_phishing_tokens', [])[:15])}
======================================================================
"""
    print(report_str)
    return metrics


if __name__ == "__main__":
    generate_evaluation_report()
