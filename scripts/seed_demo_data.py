"""
Demo Data Seeder
Populates SQLite database with 30 diverse forensic analysis records
from the synthetic dataset so dashboard metrics, charts, and history
are immediately visible upon initial startup.
"""

import csv
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.database import init_db, save_analysis_record, get_db_connection
from backend.services.hybrid_detector import run_hybrid_analysis
from backend.utils.preprocessor import extract_domain

DATASET_CSV = os.path.join(BASE_DIR, "data", "phishing_email_dataset.csv")


def seed_database(limit=30):
    print("=" * 60)
    print(f"SEEDING DATABASE WITH {limit} DIVERSE FORENSIC AUDIT RECORDS")
    print("=" * 60)

    init_db()

    # Clear existing demo entries to have a clean, balanced state
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM url_analyses;")
        conn.execute("DELETE FROM indicators;")
        conn.execute("DELETE FROM analyses;")
    conn.close()

    if not os.path.exists(DATASET_CSV):
        from data.generate_dataset import generate_dataset
        generate_dataset()

    records = []
    with open(DATASET_CSV, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)

    # Pick an even balance of legitimate and phishing samples
    legit = [r for r in records if r["label"].upper() == "LEGITIMATE"][: limit // 2]
    phish = [r for r in records if r["label"].upper() == "PHISHING"][: limit // 2]
    selected = legit + phish

    # Interleave them
    import random
    random.seed(42)
    random.shuffle(selected)

    inserted_count = 0
    for item in selected:
        sender = item.get("sender", "")
        subject = item.get("subject", "")
        body = item.get("body", "")
        urls = item.get("urls", "")
        attachment = item.get("attachment_name", "")

        result = run_hybrid_analysis(
            sender=sender,
            subject=subject,
            body=body,
            urls=urls,
            attachment_name=attachment
        )

        domain = extract_domain(sender) or item.get("sender_domain", "unknown")
        analysis_id = save_analysis_record(result, sender_domain=domain, subject=subject)
        inserted_count += 1
        print(f"[{inserted_count}/{len(selected)}] Ingested '{subject[:40]}...' -> Score: {result['hybrid_risk_score']} ({result['classification']})")

    print("=" * 60)
    print(f"Successfully seeded {inserted_count} audit records into SQLite database!")
    print("=" * 60)


if __name__ == "__main__":
    seed_database(30)
