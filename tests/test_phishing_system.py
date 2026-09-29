"""
Automated Cybersecurity Testing Suite for Phishing Detection System
Implements 25 comprehensive test scenarios validating rule engines, URL analyzers,
forensic heuristics, attachment metadata, database operations, and ML inference.
"""

import os
import sys
import unittest

# Ensure project root is in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.utils.preprocessor import extract_urls, extract_domain, extract_file_extension, compute_text_statistics
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.url_analyzer import analyze_single_url, analyze_urls
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.feature_extractor import extract_email_features
from backend.services.risk_engine import calculate_phishing_score
from backend.services.hybrid_detector import run_hybrid_analysis
from backend.database import init_db, save_analysis_record, get_all_analyses, get_analysis_by_id, delete_analysis
from ml.predict import predict_email_ml


class PhishingSystemComprehensiveTestSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        print("\n" + "="*80)
        print("RUNNING 25 DEFENSIVE CYBERSECURITY AUTOMATED TESTS")
        print("="*80)

    # 1. Legitimate Email
    def test_01_legitimate_email(self):
        result = run_hybrid_analysis(
            sender="info@example.org",
            subject="Quarterly Town Hall Notes",
            body="Team, thanks for attending our meeting today. Notes are available on the intranet.",
            urls="https://portal.example.org/notes",
            attachment_name="Notes.pdf"
        )
        self.assertLessEqual(result["hybrid_risk_score"], 25)
        self.assertEqual(result["risk_level"], "LOW")

    # 2. Urgent Phishing-Style Email
    def test_02_urgent_phishing_email(self):
        result = run_hybrid_analysis(
            sender="alert@account-verify.invalid.test",
            subject="URGENT: Immediate Account Suspension in 24 Hours",
            body="ACT NOW: You must confirm your password immediately or your account will be deleted.",
            urls="http://198.51.100.10/verify",
            attachment_name=""
        )
        self.assertGreaterEqual(result["hybrid_risk_score"], 65)
        self.assertIn(result["risk_level"], ["SUSPICIOUS", "HIGH"])

    # 3. Credential Request Detection
    def test_03_credential_request(self):
        content = analyze_email_content("Security Update", "Please verify your password and enter your 2FA code.")
        self.assertIn("credential_harvesting", content["detected_categories"])

    # 4. Financial Request Detection
    def test_04_financial_request(self):
        content = analyze_email_content("Billing Alert", "Overdue invoice. Immediate payment required via wire transfer or gift card.")
        self.assertIn("financial_pressure", content["detected_categories"])

    # 5. Generic Greeting Detection
    def test_05_generic_greeting(self):
        content = analyze_email_content("Notification", "Dear Customer,\nYour monthly summary is ready.")
        self.assertIn("generic_greeting", content["detected_categories"])

    # 6. Safe URL Analysis
    def test_06_safe_url(self):
        url_res = analyze_single_url("https://portal.example.org/documents/report.pdf")
        self.assertLess(url_res["risk_score"], 20)
        self.assertFalse(url_res["is_raw_ip"])

    # 7. Raw IP URL Analysis
    def test_07_raw_ip_url(self):
        url_res = analyze_single_url("http://198.51.100.10/verify-account")
        self.assertTrue(url_res["is_raw_ip"])
        self.assertGreaterEqual(url_res["risk_score"], 40)

    # 8. Non-HTTPS URL Analysis
    def test_08_non_https_url(self):
        url_res = analyze_single_url("http://invoicing-desk.invalid.test/pay")
        self.assertEqual(url_res["scheme"], "http")
        has_http_finding = any(f["type"] == "UNENCRYPTED_HTTP" for f in url_res["findings"])
        self.assertTrue(has_http_finding)

    # 9. Excessive Subdomains in URL
    def test_09_excessive_subdomains_url(self):
        url_res = analyze_single_url("https://login.verify.auth.account.service.invalid.test/login")
        self.assertGreaterEqual(url_res["subdomain_count"], 3)
        self.assertGreaterEqual(url_res["risk_score"], 20)

    # 10. Suspicious Keyword in URL
    def test_10_suspicious_keyword_in_url(self):
        url_res = analyze_single_url("https://server12.invalid.test/portal/login-verify-account")
        has_kw_finding = any(f["type"] == "SUSPICIOUS_URL_KEYWORDS" for f in url_res["findings"])
        self.assertTrue(has_kw_finding)

    # 11. No URL Present
    def test_11_no_url_present(self):
        urls_res = analyze_urls([])
        self.assertEqual(urls_res["total_urls"], 0)
        self.assertEqual(urls_res["aggregated_risk_score"], 0)

    # 12. Multiple URLs Aggregation
    def test_12_multiple_urls(self):
        url_list = [
            "http://198.51.100.10/login",
            "http://203.0.113.50/verify",
            "https://portal.example.org/about"
        ]
        urls_res = analyze_urls(url_list)
        self.assertEqual(urls_res["total_urls"], 3)
        self.assertTrue(urls_res["has_suspicious_urls"])

    # 13. Normal Document Attachment
    def test_13_normal_attachment(self):
        att = analyze_attachment("Quarterly_Report_2026.pdf")
        self.assertEqual(att["primary_extension"], ".pdf")
        self.assertFalse(att["is_double_extension"])
        self.assertEqual(att["severity"], "LOW")

    # 14. Executable Attachment
    def test_14_executable_attachment(self):
        att = analyze_attachment("Setup_Tool.exe")
        self.assertEqual(att["severity"], "HIGH")
        self.assertGreaterEqual(att["risk_score"], 50)

    # 15. Double Extension Attachment (e.g. invoice.pdf.exe)
    def test_15_double_extension(self):
        att = analyze_attachment("Invoice_Overdue.pdf.exe")
        self.assertTrue(att["is_double_extension"])
        has_double = any(f["type"] == "DOUBLE_EXTENSION" for f in att["findings"])
        self.assertTrue(has_double)

    # 16. Empty Subject Handling
    def test_16_empty_subject(self):
        bundle = extract_email_features("user@example.com", "", "Standard message body.")
        res = calculate_phishing_score(bundle)
        self.assertIsNotNone(res["risk_score"])

    # 17. Empty Body Handling
    def test_17_empty_body(self):
        bundle = extract_email_features("user@example.com", "Meeting Reminder", "")
        res = calculate_phishing_score(bundle)
        self.assertIsNotNone(res["risk_score"])

    # 18. Invalid/Blank Sender Handling
    def test_18_invalid_sender(self):
        sender_res = analyze_sender("")
        has_missing = any(f["type"] == "MISSING_SENDER" for f in sender_res["findings"])
        self.assertTrue(has_missing)

    # 19. High Uppercase Ratio (SHOUTING)
    def test_19_high_uppercase_ratio(self):
        stats = compute_text_statistics("URGENT NOTICE ALL RECIPIENTS ACT IMMEDIATELY")
        self.assertGreater(stats["uppercase_ratio"], 0.70)

    # 20. Multiple Exclamation Marks
    def test_20_multiple_exclamations(self):
        stats = compute_text_statistics("Warning!!! Your account is suspended!!!")
        self.assertGreaterEqual(stats["exclamation_count"], 6)

    # 21. Risk Score Capping Boundary (0-100)
    def test_21_score_boundary(self):
        result = run_hybrid_analysis(
            sender="admin@paypal-security-update.invalid.test",
            subject="URGENT: PASSWORD EXPIRATION SUSPENDED LEGAL ACTION !!!",
            body="DEAR CUSTOMER, ENTER PASSWORD ROUTING NUMBER SSN IMMEDIATELY OR BE ARRESTED BY POLICE http://198.51.100.10/login",
            urls="http://198.51.100.10/login",
            attachment_name="Notice.pdf.exe"
        )
        self.assertLessEqual(result["hybrid_risk_score"], 100)
        self.assertGreaterEqual(result["hybrid_risk_score"], 0)

    # 22. Database Save Record
    def test_22_database_save(self):
        mock_result = {
            "hybrid_risk_score": 85,
            "classification": "HIGH RISK / LIKELY PHISHING",
            "risk_level": "HIGH",
            "machine_learning": {"ml_probability": 0.95},
            "indicators": [{"category": "URL", "severity": "HIGH", "title": "Raw IP", "description": "Test IP"}],
            "url_analysis": {"url_details": [{"url": "http://198.51.100.10", "risk_score": 60, "findings": []}]}
        }
        saved_id = save_analysis_record(mock_result, sender_domain="test.invalid.test", subject="Test Subject DB")
        self.assertIsInstance(saved_id, int)
        self.assertGreater(saved_id, 0)

    # 23. Database Retrieval by ID
    def test_23_database_retrieval(self):
        mock_result = {
            "hybrid_risk_score": 10,
            "classification": "SAFE / LOW RISK",
            "risk_level": "LOW",
            "machine_learning": {"ml_probability": 0.05},
            "indicators": [],
            "url_analysis": {"url_details": []}
        }
        saved_id = save_analysis_record(mock_result, sender_domain="safe.example.com", subject="Safe Query Test")
        record = get_analysis_by_id(saved_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["sender_domain"], "safe.example.com")
        self.assertEqual(record["risk_score"], 10)

    # 24. Machine Learning Inference
    def test_24_ml_prediction(self):
        ml_res = predict_email_ml("URGENT: verify password immediately to avoid suspension http://198.51.100.10/login")
        self.assertGreaterEqual(ml_res["ml_probability"], 0.70)
        self.assertEqual(ml_res["ml_label"], "PHISHING")

    # 25. Analysis History Listing & Cleanup
    def test_25_history_listing_and_cleanup(self):
        records = get_all_analyses(limit=10)
        self.assertIsInstance(records, list)
        if len(records) > 0:
            target_id = records[0]["analysis_id"]
            # verify fetch
            rec = get_analysis_by_id(target_id)
            self.assertIsNotNone(rec)


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(PhishingSystemComprehensiveTestSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "="*80)
    print(f"TEST EXECUTION SUMMARY: {result.testsRun} Tests Run | {len(result.failures)} Failures | {len(result.errors)} Errors")
    print("="*80)
    return len(result.failures) == 0 and len(result.errors) == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
