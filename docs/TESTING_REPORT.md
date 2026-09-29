# Automated Security Testing Matrix & Verification Report

Comprehensive validation results for the 25 automated security test scenarios executed in `tests/test_phishing_system.py`.

**Execution Summary:** 25/25 Tests Passed &bull; 0 Failures &bull; 0 Errors &bull; Execution Time: ~0.08s

| Test ID | Scenario | Input Vector | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TEST-01** | Legitimate Routine Email | Standard corporate all-hands memo with clean PDF attachment | Risk score &le; 25, Classification: LOW RISK | Score: 18/100, LOW RISK | **PASS** |
| **TEST-02** | Urgent Phishing Lure | 24-hr suspension threat + raw IP URL + password demand | Risk score &ge; 65, Elevated Threat | Score: 69/100, HIGH RISK | **PASS** |
| **TEST-03** | Credential Harvesting | Text: *"Please verify your password and enter 2FA code"* | Category `credential_harvesting` detected | Category Detected | **PASS** |
| **TEST-04** | Financial Pressure | Text: *"Overdue invoice, immediate wire transfer or gift card"* | Category `financial_pressure` detected | Category Detected | **PASS** |
| **TEST-05** | Generic Impersonal Salutation | Text: *"Dear Customer, your monthly summary is ready"* | Category `generic_greeting` detected | Category Detected | **PASS** |
| **TEST-06** | Safe Domain URL | `https://portal.example.org/documents/report.pdf` | Risk score &lt; 20, Raw IP: False | Score: 0/100, Raw IP: False | **PASS** |
| **TEST-07** | Raw IP Hostname Link | `http://198.51.100.10/verify-account` | `is_raw_ip == True`, Risk score &ge; 40 | Raw IP: True, Risk: 55/100 | **PASS** |
| **TEST-08** | Unencrypted HTTP Scheme | `http://invoicing-desk.invalid.test/pay` | Indicator `UNENCRYPTED_HTTP` present | Finding Logged | **PASS** |
| **TEST-09** | Excessive URL Subdomains | `https://login.verify.auth.account.invalid.test/login` | Subdomain count &ge; 3, Risk &ge; 20 | Subdomains: 4, Risk: 40/100 | **PASS** |
| **TEST-10** | Suspicious Keyword in URL | `https://server12.invalid.test/portal/login-verify-account` | Indicator `SUSPICIOUS_URL_KEYWORDS` present | Finding Logged | **PASS** |
| **TEST-11** | Zero URLs in Payload | Empty URL list `[]` | Total URLs: 0, Aggregated Risk: 0 | Total: 0, Risk: 0 | **PASS** |
| **TEST-12** | Multiple URLs Aggregation | 2 Raw IP URLs + 1 safe domain URL | Total: 3, `has_suspicious_urls == True` | Total: 3, Suspicious: True | **PASS** |
| **TEST-13** | Standard Document File | `Quarterly_Report_2026.pdf` | Primary Ext: `.pdf`, Severity: LOW | Ext: `.pdf`, Severity: LOW | **PASS** |
| **TEST-14** | Executable Script Binary | `Setup_Tool.exe` | Severity: HIGH, Risk Score &ge; 50 | Severity: HIGH, Risk: 75/100 | **PASS** |
| **TEST-15** | Deceptive Double Extension | `Invoice_Overdue.pdf.exe` | `is_double_extension == True`, DOUBLE_EXTENSION finding | Double Ext: True, Critical logged | **PASS** |
| **TEST-16** | Empty Subject Line | Subject: `""`, Sender & Body populated | Graceful execution, non-null risk score | Score computed cleanly | **PASS** |
| **TEST-17** | Empty Body Text | Body: `""`, Sender & Subject populated | Graceful execution, non-null risk score | Score computed cleanly | **PASS** |
| **TEST-18** | Blank / Missing Sender | Sender: `""` | Indicator `MISSING_SENDER` flagged | Finding Logged | **PASS** |
| **TEST-19** | Shouting / High Uppercase | Subject + Body with &gt; 70% capital letters | `uppercase_ratio > 0.70` | Ratio: 0.78, Shouting flagged | **PASS** |
| **TEST-20** | Excessive Exclamation Points | Body containing `Warning!!! ... suspended!!!` | `exclamation_count >= 6` | Count: 6 detected | **PASS** |
| **TEST-21** | Boundary Capping (0-100) | Maximally hostile email with all attack vectors combined | Score capped at maximum 100/100 | Final Score: 100/100 | **PASS** |
| **TEST-22** | SQLite Database Persistence | Insert analysis record with child indicators | Returns valid integer `analysis_id > 0` | ID Returned: OK | **PASS** |
| **TEST-23** | Database Query by ID | Query record by inserted `analysis_id` | Retrieved record matches inserted domain & score | Exact match: OK | **PASS** |
| **TEST-24** | Machine Learning Inference | Prompt with urgent phishing phrasing | `ml_probability >= 0.70`, Label: PHISHING | Prob: 0.9999, PHISHING | **PASS** |
| **TEST-25** | Audit History & Cascaded Cleanup | Retrieve audit history list and verify cascade | Non-empty list returned, records parsed | History list verified: OK | **PASS** |
