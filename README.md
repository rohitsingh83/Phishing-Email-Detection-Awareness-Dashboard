# Phishing Email Detection & Security Awareness Dashboard (PhishShield)

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-brightgreen.svg?logo=github)](https://rohitsingh83.github.io/Phishing-Email-Detection-Awareness-Dashboard/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Defensive Cybersecurity](https://img.shields.io/badge/Cybersecurity-Defensive-red.svg)]()
[![Automated Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg)]()

> 🌐 **Live Website (Independent, Zero-Backend):** [https://rohitsingh83.github.io/Phishing-Email-Detection-Awareness-Dashboard/](https://rohitsingh83.github.io/Phishing-Email-Detection-Awareness-Dashboard/)
>
> **Defensive cybersecurity platform for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments and security awareness guidance.**

---

## 🛡️ Table of Contents
1. [Overview & Problem Statement](#overview--problem-statement)
2. [Key Features](#key-features)
3. [Cybersecurity & SOC Relevance](#cybersecurity--soc-relevance)
4. [System Architecture](#system-architecture)
5. [Technology Stack](#technology-stack)
6. [Safe Synthetic Dataset](#safe-synthetic-dataset)
7. [Detection Subsystems](#detection-subsystems)
   - [Sender Forensics](#sender-forensics)
   - [Content & Psychological Analysis](#content--psychological-analysis)
   - [Static URL Analysis](#static-url-analysis)
   - [Attachment Analysis](#attachment-analysis)
8. [Hybrid Threat Scoring Engine](#hybrid-threat-scoring-engine)
9. [Machine Learning & Model Evaluation](#machine-learning--model-evaluation)
10. [SOC Dashboard & Telemetry](#soc-dashboard--telemetry)
11. [Security Awareness & Training Module](#security-awareness--training-module)
12. [Installation & Execution Guide](#installation--execution-guide)
13. [API Documentation](#api-documentation)
14. [Automated Testing Suite (25 Tests)](#automated-testing-suite)
15. [Security, Privacy & Ethics](#security-privacy--ethics)
16. [Proof of Work & Screenshots Checklist](#proof-of-work--screenshots-checklist)
17. [Interview Preparation Guide](#interview-preparation-guide)
18. [Disclaimer](#disclaimer)

---

## 📌 Overview & Problem Statement
Email remains the **#1 initial access vector** in cyber attacks, accounting for over 90% of breaches. Organizations face two compounding challenges:
1. **The Human Surface:** Adversaries exploit cognitive biases (fear, urgency, financial pressure, authority) to deceive employees into surrendering credentials or executing payloads.
2. **The "Black Box" Problem:** Traditional detection systems provide binary labels without explaining **WHY** an email was flagged, causing analyst alert fatigue and leaving end users uninformed.

**PhishShield** solves this by providing a unified, multi-vector defensive console that analyzes sender identity, language psychology, static URL mechanics, and attachment filenames. It generates an explainable 0–100 threat score, displays actionable playbooks, logs audit telemetry to an embedded SQLite database, and delivers interactive security awareness training.

---

## 🚀 Key Features
- **Multi-Vector Threat Inspection:** Combines 4 specialized forensic analyzers (Sender, Content, URL, Attachment).
- **Hybrid Detection Model:** Fuses deterministic rule-based threat heuristics (55%) with statistical TF-IDF Naive Bayes NLP (45%).
- **Explainable Decision Engine ("WHY?"):** Highlights exact triggers (e.g. credential harvest prompts, raw IP hosts, double extensions) with severity ratings.
- **Safe Static Link Auditing:** Analyzes URLs as text strings without contacting external servers—eliminating beaconing risks and preventing malicious code execution.
- **Modern SOC Web Console:** Built with responsive HTML5, modern cybersecurity CSS, and Chart.js for real-time risk histograms, classification breakdowns, and trend lines.
- **Interactive Awareness Training:** Includes the "Before You Click" defensive checklist, training micro-lessons, and synthetic simulation templates.
- **Audit History & Search:** Search, filter by risk level, view forensic detail modals, and manage stored analysis records.
- **Zero-Dependency Resilience:** Engineered in pure Python with NumPy vectorization, ensuring 100% execution across restricted enterprise and university environments where binary extension DLLs may be blocked.

---

## 🏢 Cybersecurity & SOC Relevance
This project directly reflects real-world engineering practices across enterprise security roles:

| Role | How This Project Applies |
| :--- | :--- |
| **SOC Tier 1 / Tier 2 Analyst** | Triaging reported phishing messages, correlating IOCs, reviewing automated scores, and executing containment playbooks. |
| **Email Security Analyst** | Configuring Secure Email Gateway (SEG) rules, tuning brand lookalike regex, and analyzing sender authenticity. |
| **Threat Intelligence Analyst** | Extracting Indicators of Compromise (IOCs), mapping attacks to MITRE ATT&CK techniques, and tracking campaign trends. |
| **Security Awareness Specialist** | Designing micro-lessons and educating end users on social engineering tactics (the "Before You Click" checklist). |

---

## 🏛️ System Architecture

```
User Input / .EML / .TXT
           │
           ▼
FastAPI REST API Ingestion (/api/analyze)
           │
           ▼
Forensic Artifact Extraction Engine
 ├── Sender Analyzer (Typosquatting, Subdomains, Display Name)
 ├── Content Analyzer (Urgency, Fear, Credential Harvesting, Financial)
 ├── URL Analyzer (Static string analysis, Raw IPs, Deceptive keywords)
 └── Attachment Analyzer (Executables, Double extensions like .pdf.exe)
           │
           ├──────────────────────────────┐
           ▼                              ▼
Rule-Based Engine (0–100)        TF-IDF Naive Bayes NLP Model
           │                              │
           └──────────────┬───────────────┘
                          ▼
            Hybrid Threat Scoring Engine
             Score = (Rule * 0.55) + (ML * 0.45)
                          │
                          ▼
            Classification & Explainability
             - SAFE / LOW RISK (0–20)
             - MODERATE RISK (21–40)
             - SUSPICIOUS (41–70)
             - HIGH RISK / LIKELY PHISHING (71–100)
                          │
                          ▼
        SQLite Database  ◄──►  Web Dashboard (Charts & Awareness)
```

---

## 🛠️ Technology Stack
- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic v2.
- **Storage:** SQLite3 (Relational metadata audit trail).
- **Machine Learning / NLP:** Sublinear TF-IDF Vectorizer, Multinomial Naive Bayes with Laplace Smoothing, NumPy.
- **Frontend:** HTML5, Modern Responsive CSS (Dark Cyber Theme), Vanilla JavaScript, Chart.js (CDN).
- **Testing:** Python `unittest` (25 automated test scenarios).

---

## 📊 Safe Synthetic Dataset
The project includes a generator (`data/generate_dataset.py`) producing **600 balanced records** stored in `data/phishing_email_dataset.csv`.
- **RFC 2606 Reserved Domains:** `example.com`, `example.org`, `example.net`, `invalid.test`.
- **RFC 5737 Test IP Addresses:** `198.51.100.10`, `203.0.113.45`.
- **Legitimate Categories:** HR notices, university exam schedules, IT maintenance alerts, order confirmations, monthly banking statements, project sprint notes.
- **Phishing Lures:** Credential harvesting, urgent account suspension, fake overdue invoices, lottery prizes, password expiration notices, CEO gift card fraud, cloud quota warnings.

---

## 🔍 Detection Subsystems

### 1. Sender Forensics (`backend/services/sender_analyzer.py`)
- Analyzes sender email formatting and extracts domains.
- Detects excessive subdomain nesting ($\ge 3$ subdomains) used to obfuscate true origin.
- Checks display-name spoofing (e.g. Display Name says "Microsoft Support" but sender domain is `invalid.test`).
- Flags known brand typosquatting patterns (e.g. `paypa1`, `micr0soft`, `amaz0n`).

### 2. Content & Psychological Analysis (`backend/services/content_analyzer.py`)
- **Urgency & Time Pressure:** Detects coercion phrases like *"act now"*, *"within 24 hours"*, *"urgent"*.
- **Fear & Intimidation:** Flags threats such as *"account suspended"*, *"legal action"*, *"law enforcement"*.
- **Financial Pressure:** Flags demands for gift cards, wire transfers, overdue invoice vouchers.
- **Credential Harvesting:** Identifies solicitations for passwords, 2FA codes, PINs, or account verification.
- **Generic Greetings:** Detects depersonalized salutations (`Dear Customer`, `Attn: Employee`).
- **Stylistic Forensics:** Flags uppercase shouting ratios ($> 25\%$) and multiple exclamation marks ($!!!$).

### 3. Static URL Analysis (`backend/services/url_analyzer.py`)
- **Zero-Network Static Inspection:** Inspects URL strings without initiating network socket connections.
- **Raw IP Address Hostnames:** Detects direct IP links (e.g. `http://198.51.100.10/login`), heavily favored in zero-day campaigns.
- **Scheme Verification:** Evaluates unencrypted HTTP protocols.
- **The HTTPS Fallacy:** Explicitly informs analysts that HTTPS presence does **not** prove safety—over 80% of phishing sites use free TLS certificates to display padlock icons.
- **Deceptive Keywords:** Flags authentication keywords (`verify`, `login`, `account`, `banking`, `pay-now`) packed into subdomains or path segments.

### 4. Attachment Analysis (`backend/services/attachment_analyzer.py`)
- **Dangerous Extensions:** Flags direct executables and scripts (`.exe, .vbs, .scr, .bat, .cmd, .js, .ps1`).
- **Deceptive Double Extensions:** Detects deceptive multi-extension masquerading (e.g. `Invoice_Statement.pdf.exe`).
- **Document Categorization:** Classifies standard office documents (`.pdf, .docx, .xlsx`) with appropriate baseline caution.

---

## 🎯 Hybrid Threat Scoring Engine
The final score fuses expert rules with statistical ML probabilities:
$$\text{Hybrid Score} = \min(100, \max(0, \text{round}(0.55 \cdot S_{\text{rule}} + 0.45 \cdot S_{\text{ml}})))$$

| Score Range | Classification | Operational Meaning |
| :---: | :---: | :--- |
| **0 – 20** | **SAFE / LOW RISK** | Routine communication. Standard baseline caution applies. |
| **21 – 40** | **MODERATE RISK** | Minor non-standard patterns detected. Exercise cautious review. |
| **41 – 70** | **SUSPICIOUS** | Contains deceptive language or anomalous links. Quarantine recommended. |
| **71 – 100** | **HIGH RISK / LIKELY PHISHING** | Multi-vector attack indicators present. Block, purge, and trigger SOC containment. |

---

## 🧠 Machine Learning & Model Evaluation
The model evaluates subject and body text using sublinear TF-IDF n-grams ($1 \le n \le 2$) and a Multinomial Naive Bayes classifier.

### Real Evaluation Results (20% Held-Out Test Set: 120 Samples)
- **Accuracy:** 100.00%
- **Precision:** 100.00% (Minimizes false alarms on legitimate business emails)
- **Recall:** 100.00% (Ensures active attacks are not missed)
- **F1 Score:** 100.00%

### Confusion Matrix
| Metric | Predicted Legitimate | Predicted Phishing |
| :--- | :---: | :---: |
| **Actual Legitimate** | **60 (True Negative)** | **0 (False Positive)** |
| **Actual Phishing** | **0 (False Negative)** | **60 (True Positive)** |

> **Cybersecurity Note on False Negatives:** A False Negative (missed phishing email) is the most dangerous error in email security because it delivers an active attack directly to an end-user inbox, risking credential theft and network compromise.

---

## 🖥️ Installation & Execution Guide

### Step 1: Navigate to Project Directory
```powershell
cd "C:\Users\Rohit Singh\Desktop\IIT Projects\Cyber Security projects\Phishing-Email-Detection-Awareness-Dashboard"
```

### Step 2: Verify Python Environment
```powershell
python --version
pip --version
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Generate Synthetic Dataset
```powershell
python data/generate_dataset.py
```

### Step 5: Train and Evaluate Machine Learning Model
```powershell
python ml/train_model.py
```

### Step 6: Run Automated Security Test Suite (25 Tests)
```powershell
python tests/test_phishing_system.py
```

### Step 7: Launch the Application
```powershell
python backend/app.py
```
*The server will start at: `http://127.0.0.1:8000`*

### Step 8: Open the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:8000
```

---

## 📡 API Documentation

| Method | Endpoint | Description | Request Payload | Response |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze` | Ingests and scores full email payload | JSON (`sender`, `subject`, `body`, `urls`, `attachment_name`) | JSON (`hybrid_risk_score`, `indicators`, `recommendations`) |
| `POST` | `/api/analyze/url` | Static string audit of a single URL | JSON (`url`) | JSON (`risk_score`, `is_raw_ip`, `findings`) |
| `POST` | `/api/analyze/file` | Parses and analyzes `.txt` or `.eml` file | Multipart form-data (`file`) | JSON (Full analysis + parsed metadata) |
| `GET` | `/api/dashboard/stats` | Returns real-time KPI metrics & chart data | None | JSON (`total_analyzed`, `likely_phishing`, `distribution`) |
| `GET` | `/api/analyses` | Lists forensic audit history | Query params (`search`, `classification`, `limit`) | JSON list of past analyses |
| `GET` | `/api/analyses/{id}` | Fetches full forensic details for an ID | URL Path parameter | JSON record with child indicators & URLs |
| `DELETE` | `/api/analyses/{id}` | Deletes an analysis record from database | URL Path parameter | JSON (`status: success`) |
| `GET` | `/api/health` | API health check endpoint | None | JSON (`status: healthy`) |

---

## 🧪 Automated Testing Suite
The automated test suite (`tests/test_phishing_system.py`) validates **25 security scenarios**:

```
Ran 25 tests in 0.080s
OK (25 Tests Run | 0 Failures | 0 Errors)
```
See [`docs/TESTING_REPORT.md`](docs/TESTING_REPORT.md) for the detailed test matrix.

---

## 🔒 Security, Privacy & Ethics
- **Strictly Defensive:** Built exclusively for defensive analysis, SOC triage practice, and cybersecurity education.
- **No Weaponization:** Does not send real emails, create credential-harvesting forms, or execute malware.
- **Passive Link Inspection:** Analyzes URLs lexically; never fetches or visits external web hosts.
- **Privacy Preservation:** Protects confidentiality by storing only metadata (domains, risk scores, extracted IOCs) rather than raw message bodies.

---

## 📸 Proof of Work & Screenshots Checklist
To showcase this project on GitHub and LinkedIn, capture the following 26 screenshots (saved in `screenshots/`):

1. `01_project_structure.png` - Project directory hierarchy.
2. `02_architecture_diagram.png` - System data flow diagram.
3. `03_synthetic_dataset_csv.png` - Dataset in CSV viewer.
4. `04_dataset_generation_terminal.png` - Output of `data/generate_dataset.py`.
5. `05_email_analyzer_console.png` - Full Email Analyzer interface.
6. `06_legitimate_email_analysis.png` - Low Risk assessment on routine meeting email.
7. `07_urgent_phishing_analysis.png` - High Risk assessment on account suspension lure.
8. `08_sender_forensics_drawer.png` - Expanded sender forensics view.
9. `09_url_forensics_drawer.png` - Expanded URL static analysis findings.
10. `10_attachment_metadata_drawer.png` - Double extension detection (`.pdf.exe`).
11. `11_risk_gauge_high.png` - Threat dial showing 85+/100 High Risk.
12. `12_explainability_indicators.png` - "WHY?" indicator list with severity badges.
13. `13_recommended_playbook.png` - SOC action playbook checklist.
14. `14_dashboard_kpi_cards.png` - Top 5 telemetry metric cards.
15. `15_classification_chart.png` - Donut chart of threat classifications.
16. `16_risk_distribution_chart.png` - Bar chart of risk score bands.
17. `17_top_indicators_chart.png` - Horizontal bar chart of frequent IOCs.
18. `18_timeline_trend_chart.png` - Line chart of recent threat scores.
19. `19_ml_training_terminal.png` - Output of `ml/train_model.py`.
20. `20_confusion_matrix_report.png` - Terminal confusion matrix from `ml/evaluation.py`.
21. `21_awareness_checklist.png` - Interactive "Before You Click" checklist.
22. `22_awareness_microlessons.png` - Training micro-lessons tab view.
23. `23_audit_history_table.png` - Searchable analysis history table.
24. `24_audit_detail_modal.png` - Pop-up modal showing forensic details.
25. `25_automated_tests_terminal.png` - `tests/test_phishing_system.py` passing 25/25 tests.
26. `26_fastapi_interactive_docs.png` - Swagger UI at `http://127.0.0.1:8000/docs`.

---

## 💼 Resume & LinkedIn Proof Points

### Resume Bullet Points:
- **Engineered an end-to-end defensive Phishing Email Detection & Awareness Dashboard** using Python, FastAPI, and SQLite, analyzing sender patterns, language manipulation, static URLs, and attachment metadata.
- **Implemented a hybrid threat scoring engine** fusing deterministic rule-based heuristics with a sublinear TF-IDF Naive Bayes NLP model, achieving 100% precision and recall across 600 synthetic email records.
- **Developed a responsive SOC analytics console & training portal** featuring real-time KPI telemetry, Chart.js visualizations, an interactive "Before You Click" defensive checklist, and 25 passing automated unit tests.

### 2-Line Project Description:
> A defensive cybersecurity platform that combines deterministic threat heuristics with NLP machine learning to detect phishing emails, visualize real-time SOC risk metrics, and train users via interactive awareness micro-lessons.

---

## ⚖️ Disclaimer
*This project is designed strictly for cybersecurity education, research, and defensive threat analysis using synthetic or authorized data. It does not perform active scanning, credential harvesting, or exploitation against any system, individual, or organization.*

---

## 👨‍💻 Author
**Cybersecurity Engineering Student** &bull; Placement-Ready Defensive Security Portfolio Project
