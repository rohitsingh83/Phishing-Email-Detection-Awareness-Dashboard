# System Architecture & Technical Specifications

## 1. Architectural Overview

The **Phishing Email Detection & Awareness Dashboard (PhishShield)** is engineered as a defensive cybersecurity platform that combines deterministic rule-based threat heuristics with statistical Machine Learning (TF-IDF + Multinomial Naive Bayes) to deliver transparent, explainable threat scoring.

```
+-------------------------------------------------------------------------+
|                              USER INTERFACE                             |
|    Web Dashboard (HTML5 / Tailwind CSS / Vanilla JS / Chart.js Telemetry) |
+-------------------------------------------------------------------------+
                                   |
                 HTTP REST API Requests (JSON / Multipart)
                                   v
+-------------------------------------------------------------------------+
|                             FASTAPI BACKEND                             |
|  - CORS Middleware & Static Server                                      |
|  - /api/analyze (Hybrid Ingestion)                                      |
|  - /api/analyze/url (Static Link Auditing)                              |
|  - /api/analyze/file (.EML / .TXT Parsing)                              |
|  - /api/dashboard/stats & /api/analyses (Telemetry & Audit Trail)       |
+-------------------------------------------------------------------------+
                                   |
                 Normalized Forensic Payload & Metadata
                                   v
+-------------------------------------------------------------------------+
|                       FORENSIC EXTRACTION ENGINE                        |
|                                                                         |
|  +--------------------+  +--------------------+  +--------------------+ |
|  |  Sender Analyzer   |  |  Content Analyzer  |  |    URL Analyzer    | |
|  | - Spoofing checks  |  | - Urgency/Fear     |  | - Raw IP detection | |
|  | - Lookalike typos  |  | - Credential lures |  | - Deceptive schemes| |
|  | - Subdomain depth  |  | - Generic greetings|  | - Static string lex| |
|  +--------------------+  +--------------------+  +--------------------+ |
|                                   |                                     |
|  +--------------------+  +--------------------+                         |
|  | Attachment Analyzer|  | NLP Feature Vector |                         |
|  | - Double extension |  | - Stylistic stats  |                         |
|  | - Executable flags |  | - Shouting/Exclaim |                         |
|  +--------------------+  +--------------------+                         |
+-------------------------------------------------------------------------+
                    |                                 |
           Forensic Artifacts                N-Gram Token Matrix
                    v                                 v
+-----------------------------+     +-------------------------------------+
|   RULE-BASED THREAT ENGINE  |     |      MACHINE LEARNING PIPELINE      |
|  - Multi-vector weightings  |     |  - Sublinear TF-IDF Vectorizer      |
|  - Dynamic risk capping     |     |  - Multinomial Naive Bayes (Laplace)|
|  - Explanatory findings     |     |  - Log-odds probability inference   |
+-----------------------------+     +-------------------------------------+
                    \                                 /
                     \                               /
            Rule Score (0-100)              ML Probability (0.0-1.0)
                       \                           /
                        v                         v
+-------------------------------------------------------------------------+
|                         HYBRID THREAT SCORER                            |
|             Hybrid Score = (Rule_Score * 0.55) + (ML_Score * 0.45)      |
|                                                                         |
|  Classification Bands:                                                  |
|  - 0-20  : SAFE / LOW RISK                                              |
|  - 21-40 : MODERATE RISK                                                |
|  - 41-70 : SUSPICIOUS                                                   |
|  - 71-100: HIGH RISK / LIKELY PHISHING                                  |
+-------------------------------------------------------------------------+
                                   |
           Audit Logging & Real-Time Telemetry Synchronization
                                   v
+-------------------------------------------------------------------------+
|                         SQLITE METADATA DATABASE                        |
|  - `analyses` (Forensic scores, domain, timestamp, classification)     |
|  - `indicators` (Relational child table of categorized threat signals)  |
|  - `url_analyses` (Static URL inspection records & findings)            |
+-------------------------------------------------------------------------+
```

---

## 2. Multi-Vector Scoring Formulation

The hybrid risk score $S_{\text{hybrid}}$ balances deterministic heuristics with learned statistical patterns:

$$S_{\text{hybrid}} = \min\left(100, \max\left(0, \text{round}\left(w_{\text{rule}} \cdot S_{\text{rule}} + w_{\text{ml}} \cdot S_{\text{ml}}\right)\right)\right)$$

Where:
- $w_{\text{rule}} = 0.55$ (Expert rules provide decisive, explainable evidence for critical IOCs).
- $w_{\text{ml}} = 0.45$ (Statistical model captures semantic phrasing patterns).
- $S_{\text{rule}} = \sum_{i} \text{Points}_i$ capped at 100.
- $S_{\text{ml}} = \text{round}(P(\text{Phishing} \mid \text{Tokens}) \times 100)$.

---

## 3. Database Entity Relationship (ER) Model

```
+----------------------------------+          +----------------------------------+
|            ANALYSES              |          |            INDICATORS            |
+----------------------------------+          +----------------------------------+
| PK analysis_id    INTEGER (AUTO) |<----+    | PK indicator_id   INTEGER (AUTO) |
|    sender_domain  TEXT           |     |    | FK analysis_id    INTEGER        |
|    subject        TEXT           |     |    |    category       TEXT           |
|    risk_score     INTEGER        |     |    |    severity       TEXT           |
|    classification TEXT           |     |    |    title          TEXT           |
|    risk_level     TEXT           |     |    |    description    TEXT           |
|    ml_probability REAL           |     |    +----------------------------------+
|    created_at     DATETIME       |     |
+----------------------------------+     |    +----------------------------------+
                                         |    |           URL_ANALYSES           |
                                         |    +----------------------------------+
                                         +--->| PK url_analysis_id INTEGER(AUTO) |
                                              | FK analysis_id     INTEGER       |
                                              |    url_safe_repr   TEXT          |
                                              |    risk_score      INTEGER       |
                                              |    findings        TEXT (JSON)   |
                                              +----------------------------------+
```
