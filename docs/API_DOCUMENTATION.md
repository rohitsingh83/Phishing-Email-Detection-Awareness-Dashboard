# REST API Specification & Security Engineering Reference

**Base URL:** `http://127.0.0.1:8000/api`  
**Interactive Swagger UI:** `http://127.0.0.1:8000/docs`  
**ReDoc Specification:** `http://127.0.0.1:8000/redoc`

---

## 1. Global Security & Validation Architecture

- **CORS Policy:** Configured for cross-origin access during local development (`*`). In production, this must be restricted to verified dashboard domains.
- **Defensive Size Limits:** File uploads are restricted to a maximum of **2 MB** to prevent denial-of-service (DoS) via resource exhaustion.
- **Passive Link Inspection:** URL endpoints perform lexical string manipulation without establishing external TCP sockets.
- **Input Validation:** Enforced via Pydantic v2 schemas; rejects malformed payloads with descriptive `422 Unprocessable Entity` or `400 Bad Request`.
- **Status Codes:**
  - `200 OK`: Request succeeded; forensic results returned.
  - `400 Bad Request`: Missing mandatory parameters or invalid file extensions.
  - `404 Not Found`: Target analysis record does not exist in SQLite database.
  - `413 Payload Too Large`: Uploaded file exceeds 2 MB safety cap.
  - `422 Unprocessable Entity`: Schema validation error.
  - `500 Internal Server Error`: Unhandled parsing or pipeline exception.

---

## 2. API Endpoints

### 2.1 Ingest & Analyze Full Email
- **HTTP Method:** `POST`
- **Endpoint:** `/api/analyze`
- **Description:** Parses email attributes, extracts multi-vector forensic indicators, executes rule-based and ML threat evaluation, saves the audit record to SQLite, and returns an explainable threat assessment.
- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
```json
{
  "sender": "security-alert@account-verify.invalid.test",
  "subject": "URGENT: Immediate Account Verification Required Within 24 Hours",
  "body": "Dear Valued Customer, please confirm your credentials immediately at http://198.51.100.10/login to avoid suspension.",
  "urls": "http://198.51.100.10/login",
  "attachment_name": "Notice.pdf.exe"
}
```
- **Response (`200 OK`):**
```json
{
  "analysis_id": 31,
  "hybrid_risk_score": 88,
  "classification": "HIGH RISK / LIKELY PHISHING",
  "risk_level": "HIGH",
  "rule_engine": {
    "score": 85,
    "classification": "HIGH RISK / LIKELY PHISHING",
    "score_breakdown": [
      { "factor": "Sender Domain / Impersonation Risk", "points": 15 },
      { "factor": "Urgent Time-Pressure Language", "points": 10 },
      { "factor": "Credential Verification Request", "points": 20 },
      { "factor": "Suspicious URL Structure", "points": 15 },
      { "factor": "High-Risk Attachment", "points": 25 }
    ]
  },
  "machine_learning": {
    "ml_probability": 0.9999,
    "ml_score": 100,
    "ml_label": "PHISHING",
    "confidence_percent": 99.99,
    "matched_phishing_tokens": ["urgent", "verify", "account", "login", "password"]
  },
  "indicators": [
    {
      "category": "Sender",
      "severity": "HIGH",
      "title": "Suspicious Sender Identity",
      "description": "Sender domain contains unusual pattern."
    },
    {
      "category": "URL",
      "severity": "CRITICAL",
      "title": "Raw IP Address in URL",
      "description": "URL links directly to a numerical IP address instead of an authenticated domain."
    }
  ],
  "recommendations": [
    "Do NOT click any hyperlinks contained within this email.",
    "Do NOT download or open the attachment 'Notice.pdf.exe'.",
    "Report this message immediately to your organization's Security Operations Center (SOC)."
  ]
}
```

---

### 2.2 Static URL String Analysis
- **HTTP Method:** `POST`
- **Endpoint:** `/api/analyze/url`
- **Description:** Performs zero-network static string analysis on a single URL.
- **Request Body:**
```json
{
  "url": "http://198.51.100.10/verify-account"
}
```
- **Response (`200 OK`):**
```json
{
  "url": "http://198.51.100.10/verify-account",
  "scheme": "http",
  "hostname": "198.51.100.10",
  "is_raw_ip": true,
  "subdomain_count": 0,
  "length": 34,
  "risk_score": 55,
  "findings": [
    {
      "type": "UNENCRYPTED_HTTP",
      "severity": "MEDIUM",
      "description": "URL uses unencrypted HTTP scheme instead of HTTPS."
    },
    {
      "type": "RAW_IP_HOSTNAME",
      "severity": "CRITICAL",
      "description": "Host is a raw numerical IP address (198.51.100.10), commonly used to bypass domain reputation checks."
    }
  ]
}
```

---

### 2.3 Upload and Analyze Sample File (.eml / .txt)
- **HTTP Method:** `POST`
- **Endpoint:** `/api/analyze/file`
- **Description:** Ingests an `.eml` or `.txt` file, extracts headers and attachments via Python's standard `email` library, triggers the hybrid engine, and records the audit event.
- **Content-Type:** `multipart/form-data`
- **Form Param:** `file: [binary blob]`
- **Response (`200 OK`):** Full `EmailAnalysisResponse` including `parsed_metadata`.

---

### 2.4 Get Dashboard Telemetry & KPI Stats
- **HTTP Method:** `GET`
- **Endpoint:** `/api/dashboard/stats`
- **Description:** Computes aggregated KPI metrics, risk distributions, indicator frequencies, keyword counts, and recent trends for dashboard charts.
- **Response (`200 OK`):**
```json
{
  "total_analyzed": 30,
  "likely_phishing": 10,
  "suspicious": 5,
  "low_risk": 15,
  "average_risk_score": 38.6,
  "phishing_vs_legitimate": {
    "phishing_threats": 15,
    "legitimate_emails": 15
  },
  "distribution": {
    "safe_low": 15,
    "moderate": 0,
    "suspicious": 5,
    "high_risk": 10
  },
  "top_indicators": [
    { "title": "Raw IP Address in URL", "count": 6 },
    { "title": "Dangerous Attachment", "count": 4 }
  ],
  "top_keywords": [
    { "keyword": "Urgent", "count": 12 },
    { "keyword": "Verify", "count": 10 }
  ],
  "recent_trend": [
    { "time": "2026-09-29 10:20", "score": 80, "classification": "HIGH RISK / LIKELY PHISHING" }
  ]
}
```

---

### 2.5 Audit History Retrieval
- **HTTP Method:** `GET`
- **Endpoint:** `/api/analyses`
- **Query Parameters:**
  - `search` (Optional): String query filtering `subject` or `sender_domain`.
  - `classification` (Optional): Filter string (`HIGH RISK`, `SUSPICIOUS`, `LOW RISK`).
  - `sort_by` (Optional): Field to sort by (`created_at`, `risk_score`).
  - `limit` (Optional, Default: 50): Number of records.
  - `offset` (Optional, Default: 0): Pagination offset.
- **Response (`200 OK`):**
```json
{
  "total": 30,
  "analyses": [
    {
      "analysis_id": 30,
      "sender_domain": "account-verify.invalid.test",
      "subject": "URGENT: Immediate Account Verification Required",
      "risk_score": 80,
      "classification": "HIGH RISK / LIKELY PHISHING",
      "risk_level": "HIGH",
      "ml_probability": 0.9999,
      "created_at": "2026-09-29 10:20:04"
    }
  ]
}
```

---

### 2.6 View Single Analysis Record
- **HTTP Method:** `GET`
- **Endpoint:** `/api/analyses/{id}`
- **Response (`200 OK`):** Returns complete record including all relational indicators and URL records.

---

### 2.7 Delete Analysis Record
- **HTTP Method:** `DELETE`
- **Endpoint:** `/api/analyses/{id}`
- **Description:** Cascades deletion across `analyses`, `indicators`, and `url_analyses`.
- **Response (`200 OK`):**
```json
{
  "status": "success",
  "message": "Analysis ID 30 deleted successfully."
}
```
