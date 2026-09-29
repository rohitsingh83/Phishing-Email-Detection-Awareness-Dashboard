# GitHub Repository Strategy & Upload Commands

## 1. Repository Metadata
- **Repository Name:** `Phishing-Email-Detection-Awareness-Dashboard`
- **Short Description:** *"Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments."*
- **Visibility:** Public
- **License:** MIT

### Recommended GitHub Topics / Tags:
```
cybersecurity
phishing-detection
email-security
soc
python
fastapi
nlp
threat-detection
security-awareness
url-analysis
defensive-security
mitre-attack
```

---

## 2. Git Initialization & 15 Progressive Commits

Run the following commands inside the project directory:

```bash
cd "C:\Users\Rohit Singh\Desktop\IIT Projects\Cyber Security projects\Phishing-Email-Detection-Awareness-Dashboard"

# Initialize Git
git init

# Commit 1: Project Setup & Base Architecture
git add requirements.txt .gitignore .env.example
git commit -m "Initialize phishing detection project and environment configuration"

# Commit 2: Dataset Generator
git add data/
git commit -m "Add synthetic email dataset generator with 600 balanced records"

# Commit 3: Preprocessing Utility
git add backend/utils/
git commit -m "Implement email preprocessing and forensic artifact extraction"

# Commit 4: Sender Forensics
git add backend/services/sender_analyzer.py
git commit -m "Add sender analysis module for typosquatting and display-name spoofing"

# Commit 5: Content & Psychology Analyzer
git add backend/services/content_analyzer.py
git commit -m "Implement phishing content analyzer for urgency, fear, and credential harvesting"

# Commit 6: Static URL Inspector
git add backend/services/url_analyzer.py
git commit -m "Add static URL risk analysis for raw IPs, schemes, and keyword stuffing"

# Commit 7: Attachment Metadata Analyzer
git add backend/services/attachment_analyzer.py
git commit -m "Implement attachment filename analysis for executables and double extensions"

# Commit 8: Feature Extraction & Rule Engine
git add backend/services/feature_extractor.py backend/services/risk_engine.py
git commit -m "Build multi-vector feature extraction and weighted phishing risk scoring engine"

# Commit 9: Machine Learning Pipeline
git add ml/ models/
git commit -m "Add TF-IDF vectorizer and Multinomial Naive Bayes classifier with evaluation metrics"

# Commit 10: Hybrid Fusion Engine
git add backend/services/hybrid_detector.py
git commit -m "Implement hybrid threat fusion combining rule heuristics and ML probabilities"

# Commit 11: Database Persistence
git add backend/database.py backend/models/
git commit -m "Implement SQLite database persistence for audit trail and telemetry"

# Commit 12: REST API Endpoints
git add backend/app.py backend/routes/
git commit -m "Create FastAPI REST API routes for email, URL, file analysis, and dashboard stats"

# Commit 13: Web Console & Telemetry
git add frontend/
git commit -m "Build modern SOC dashboard with live risk gauge, telemetry charts, and awareness module"

# Commit 14: Sample Vectors & Test Suite
git add samples/ tests/
git commit -m "Add synthetic test emails and comprehensive 25-scenario automated testing suite"

# Commit 15: Documentation & Project Report
git add docs/ reports/ README.md
git commit -m "Complete professional README, SOC playbooks, project report, and interview prep"
```

---

## 3. Pushing to Remote GitHub Repository

```bash
# Link your personal remote GitHub repository:
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/Phishing-Email-Detection-Awareness-Dashboard.git

# Set main branch and push
git branch -M main
git push -u origin main
```
