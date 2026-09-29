# Screenshot & Visual Proof Catalog

This folder contains visual proof-of-work documentation demonstrating full system execution. Use these screenshots for your GitHub repository README, portfolio presentation, and LinkedIn showcase.

---

## 📸 26 Required Screenshot Checkpoints

| # | Filename | Visual Subject / View | What it Proves |
| :-: | :--- | :--- | :--- |
| **01** | `01_project_structure.png` | VS Code / File Explorer tree view | Professional modular project folder hierarchy. |
| **02** | `02_architecture_diagram.png` | Architecture flow diagram from `docs/ARCHITECTURE.md` | Clear end-to-end design and engineering rigor. |
| **03** | `03_synthetic_dataset_csv.png` | CSV view of `data/phishing_email_dataset.csv` | 600 safe, balanced legitimate and phishing records. |
| **04** | `04_dataset_generation_terminal.png` | Terminal running `python data/generate_dataset.py` | Programmatic data synthesis using RFC reserved domains. |
| **05** | `05_email_analyzer_console.png` | Browser at `http://127.0.0.1:8000` (Full UI) | Clean, responsive cybersecurity web console. |
| **06** | `06_legitimate_email_analysis.png` | Analysis of meeting notice (`SAFE / LOW RISK`) | Low threat scoring on authentic communications. |
| **07** | `07_urgent_phishing_analysis.png` | Analysis of suspension lure (`HIGH RISK`) | High threat scoring on credential and time-pressure attacks. |
| **08** | `08_sender_forensics_drawer.png` | Expanded "Sender Forensics" accordion | Typosquatting and display-name spoofing detection. |
| **09** | `09_url_forensics_drawer.png` | Expanded "URL Static String Analysis" accordion | Detection of raw IP hostnames, unencrypted HTTP, and length. |
| **10** | `10_attachment_metadata_drawer.png` | Expanded "Attachment Metadata" accordion | Double extension masquerading detection (`.pdf.exe`). |
| **11** | `11_risk_gauge_high.png` | Close-up of threat score dial (80+/100) | Visual threat dial and color-coded risk meter. |
| **12** | `12_explainability_indicators.png` | Close-up of "Forensic Indicators (WHY?)" list | Explainable security decisions with severity tags. |
| **13** | `13_recommended_playbook.png` | Close-up of "Recommended SOC Playbook" | Actionable guidance and mitigation steps. |
| **14** | `14_dashboard_kpi_cards.png` | Top 5 KPI telemetry metric cards | Real-time counts of total, phishing, and average risk. |
| **15** | `15_classification_chart.png` | Chart.js doughnut chart | Visual distribution of threat classifications. |
| **16** | `16_risk_distribution_chart.png` | Chart.js bar chart of risk bands (0-20, 21-40, etc.) | Statistical distribution across threat tiers. |
| **17** | `17_top_indicators_chart.png` | Horizontal bar chart of top indicators | High-frequency IOC tracking across all scanned emails. |
| **18** | `18_timeline_trend_chart.png` | Chart.js line chart of threat score timeline | Telemetry trend monitoring over time. |
| **19** | `19_ml_training_terminal.png` | Terminal running `python ml/train_model.py` | Execution of sublinear TF-IDF + Naive Bayes training. |
| **20** | `20_confusion_matrix_report.png` | Terminal running `python ml/evaluation.py` | Tabular confusion matrix, 100% precision & recall. |
| **21** | `21_awareness_checklist.png` | Interactive "Before You Click" checklist | Practical defensive habit reinforcement. |
| **22** | `22_awareness_microlessons.png` | Active micro-lessons tabs (Hovering, HTTPS myth) | Bite-sized cybersecurity employee training. |
| **23** | `23_audit_history_table.png` | Searchable analysis history data table | Relational SQLite audit trail with search and filtering. |
| **24** | `24_audit_detail_modal.png` | Pop-up modal showing forensic record details | In-depth historical investigation capabilities. |
| **25** | `25_automated_tests_terminal.png` | Terminal running `python tests/test_phishing_system.py` | All 25 automated security tests passing in 0.08s. |
| **26** | `26_fastapi_interactive_docs.png` | Browser at `http://127.0.0.1:8000/docs` | Live Swagger UI documenting all REST API endpoints. |

---

## 💡 Capturing Instructions
1. Run `python backend/app.py` and open `http://127.0.0.1:8000`.
2. Use Windows Snipping Tool (`Win + Shift + S`) to capture the targeted regions.
3. Save each screenshot directly into this `screenshots/` directory matching the exact filename listed above.
