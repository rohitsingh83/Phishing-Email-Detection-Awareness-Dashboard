"""
Script to automatically capture high-resolution screenshots of the
PhishShield Web Platform and Terminal Verification outputs for GitHub README.
"""

import os
import time
import subprocess
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

SCREENSHOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

HTML_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "index.html")
FILE_URL = "file:///" + HTML_FILE_PATH.replace("\\", "/")

def get_headless_driver(width=1600, height=1050):
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument(f"--window-size={width},{height}")
    options.add_argument("--hide-scrollbars")
    return webdriver.Chrome(options=options)

def js_click(driver, element):
    driver.execute_script("arguments[0].click();", element)

def capture_dashboard_views():
    print(f"[*] Launching Chrome headless on {FILE_URL}...")
    driver = get_headless_driver(1600, 1050)
    try:
        driver.get(FILE_URL)
        time.sleep(2)  # allow charts and data to render

        # 1. Hero Overview (Top Navigation, KPIs, Empty Analyzer)
        p1 = os.path.join(SCREENSHOTS_DIR, "01_hero_overview.png")
        driver.save_screenshot(p1)
        print(f"[+] Saved: {p1}")

        # 2. Trigger Urgent Phishing Preset and click Analyze
        btn_phish = driver.find_element(By.ID, "load-sample-phish-urgent")
        js_click(driver, btn_phish)
        time.sleep(0.5)

        btn_analyze = driver.find_element(By.ID, "btn-analyze")
        js_click(driver, btn_analyze)
        time.sleep(2.0)  # wait for gauge animation and indicator rendering

        # Scroll slightly to center the results panel
        results_panel = driver.find_element(By.ID, "results-panel")
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'center'});", results_panel)
        time.sleep(1.0)

        p2 = os.path.join(SCREENSHOTS_DIR, "02_phishing_analysis_threat_gauge.png")
        driver.save_screenshot(p2)
        print(f"[+] Saved: {p2}")

        # 3. Trigger Legitimate Meeting Preset and Analyze
        btn_legit = driver.find_element(By.ID, "load-sample-legit")
        js_click(driver, btn_legit)
        time.sleep(0.5)

        js_click(driver, btn_analyze)
        time.sleep(2.0)

        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'center'});", results_panel)
        time.sleep(1.0)

        p3 = os.path.join(SCREENSHOTS_DIR, "03_legitimate_email_analysis.png")
        driver.save_screenshot(p3)
        print(f"[+] Saved: {p3}")

        # 4. Scroll to SOC Telemetry Dashboard (all 6 Chart.js graphs)
        dashboard_section = driver.find_element(By.ID, "dashboard-section")
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'start'});", dashboard_section)
        time.sleep(2.0)

        p4 = os.path.join(SCREENSHOTS_DIR, "04_soc_telemetry_dashboard.png")
        driver.save_screenshot(p4)
        print(f"[+] Saved: {p4}")

        # 5. Scroll to Awareness & Training Module
        awareness_section = driver.find_element(By.ID, "awareness-section")
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'start'});", awareness_section)
        time.sleep(1.5)

        p5 = os.path.join(SCREENSHOTS_DIR, "05_security_awareness_training.png")
        driver.save_screenshot(p5)
        print(f"[+] Saved: {p5}")

        # 6. Scroll to Forensic Audit History
        history_section = driver.find_element(By.ID, "history-section")
        driver.execute_script("arguments[0].scrollIntoView({behavior: 'instant', block: 'start'});", history_section)
        time.sleep(1.5)

        p6 = os.path.join(SCREENSHOTS_DIR, "06_forensic_audit_history.png")
        driver.save_screenshot(p6)
        print(f"[+] Saved: {p6}")

    finally:
        driver.quit()

def capture_terminal_outputs():
    """Generates clean HTML terminal mockups and renders them to PNG for test and ML verification."""
    print("[*] Generating terminal verification graphics...")

    # Run tests
    test_proc = subprocess.run(["python", "tests/test_phishing_system.py"], capture_output=True, text=True)
    test_out = test_proc.stdout + test_proc.stderr

    # Run ML evaluation
    ml_proc = subprocess.run(["python", "ml/train_model.py"], capture_output=True, text=True)
    ml_out = ml_proc.stdout + ml_proc.stderr

    def make_terminal_html(title, command, text):
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{
    background: #0b0f19;
    margin: 0;
    padding: 30px;
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    display: flex;
    justify-content: center;
    align-items: center;
  }}
  .window {{
    width: 1100px;
    background: #0d1322;
    border-radius: 12px;
    border: 1px solid #1e293b;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    overflow: hidden;
  }}
  .titlebar {{
    background: #131c31;
    padding: 12px 18px;
    display: flex;
    align-items: center;
    border-bottom: 1px solid #1e293b;
  }}
  .dots {{
    display: flex;
    gap: 8px;
    margin-right: 16px;
  }}
  .dot {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }}
  .dot-red {{ background: #ef4444; }}
  .dot-yellow {{ background: #f59e0b; }}
  .dot-green {{ background: #10b981; }}
  .title {{
    color: #94a3b8;
    font-size: 13px;
    font-weight: 600;
  }}
  .content {{
    padding: 24px;
    color: #e2e8f0;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-all;
  }}
  .prompt {{
    color: #10b981;
    font-weight: bold;
  }}
  .highlight {{
    color: #38bdf8;
  }}
</style>
</head>
<body>
  <div class="window">
    <div class="titlebar">
      <div class="dots">
        <div class="dot dot-red"></div>
        <div class="dot dot-yellow"></div>
        <div class="dot dot-green"></div>
      </div>
      <div class="title">{title}</div>
    </div>
    <div class="content"><span class="prompt">PS C:\\Users\\rohit\\PhishShield&gt;</span> <span class="highlight">{command}</span>\n\n{text}</div>
  </div>
</body>
</html>"""

    tmp_test_html = os.path.join(SCREENSHOTS_DIR, "_tmp_test.html")
    with open(tmp_test_html, "w", encoding="utf-8") as f:
        f.write(make_terminal_html("PowerShell - Security Test Suite Verification (25 Scenarios)", "python tests/test_phishing_system.py", test_out))

    tmp_ml_html = os.path.join(SCREENSHOTS_DIR, "_tmp_ml.html")
    with open(tmp_ml_html, "w", encoding="utf-8") as f:
        f.write(make_terminal_html("PowerShell - TF-IDF & Naive Bayes Training & Classification Report", "python ml/train_model.py", ml_out))

    driver = get_headless_driver(1200, 780)
    try:
        driver.get("file:///" + tmp_test_html.replace("\\", "/"))
        time.sleep(1)
        p7 = os.path.join(SCREENSHOTS_DIR, "07_automated_tests_terminal.png")
        driver.save_screenshot(p7)
        print(f"[+] Saved: {p7}")

        driver.get("file:///" + tmp_ml_html.replace("\\", "/"))
        time.sleep(1)
        p8 = os.path.join(SCREENSHOTS_DIR, "08_ml_training_evaluation.png")
        driver.save_screenshot(p8)
        print(f"[+] Saved: {p8}")
    finally:
        driver.quit()
        if os.path.exists(tmp_test_html):
            os.remove(tmp_test_html)
        if os.path.exists(tmp_ml_html):
            os.remove(tmp_ml_html)

if __name__ == "__main__":
    capture_dashboard_views()
    capture_terminal_outputs()
    print("[✓] All screenshots successfully captured and saved in screenshots/ directory.")
