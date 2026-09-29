# PhishShield PowerShell Launcher
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   PHISHSHIELD: PHISHING EMAIL DETECTION & SOC AWARENESS DASHBOARD   " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Python
Write-Host "[1/3] Checking Python Environment..." -ForegroundColor Yellow
python --version

# Verify Model
if (-not (Test-Path "models\phishing_ml_model.json")) {
    Write-Host "[2/3] Training Machine Learning Model..." -ForegroundColor Yellow
    python ml\train_model.py
} else {
    Write-Host "[2/3] Model Artifacts Verified." -ForegroundColor Green
}

# Launch Browser after short delay
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:8000"
} | Out-Null

Write-Host "[3/3] Starting Server at http://127.0.0.1:8000 ..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate the server." -ForegroundColor Gray
python backend\app.py
