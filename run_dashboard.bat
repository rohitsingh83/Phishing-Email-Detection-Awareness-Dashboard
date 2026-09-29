@echo off
title Phishing Email Detection & Security Awareness Dashboard
color 0A

echo ======================================================================
echo    PHISHSHIELD: PHISHING EMAIL DETECTION & SOC AWARENESS DASHBOARD
echo ======================================================================
echo.
echo [1/3] Checking Python Environment...
python --version
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+.
    pause
    exit /b
)

echo [2/3] Checking Model Artifacts and Database...
if not exist "models\phishing_ml_model.json" (
    echo Training Machine Learning Model...
    python ml\train_model.py
)

echo [3/3] Launching PhishShield Server on http://127.0.0.1:8000 ...
echo Opening your web browser in 3 seconds...
start "" timeout /t 3 /nobreak >nul & start http://127.0.0.1:8000

python backend\app.py
pause
