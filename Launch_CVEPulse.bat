@echo off
title Launching CVEPulse Dashboard
echo ============================================
echo         CVEPulse Launch Assistant
echo ============================================

REM Change directory to backend
cd /d "%~dp0backend"
echo.
echo [1/3] Activating virtual environment...
call venv\Scripts\activate

echo [2/3] Starting backend (FastAPI + Uvicorn)...
start cmd /k "uvicorn app:app --reload --port 8000"

REM Wait a bit to ensure backend starts
timeout /t 4 >nul

echo [3/3] Starting frontend (local web server)...
cd ..\frontend
start cmd /k "python -m http.server 5500"

echo.
echo Opening dashboard in browser...
start http://127.0.0.1:5500

echo.
echo All systems running!  You can close this window.
pause
