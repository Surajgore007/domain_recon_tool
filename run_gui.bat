@echo off
title OSINT Recon Web Dashboard
echo ========================================================
echo   Starting OSINT Recon Web Dashboard...
echo ========================================================

if exist ".venv\Scripts\python.exe" (
    echo Using virtual environment Python...
    start http://127.0.0.1:8000
    .venv\Scripts\python.exe app.py
) else (
    echo Using system Python...
    start http://127.0.0.1:8000
    python app.py
)

pause
