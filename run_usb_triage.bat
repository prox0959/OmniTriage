@echo off
title OmniTriage - Live DFIR Incident Response (RFC 3227)
color 0A
cls
echo ========================================================
echo  OmniTriage v1.1.0 USB Live Responder Launcher
echo  Author: Cinar (prox0959)
echo ========================================================
echo.

:: Check for portable Python Embeddable runtime on the USB drive first
if exist "%~dp0python\python.exe" (
    echo [*] Utilizing portable USB Python runtime (%~dp0python\python.exe)...
    "%~dp0python\python.exe" "%~dp0omnitriage.py" --out "%~dp0triage_reports"
) else (
    echo [*] Utilizing host system Python runtime...
    python "%~dp0omnitriage.py" --out "%~dp0triage_reports"
)

echo.
echo ========================================================
echo  Triage completed! Check .\triage_reports for reports.
echo ========================================================
pause
