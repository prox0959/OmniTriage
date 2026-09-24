@echo off
title OmniTriage - Live DFIR Incident Response
color 0A
cls
echo ========================================================
echo  OmniTriage USB Live Responder Launcher
echo  Author: Cinar (prox0959)
echo ========================================================
echo.
python omnitriage.py --out .\triage_reports
echo.
echo Triage completed! Check .\triage_reports for HTML and JSON.
pause
