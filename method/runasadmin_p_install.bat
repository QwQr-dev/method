@echo off
fltmc >nul 2>&1 || (
    PowerShell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
python p_install.py
pause