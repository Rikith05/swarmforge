@echo off
title SwarmForge Web Studio
cd /d "%~dp0"
echo ======================================================================
echo   Starting SwarmForge Web Studio & Policy Firewall Studio...
echo ======================================================================

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3.11 run_studio.py
    if %ERRORLEVEL% neq 0 (
        python run_studio.py
    )
) else (
    python run_studio.py
)

pause
