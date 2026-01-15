@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo [*] Starting MIDNIGHT MULTI-TOOL Setup...
echo.

echo [*] Running setup.py...
python setup.py

if errorlevel 1 (
    echo.
    echo [ERROR] Setup failed!
    echo.
    pause
    exit /b 1
)

echo.
echo [*] Setup completed successfully!
echo.
pause
