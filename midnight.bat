@echo off
chcp 65001 >nul
cd /d "%~dp0"

python main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Application exited with error code %errorlevel%
    echo.
    pause >nul
    exit /b %errorlevel%
)