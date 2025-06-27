@echo off
:: ZehraShield Stop Script (Windows)
:: Copyright (c) 2025 ZehraSec - Yashab Alam

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "ZEHRASHIELD_DIR=%SCRIPT_DIR%.."
set "PID_FILE=%ZEHRASHIELD_DIR%\zehrashield.pid"

echo.
echo ========================================
echo  ZehraShield Advanced Firewall System
echo  Stopping Services...
echo  Copyright (c) 2025 ZehraSec
echo ========================================
echo.

:: Check if PID file exists
if not exist "%PID_FILE%" (
    echo [INFO] ZehraShield is not running (no PID file found)
    pause
    exit /b 0
)

:: Read PID from file
set /p PID=<%PID_FILE%

:: Check if process is running
tasklist /FI "PID eq %PID%" 2>nul | find "%PID%" >nul
if !errorlevel! neq 0 (
    echo [INFO] ZehraShield process not found (PID: %PID%)
    echo [INFO] Removing stale PID file...
    del "%PID_FILE%" >nul 2>&1
    pause
    exit /b 0
)

echo [INFO] Stopping ZehraShield (PID: %PID%)...

:: Attempt graceful shutdown first
taskkill /PID %PID% >nul 2>&1

:: Wait a moment
timeout /t 3 /nobreak >nul

:: Check if still running
tasklist /FI "PID eq %PID%" 2>nul | find "%PID%" >nul
if !errorlevel! equ 0 (
    echo [WARNING] Graceful shutdown failed, forcing termination...
    taskkill /F /PID %PID% >nul 2>&1
)

:: Remove PID file
del "%PID_FILE%" >nul 2>&1

echo [SUCCESS] ZehraShield stopped successfully!
echo.
echo ========================================
echo  ZehraShield has been stopped
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
