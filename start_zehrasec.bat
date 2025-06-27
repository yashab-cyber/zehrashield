@echo off
:: ZehraShield Startup Script (Windows)
:: Copyright (c) 2025 ZehraSec - Yashab Alam

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "ZEHRASHIELD_DIR=%SCRIPT_DIR%.."
set "PID_FILE=%ZEHRASHIELD_DIR%\zehrashield.pid"
set "LOG_FILE=%ZEHRASHIELD_DIR%\logs\startup.log"

echo.
echo ========================================
echo  ZehraShield Advanced Firewall System
echo  Copyright (c) 2025 ZehraSec
echo  Developed by Yashab Alam
echo ========================================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Not running as administrator. Some features may not work.
    echo [WARNING] Consider running as administrator for full functionality.
    echo.
)

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo [ERROR] Please install Python 3.8+ and try again
    pause
    exit /b 1
)

:: Create logs directory
if not exist "%ZEHRASHIELD_DIR%\logs" mkdir "%ZEHRASHIELD_DIR%\logs"

:: Check if already running
if exist "%PID_FILE%" (
    set /p EXISTING_PID=<%PID_FILE%
    tasklist /FI "PID eq !EXISTING_PID!" 2>nul | find "!EXISTING_PID!" >nul
    if !errorlevel! equ 0 (
        echo [WARNING] ZehraShield is already running (PID: !EXISTING_PID!)
        echo [INFO] Web console: https://localhost:8443
        pause
        exit /b 0
    ) else (
        echo [WARNING] Stale PID file found, removing...
        del "%PID_FILE%" >nul 2>&1
    )
)

:: Navigate to ZehraShield directory
cd /d "%ZEHRASHIELD_DIR%"

:: Check for virtual environment
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
)

:: Check configuration
if not exist "config\firewall.json" (
    echo [WARNING] Configuration file not found. Using defaults.
)

echo [INFO] Starting ZehraShield Advanced Firewall...
echo [INFO] This may take a few moments...
echo.

:: Start ZehraShield
start /B python main.py --daemon > "%LOG_FILE%" 2>&1

:: Wait a moment for startup
timeout /t 3 /nobreak >nul

:: Check if process started successfully
python -c "
import psutil, sys, time
time.sleep(2)
found = False
for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
    try:
        if 'python' in proc.info['name'].lower() and 'main.py' in ' '.join(proc.info['cmdline']):
            with open('%PID_FILE%', 'w') as f:
                f.write(str(proc.info['pid']))
            print('[SUCCESS] ZehraShield started successfully!')
            print('[INFO] PID:', proc.info['pid'])
            print('[INFO] Log file: %LOG_FILE%')
            print('[INFO] Web console: https://localhost:8443')
            print('[INFO] Default credentials: admin / zehrasec123')
            found = True
            break
    except:
        continue
if not found:
    print('[ERROR] Failed to start ZehraShield')
    print('[ERROR] Check log file: %LOG_FILE%')
    sys.exit(1)
"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Startup failed. Check the log file for details.
    echo [INFO] Log file: %LOG_FILE%
    pause
    exit /b 1
)

echo.
echo ========================================
echo  ZehraShield is now running!
echo ========================================
echo.
echo Web Management Console:
echo   URL: https://localhost:8443
echo   Username: admin
echo   Password: zehrasec123
echo.
echo To stop ZehraShield, close this window or run:
echo   stop_zehrasec.bat
echo.
echo Press any key to close this window...
pause >nul
