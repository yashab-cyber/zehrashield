# ZehraShield PowerShell Installation Script
# Copyright (c) 2025 ZehraSec - Yashab Alam
# Windows Enterprise Installation

param(
    [switch]$NoService,
    [switch]$Development,
    [string]$InstallPath = "C:\Program Files\ZehraSec\ZehraShield"
)

# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ZehraShield Advanced Firewall System" -ForegroundColor Cyan
Write-Host " Windows Enterprise Installation" -ForegroundColor Cyan
Write-Host " Copyright (c) 2025 ZehraSec" -ForegroundColor Cyan
Write-Host " Developed by Yashab Alam" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[INFO] Found Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "[ERROR] Please install Python 3.8+ from https://python.org" -ForegroundColor Red
    exit 1
}

# Check pip
try {
    pip --version | Out-Null
    Write-Host "[INFO] pip is available" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] pip is not available" -ForegroundColor Red
    exit 1
}

# Install Python dependencies
Write-Host "[INFO] Installing Python dependencies..." -ForegroundColor Yellow
try {
    if (Test-Path "requirements.txt") {
        pip install -r requirements.txt
        Write-Host "[SUCCESS] Base dependencies installed" -ForegroundColor Green
    }
    
    if (Test-Path "requirements_advanced.txt") {
        pip install -r requirements_advanced.txt
        Write-Host "[SUCCESS] Advanced dependencies installed" -ForegroundColor Green
    }
} catch {
    Write-Host "[ERROR] Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Create installation directory (if different from current)
if ($InstallPath -ne (Get-Location).Path) {
    Write-Host "[INFO] Creating installation directory: $InstallPath" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    
    # Copy files to installation directory
    Write-Host "[INFO] Copying files to installation directory..." -ForegroundColor Yellow
    Copy-Item -Path ".\*" -Destination $InstallPath -Recurse -Force
    Set-Location $InstallPath
}

# Create necessary directories
$directories = @("logs", "data", "backups", "temp", "certs")
foreach ($dir in $directories) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-Host "[INFO] Created directory: $dir" -ForegroundColor Green
}

# Configure Windows Firewall exceptions
Write-Host "[INFO] Configuring Windows Firewall..." -ForegroundColor Yellow
try {
    netsh advfirewall firewall add rule name="ZehraShield Web Console" dir=in action=allow protocol=TCP localport=8443
    netsh advfirewall firewall add rule name="ZehraShield API" dir=in action=allow protocol=TCP localport=5000
    Write-Host "[SUCCESS] Firewall rules configured" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Failed to configure firewall rules" -ForegroundColor Yellow
}

# Install Windows Service (if not disabled)
if (-not $NoService) {
    Write-Host "[INFO] Installing Windows Service..." -ForegroundColor Yellow
    
    # Create service wrapper script
    $serviceScript = @"
import sys
import os
import time
import win32service
import win32serviceutil
import win32api
import win32con

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class ZehraShieldService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ZehraShieldFirewall"
    _svc_display_name_ = "ZehraShield Advanced Firewall"
    _svc_description_ = "ZehraShield 6-Layer Enterprise Firewall System"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32.CreateEvent(None, 0, 0, None)
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32.SetEvent(self.hWaitStop)
    
    def SvcDoRun(self):
        import main
        main.main(['--daemon'])

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(ZehraShieldService)
"@
    
    $serviceScript | Out-File -FilePath "zehrashield_service.py" -Encoding UTF8
    
    try {
        # Install pywin32 for service support
        pip install pywin32
        
        # Install the service
        python zehrashield_service.py install
        Write-Host "[SUCCESS] Windows service installed" -ForegroundColor Green
        
        # Start the service
        Start-Service -Name "ZehraShieldFirewall"
        Write-Host "[SUCCESS] ZehraShield service started" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Service installation failed. You can start ZehraShield manually." -ForegroundColor Yellow
    }
}

# Create desktop shortcuts
Write-Host "[INFO] Creating desktop shortcuts..." -ForegroundColor Yellow
$WshShell = New-Object -comObject WScript.Shell

# Start shortcut
$StartShortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Start ZehraShield.lnk")
$StartShortcut.TargetPath = "$InstallPath\start_zehrasec.bat"
$StartShortcut.WorkingDirectory = $InstallPath
$StartShortcut.Description = "Start ZehraShield Advanced Firewall"
$StartShortcut.Save()

# Web Console shortcut
$WebShortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\ZehraShield Console.lnk")
$WebShortcut.TargetPath = "https://localhost:8443"
$WebShortcut.Description = "ZehraShield Web Management Console"
$WebShortcut.Save()

Write-Host "[SUCCESS] Desktop shortcuts created" -ForegroundColor Green

# Test installation
Write-Host "[INFO] Testing installation..." -ForegroundColor Yellow
try {
    python -c "
import sys, os
sys.path.insert(0, os.getcwd())
from src.core.firewall_engine import FirewallEngine
print('Core modules imported successfully')
"
    Write-Host "[SUCCESS] Installation test passed" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Installation test failed" -ForegroundColor Red
    exit 1
}

# Display completion message
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ZehraShield Installation Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation Path: $InstallPath" -ForegroundColor Green
Write-Host "Web Console: https://localhost:8443" -ForegroundColor Green
Write-Host "Default Credentials: admin / zehrasec123" -ForegroundColor Green
Write-Host ""
Write-Host "To start ZehraShield:" -ForegroundColor Yellow
if (-not $NoService) {
    Write-Host "  - Service is already running" -ForegroundColor Green
    Write-Host "  - Or use: Start-Service ZehraShieldFirewall" -ForegroundColor Green
} else {
    Write-Host "  - Double-click 'Start ZehraShield' desktop shortcut" -ForegroundColor Green
    Write-Host "  - Or run: $InstallPath\start_zehrasec.bat" -ForegroundColor Green
}
Write-Host ""
Write-Host "Documentation: $InstallPath\docs\" -ForegroundColor Green
Write-Host "Support: support@zehrasec.com" -ForegroundColor Green
Write-Host ""

# Offer to open web console
$openConsole = Read-Host "Open ZehraShield web console now? (y/N)"
if ($openConsole -eq "y" -or $openConsole -eq "Y") {
    Start-Process "https://localhost:8443"
}
