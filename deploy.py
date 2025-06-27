#!/usr/bin/env python3
"""
ZehraShield Automated Deployment Script
Copyright (c) 2025 ZehraSec - Yashab Alam
Enterprise-grade automated deployment for all platforms
"""

import os
import sys
import json
import shutil
import platform
import subprocess
import argparse
from pathlib import Path

class ZehraShieldDeployer:
    def __init__(self):
        self.platform = platform.system().lower()
        self.is_admin = self.check_admin_privileges()
        self.project_root = Path(__file__).parent.absolute()
        
    def check_admin_privileges(self):
        """Check if running with administrative privileges"""
        try:
            if self.platform == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def log(self, message, level="INFO"):
        """Log deployment messages"""
        print(f"[{level}] {message}")
    
    def run_command(self, command, shell=True):
        """Execute system command safely"""
        try:
            result = subprocess.run(command, shell=shell, capture_output=True, text=True)
            if result.returncode != 0:
                self.log(f"Command failed: {command}", "ERROR")
                self.log(f"Error: {result.stderr}", "ERROR")
                return False
            return True
        except Exception as e:
            self.log(f"Command execution failed: {e}", "ERROR")
            return False
    
    def install_dependencies(self):
        """Install Python dependencies"""
        self.log("Installing Python dependencies...")
        
        # Check if pip is available
        if not shutil.which("pip") and not shutil.which("pip3"):
            self.log("pip not found. Please install Python and pip first.", "ERROR")
            return False
        
        pip_cmd = "pip3" if shutil.which("pip3") else "pip"
        
        # Install requirements
        if os.path.exists("requirements.txt"):
            if not self.run_command(f"{pip_cmd} install -r requirements.txt"):
                return False
        
        if os.path.exists("requirements_advanced.txt"):
            if not self.run_command(f"{pip_cmd} install -r requirements_advanced.txt"):
                return False
        
        return True
    
    def create_directories(self):
        """Create necessary directories"""
        directories = [
            "logs",
            "data",
            "backups",
            "temp",
            "certs"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            self.log(f"Created directory: {directory}")
    
    def setup_configuration(self):
        """Set up configuration files"""
        config_dir = Path("config")
        
        # Copy default configs if they don't exist
        configs = [
            "firewall.json",
            "firewall_advanced.json",
            "threat_intelligence.json",
            "ml_models.json",
            "zero_trust_policies.json",
            "soar_playbooks.json"
        ]
        
        for config in configs:
            config_path = config_dir / config
            if not config_path.exists():
                self.log(f"Configuration {config} missing - will be created on first run")
    
    def setup_linux(self):
        """Linux-specific deployment setup"""
        self.log("Setting up ZehraShield for Linux...")
        
        # Make scripts executable
        scripts = ["scripts/install.sh", "scripts/deploy.sh", "scripts/zehrashield-cli"]
        for script in scripts:
            if os.path.exists(script):
                os.chmod(script, 0o755)
        
        # Create systemd service
        if self.is_admin:
            self.log("Setting up systemd service...")
            service_content = f"""[Unit]
Description=ZehraShield Advanced Firewall System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={self.project_root}
ExecStart=/usr/bin/python3 {self.project_root}/main.py --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
            with open("/etc/systemd/system/zehrashield.service", "w") as f:
                f.write(service_content)
            
            self.run_command("systemctl daemon-reload")
            self.run_command("systemctl enable zehrashield")
        
        return True
    
    def setup_windows(self):
        """Windows-specific deployment setup"""
        self.log("Setting up ZehraShield for Windows...")
        
        if self.is_admin:
            # Create Windows service (simplified)
            self.log("Windows service setup would require pywin32")
            self.log("For now, use the batch file to start ZehraShield")
        
        return True
    
    def setup_macos(self):
        """macOS-specific deployment setup"""
        self.log("Setting up ZehraShield for macOS...")
        
        # Make scripts executable
        scripts = ["scripts/install.sh", "scripts/deploy.sh", "scripts/zehrashield-cli"]
        for script in scripts:
            if os.path.exists(script):
                os.chmod(script, 0o755)
        
        # Create launchd plist
        if self.is_admin:
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.zehrasec.zehrashield</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{self.project_root}/main.py</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>{self.project_root}</string>
</dict>
</plist>
"""
            plist_path = "/Library/LaunchDaemons/com.zehrasec.zehrashield.plist"
            with open(plist_path, "w") as f:
                f.write(plist_content)
            
            os.chmod(plist_path, 0o644)
            self.run_command(f"launchctl load {plist_path}")
        
        return True
    
    def test_installation(self):
        """Test the installation"""
        self.log("Testing ZehraShield installation...")
        
        # Test Python imports
        try:
            sys.path.insert(0, str(self.project_root))
            from src.core.firewall_engine import FirewallEngine
            self.log("Core modules imported successfully")
        except ImportError as e:
            self.log(f"Import test failed: {e}", "ERROR")
            return False
        
        # Test configuration loading
        try:
            config_path = self.project_root / "config" / "firewall.json"
            if config_path.exists():
                with open(config_path) as f:
                    json.load(f)
                self.log("Configuration loading test passed")
            else:
                self.log("Configuration file not found", "WARNING")
        except Exception as e:
            self.log(f"Configuration test failed: {e}", "ERROR")
            return False
        
        return True
    
    def deploy(self):
        """Main deployment function"""
        self.log(f"Starting ZehraShield deployment on {self.platform}")
        
        if not self.is_admin:
            self.log("Warning: Not running as administrator. Some features may not work.", "WARNING")
        
        # Step 1: Install dependencies
        if not self.install_dependencies():
            self.log("Dependency installation failed", "ERROR")
            return False
        
        # Step 2: Create directories
        self.create_directories()
        
        # Step 3: Setup configuration
        self.setup_configuration()
        
        # Step 4: Platform-specific setup
        if self.platform == "linux":
            if not self.setup_linux():
                return False
        elif self.platform == "windows":
            if not self.setup_windows():
                return False
        elif self.platform == "darwin":  # macOS
            if not self.setup_macos():
                return False
        else:
            self.log(f"Unsupported platform: {self.platform}", "ERROR")
            return False
        
        # Step 5: Test installation
        if not self.test_installation():
            self.log("Installation test failed", "ERROR")
            return False
        
        self.log("ZehraShield deployment completed successfully!")
        self.log("Web console will be available at: https://localhost:8443")
        self.log("Default credentials: admin / zehrasec123")
        
        return True

def main():
    parser = argparse.ArgumentParser(description="ZehraShield Automated Deployment")
    parser.add_argument("--test-only", action="store_true", help="Only run tests, don't deploy")
    parser.add_argument("--no-service", action="store_true", help="Don't install system service")
    args = parser.parse_args()
    
    deployer = ZehraShieldDeployer()
    
    if args.test_only:
        success = deployer.test_installation()
    else:
        success = deployer.deploy()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
