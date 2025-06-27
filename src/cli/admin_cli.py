#!/usr/bin/env python3
"""
ZehraShield CLI Administration Tool
Advanced Enterprise Firewall System
Developed by Yashab Alam for ZehraSec

Command-line interface for managing ZehraShield firewall.
"""

import argparse
import json
import sys
import os
import subprocess
import time
from pathlib import Path
from datetime import datetime, timedelta
import requests
from tabulate import tabulate

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.config_manager import ConfigManager
from core.logger import SecurityLogger


class ZehraShieldCLI:
    """Command-line interface for ZehraShield administration."""
    
    def __init__(self):
        self.config_path = "/etc/zehrashield/firewall.json"
        self.service_name = "zehrashield"
        self.api_base = "http://localhost:8080"
        self.config_manager = None
        self.logger = None
        
        # Try to load config
        try:
            self.config_manager = ConfigManager(self.config_path)
            self.logger = SecurityLogger(self.config_manager.get_config())
        except Exception as e:
            print(f"Warning: Could not load config: {e}")
    
    def status(self):
        """Show firewall status."""
        try:
            # Check service status
            result = subprocess.run(
                ["systemctl", "is-active", self.service_name],
                capture_output=True, text=True
            )
            service_status = result.stdout.strip()
            
            # Check if web console is responding
            try:
                response = requests.get(f"{self.api_base}/api/status", timeout=5)
                web_status = "Running" if response.status_code == 200 else "Error"
                api_data = response.json() if response.status_code == 200 else {}
            except:
                web_status = "Not responding"
                api_data = {}
            
            # Display status
            status_data = [
                ["Service Status", service_status.title()],
                ["Web Console", web_status],
                ["Config File", "Found" if os.path.exists(self.config_path) else "Missing"],
                ["Log Directory", "Found" if os.path.exists("/var/log/zehrashield") else "Missing"]
            ]
            
            if api_data:
                status_data.extend([
                    ["Uptime", api_data.get("uptime", "Unknown")],
                    ["Packets Processed", f"{api_data.get('packets_processed', 0):,}"],
                    ["Threats Blocked", f"{api_data.get('threats_blocked', 0):,}"],
                    ["Active Rules", str(api_data.get('active_rules', 0))]
                ])
            
            print("\n🛡️  ZehraShield Firewall Status")
            print("=" * 40)
            print(tabulate(status_data, headers=["Component", "Status"], tablefmt="grid"))
            
        except Exception as e:
            print(f"Error checking status: {e}")
            return False
        
        return service_status == "active"
    
    def start(self):
        """Start the firewall service."""
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "start", self.service_name],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("✅ ZehraShield firewall started successfully")
                time.sleep(2)
                self.status()
            else:
                print(f"❌ Failed to start firewall: {result.stderr}")
        except Exception as e:
            print(f"Error starting firewall: {e}")
    
    def stop(self):
        """Stop the firewall service."""
        try:
            result = subprocess.run(
                ["sudo", "systemctl", "stop", self.service_name],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("🛑 ZehraShield firewall stopped successfully")
            else:
                print(f"❌ Failed to stop firewall: {result.stderr}")
        except Exception as e:
            print(f"Error stopping firewall: {e}")
    
    def restart(self):
        """Restart the firewall service."""
        print("🔄 Restarting ZehraShield firewall...")
        self.stop()
        time.sleep(2)
        self.start()
    
    def logs(self, lines=50, follow=False):
        """Show firewall logs."""
        try:
            cmd = ["sudo", "journalctl", "-u", self.service_name, "-n", str(lines)]
            if follow:
                cmd.append("-f")
            
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nLog viewing stopped.")
        except Exception as e:
            print(f"Error viewing logs: {e}")
    
    def config_validate(self):
        """Validate configuration file."""
        if not os.path.exists(self.config_path):
            print(f"❌ Configuration file not found: {self.config_path}")
            return False
        
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Basic validation
            required_sections = ["layers", "network", "logging", "web_console"]
            missing_sections = [s for s in required_sections if s not in config]
            
            if missing_sections:
                print(f"❌ Missing configuration sections: {missing_sections}")
                return False
            
            print("✅ Configuration file is valid")
            return True
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in configuration file: {e}")
            return False
        except Exception as e:
            print(f"❌ Error validating configuration: {e}")
            return False
    
    def config_backup(self, backup_path=None):
        """Backup configuration."""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"/tmp/zehrashield_config_backup_{timestamp}.json"
        
        try:
            if os.path.exists(self.config_path):
                subprocess.run(["sudo", "cp", self.config_path, backup_path])
                print(f"✅ Configuration backed up to: {backup_path}")
            else:
                print(f"❌ Configuration file not found: {self.config_path}")
        except Exception as e:
            print(f"❌ Error backing up configuration: {e}")
    
    def config_restore(self, backup_path):
        """Restore configuration from backup."""
        if not os.path.exists(backup_path):
            print(f"❌ Backup file not found: {backup_path}")
            return
        
        try:
            # Validate backup file first
            with open(backup_path, 'r') as f:
                json.load(f)
            
            # Create current backup before restore
            self.config_backup()
            
            # Restore configuration
            subprocess.run(["sudo", "cp", backup_path, self.config_path])
            print(f"✅ Configuration restored from: {backup_path}")
            print("🔄 Restart the firewall to apply changes")
            
        except json.JSONDecodeError:
            print(f"❌ Invalid backup file format")
        except Exception as e:
            print(f"❌ Error restoring configuration: {e}")
    
    def stats(self):
        """Show firewall statistics."""
        try:
            response = requests.get(f"{self.api_base}/api/stats", timeout=10)
            if response.status_code == 200:
                stats = response.json()
                
                print("\n📊 ZehraShield Statistics")
                print("=" * 40)
                
                # General stats
                general_data = [
                    ["Uptime", stats.get("uptime", "Unknown")],
                    ["Total Packets", f"{stats.get('total_packets', 0):,}"],
                    ["Blocked Packets", f"{stats.get('blocked_packets', 0):,}"],
                    ["Allowed Packets", f"{stats.get('allowed_packets', 0):,}"],
                    ["Threats Detected", f"{stats.get('threats_detected', 0):,}"]
                ]
                print(tabulate(general_data, headers=["Metric", "Value"], tablefmt="grid"))
                
                # Layer stats
                if "layers" in stats:
                    print("\n🔒 Layer Statistics")
                    layer_data = []
                    for layer, data in stats["layers"].items():
                        layer_data.append([
                            layer.replace("_", " ").title(),
                            f"{data.get('processed', 0):,}",
                            f"{data.get('blocked', 0):,}",
                            f"{data.get('threats', 0):,}"
                        ])
                    
                    print(tabulate(layer_data, 
                                 headers=["Layer", "Processed", "Blocked", "Threats"],
                                 tablefmt="grid"))
                
            else:
                print(f"❌ Failed to get statistics: HTTP {response.status_code}")
                
        except requests.RequestException:
            print("❌ Could not connect to ZehraShield API")
        except Exception as e:
            print(f"❌ Error getting statistics: {e}")
    
    def rules_list(self):
        """List active firewall rules."""
        try:
            response = requests.get(f"{self.api_base}/api/rules", timeout=10)
            if response.status_code == 200:
                rules = response.json()
                
                print("\n🔥 Active Firewall Rules")
                print("=" * 50)
                
                if not rules:
                    print("No active rules found.")
                    return
                
                rule_data = []
                for rule in rules:
                    rule_data.append([
                        rule.get("id", ""),
                        rule.get("name", ""),
                        rule.get("action", ""),
                        rule.get("source", ""),
                        rule.get("destination", ""),
                        rule.get("enabled", False)
                    ])
                
                print(tabulate(rule_data,
                             headers=["ID", "Name", "Action", "Source", "Destination", "Enabled"],
                             tablefmt="grid"))
                
            else:
                print(f"❌ Failed to get rules: HTTP {response.status_code}")
                
        except requests.RequestException:
            print("❌ Could not connect to ZehraShield API")
        except Exception as e:
            print(f"❌ Error getting rules: {e}")
    
    def threats_recent(self, hours=24):
        """Show recent threats."""
        try:
            params = {"hours": hours}
            response = requests.get(f"{self.api_base}/api/threats/recent", 
                                  params=params, timeout=10)
            
            if response.status_code == 200:
                threats = response.json()
                
                print(f"\n⚠️  Recent Threats (Last {hours} hours)")
                print("=" * 60)
                
                if not threats:
                    print("No recent threats detected.")
                    return
                
                threat_data = []
                for threat in threats[:20]:  # Show last 20
                    threat_data.append([
                        threat.get("timestamp", ""),
                        threat.get("type", ""),
                        threat.get("severity", ""),
                        threat.get("source_ip", ""),
                        threat.get("description", "")[:50] + "..."
                    ])
                
                print(tabulate(threat_data,
                             headers=["Timestamp", "Type", "Severity", "Source IP", "Description"],
                             tablefmt="grid"))
                
                if len(threats) > 20:
                    print(f"\n... and {len(threats) - 20} more threats")
                
            else:
                print(f"❌ Failed to get threats: HTTP {response.status_code}")
                
        except requests.RequestException:
            print("❌ Could not connect to ZehraShield API")
        except Exception as e:
            print(f"❌ Error getting threats: {e}")
    
    def update_check(self):
        """Check for updates."""
        print("🔍 Checking for ZehraShield updates...")
        try:
            # This would connect to update server in production
            response = requests.get("https://api.github.com/repos/yashab-cyber/zehrashield/releases/latest", 
                                  timeout=10)
            
            if response.status_code == 200:
                release = response.json()
                latest_version = release.get("tag_name", "unknown")
                current_version = "v3.0.0"  # This would be read from version file
                
                print(f"Current version: {current_version}")
                print(f"Latest version: {latest_version}")
                
                if latest_version != current_version:
                    print("🆕 New version available!")
                    print(f"Release notes: {release.get('html_url', '')}")
                else:
                    print("✅ You are running the latest version")
            else:
                print("❌ Could not check for updates")
                
        except Exception as e:
            print(f"❌ Error checking for updates: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ZehraShield Firewall CLI Administration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  zehrashield-cli status              # Show firewall status
  zehrashield-cli start               # Start firewall service
  zehrashield-cli logs --follow       # Follow logs in real-time
  zehrashield-cli config validate     # Validate configuration
  zehrashield-cli stats               # Show statistics
  zehrashield-cli threats --hours 6   # Show threats from last 6 hours
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Status command
    subparsers.add_parser("status", help="Show firewall status")
    
    # Service control commands
    subparsers.add_parser("start", help="Start firewall service")
    subparsers.add_parser("stop", help="Stop firewall service")
    subparsers.add_parser("restart", help="Restart firewall service")
    
    # Logs command
    logs_parser = subparsers.add_parser("logs", help="Show firewall logs")
    logs_parser.add_argument("--lines", "-n", type=int, default=50,
                           help="Number of log lines to show")
    logs_parser.add_argument("--follow", "-f", action="store_true",
                           help="Follow logs in real-time")
    
    # Configuration commands
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_action")
    
    config_subparsers.add_parser("validate", help="Validate configuration")
    
    backup_parser = config_subparsers.add_parser("backup", help="Backup configuration")
    backup_parser.add_argument("--path", help="Backup file path")
    
    restore_parser = config_subparsers.add_parser("restore", help="Restore configuration")
    restore_parser.add_argument("path", help="Backup file path")
    
    # Statistics and monitoring
    subparsers.add_parser("stats", help="Show firewall statistics")
    subparsers.add_parser("rules", help="List active firewall rules")
    
    threats_parser = subparsers.add_parser("threats", help="Show recent threats")
    threats_parser.add_argument("--hours", type=int, default=24,
                               help="Hours to look back for threats")
    
    # Update command
    subparsers.add_parser("update", help="Check for updates")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = ZehraShieldCLI()
    
    try:
        if args.command == "status":
            cli.status()
        elif args.command == "start":
            cli.start()
        elif args.command == "stop":
            cli.stop()
        elif args.command == "restart":
            cli.restart()
        elif args.command == "logs":
            cli.logs(args.lines, args.follow)
        elif args.command == "config":
            if args.config_action == "validate":
                cli.config_validate()
            elif args.config_action == "backup":
                cli.config_backup(args.path)
            elif args.config_action == "restore":
                cli.config_restore(args.path)
            else:
                config_parser.print_help()
        elif args.command == "stats":
            cli.stats()
        elif args.command == "rules":
            cli.rules_list()
        elif args.command == "threats":
            cli.threats_recent(args.hours)
        elif args.command == "update":
            cli.update_check()
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
