"""
ZehraShield Update System
Advanced Enterprise Firewall System
Developed by Yashab Alam for ZehraSec

Automatic update system for ZehraShield components.
"""

import os
import json
import requests
import subprocess
import hashlib
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import logging
import threading
import time


class UpdateManager:
    """Manages automatic updates for ZehraShield."""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.update_config = config.get("update_system", {})
        
        # Update settings
        self.auto_updates_enabled = self.update_config.get("auto_updates", False)
        self.check_interval = self.update_config.get("check_interval", 86400)  # 24 hours
        self.update_channel = self.update_config.get("channel", "stable")  # stable, beta, dev
        self.backup_before_update = self.update_config.get("backup_before_update", True)
        
        # Update URLs
        self.update_server = self.update_config.get("server", "https://api.github.com/repos/yashab-cyber/zehrashield")
        self.download_base = "https://github.com/yashab-cyber/zehrashield/archive"
        
        # Installation paths
        self.install_dir = "/opt/zehrashield"
        self.backup_dir = "/var/backups/zehrashield"
        self.current_version_file = os.path.join(self.install_dir, "VERSION")
        
        # Update state
        self.current_version = self._get_current_version()
        self.last_check = None
        self.available_update = None
        
        # Update thread
        self.update_thread = None
        self.stop_updates = threading.Event()
        
        # Ensure backup directory exists
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def _get_current_version(self):
        """Get currently installed version."""
        try:
            if os.path.exists(self.current_version_file):
                with open(self.current_version_file, 'r') as f:
                    return f.read().strip()
            else:
                return "3.0.0"  # Default version
        except Exception as e:
            self.logger.error(f"Error reading current version: {e}")
            return "unknown"
    
    def start_update_service(self):
        """Start automatic update checking service."""
        if not self.auto_updates_enabled:
            self.logger.info("Automatic updates are disabled")
            return
        
        if self.update_thread and self.update_thread.is_alive():
            self.logger.warning("Update service already running")
            return
        
        self.stop_updates.clear()
        self.update_thread = threading.Thread(
            target=self._update_check_loop,
            name="UpdateManager",
            daemon=True
        )
        self.update_thread.start()
        self.logger.info("Update service started")
    
    def stop_update_service(self):
        """Stop automatic update service."""
        if self.update_thread and self.update_thread.is_alive():
            self.stop_updates.set()
            self.update_thread.join(timeout=10)
            self.logger.info("Update service stopped")
    
    def _update_check_loop(self):
        """Main update checking loop."""
        while not self.stop_updates.is_set():
            try:
                self.check_for_updates()
                
                # If an update is available and auto-updates are enabled
                if self.available_update and self.auto_updates_enabled:
                    if self._should_auto_update():
                        self.logger.info("Starting automatic update")
                        success = self.perform_update()
                        if success:
                            self.logger.info("Automatic update completed successfully")
                        else:
                            self.logger.error("Automatic update failed")
                
            except Exception as e:
                self.logger.error(f"Error in update check loop: {e}")
            
            # Wait for next check
            self.stop_updates.wait(self.check_interval)
    
    def check_for_updates(self, force=False):
        """Check for available updates."""
        try:
            # Don't check too frequently unless forced
            if not force and self.last_check:
                time_since_check = datetime.now() - self.last_check
                if time_since_check < timedelta(hours=1):
                    return self.available_update
            
            self.logger.info("Checking for updates...")
            
            # Get latest release info
            response = requests.get(f"{self.update_server}/releases/latest", timeout=30)
            response.raise_for_status()
            
            release_info = response.json()
            latest_version = release_info.get("tag_name", "").lstrip("v")
            
            self.last_check = datetime.now()
            
            # Compare versions
            if self._is_newer_version(latest_version, self.current_version):
                self.available_update = {
                    "version": latest_version,
                    "release_date": release_info.get("published_at"),
                    "description": release_info.get("body", ""),
                    "download_url": f"{self.download_base}/v{latest_version}.tar.gz",
                    "html_url": release_info.get("html_url"),
                    "prerelease": release_info.get("prerelease", False)
                }
                
                self.logger.info(f"Update available: {latest_version} (current: {self.current_version})")
                return self.available_update
            else:
                self.available_update = None
                self.logger.info("No updates available")
                return None
                
        except requests.RequestException as e:
            self.logger.error(f"Failed to check for updates: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error checking for updates: {e}")
            return None
    
    def _is_newer_version(self, new_version, current_version):
        """Compare version strings."""
        try:
            # Simple version comparison (assumes semantic versioning)
            new_parts = [int(x) for x in new_version.split('.')]
            current_parts = [int(x) for x in current_version.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(new_parts), len(current_parts))
            new_parts.extend([0] * (max_len - len(new_parts)))
            current_parts.extend([0] * (max_len - len(current_parts)))
            
            return new_parts > current_parts
            
        except ValueError:
            # If version parsing fails, assume no update available
            return False
    
    def _should_auto_update(self):
        """Determine if automatic update should proceed."""
        if not self.available_update:
            return False
        
        # Don't auto-update prerelease versions on stable channel
        if (self.update_channel == "stable" and 
            self.available_update.get("prerelease", False)):
            return False
        
        # Additional checks can be added here (maintenance windows, etc.)
        return True
    
    def perform_update(self, version=None):
        """Perform system update."""
        try:
            if not version and not self.available_update:
                self.logger.error("No update available")
                return False
            
            update_info = self.available_update if not version else {"version": version}
            target_version = update_info["version"]
            
            self.logger.info(f"Starting update to version {target_version}")
            
            # Step 1: Create backup
            if self.backup_before_update:
                backup_path = self._create_backup()
                if not backup_path:
                    self.logger.error("Failed to create backup, aborting update")
                    return False
                self.logger.info(f"Backup created: {backup_path}")
            
            # Step 2: Download update
            download_path = self._download_update(target_version)
            if not download_path:
                self.logger.error("Failed to download update")
                return False
            
            # Step 3: Verify download
            if not self._verify_download(download_path):
                self.logger.error("Update verification failed")
                return False
            
            # Step 4: Stop ZehraShield service
            self.logger.info("Stopping ZehraShield service")
            stop_result = subprocess.run(
                ["sudo", "systemctl", "stop", "zehrashield"],
                capture_output=True, text=True
            )
            
            # Step 5: Install update
            install_success = self._install_update(download_path)
            
            # Step 6: Start service
            self.logger.info("Starting ZehraShield service")
            start_result = subprocess.run(
                ["sudo", "systemctl", "start", "zehrashield"],
                capture_output=True, text=True
            )
            
            if install_success and start_result.returncode == 0:
                self.logger.info(f"Update to version {target_version} completed successfully")
                self.current_version = target_version
                self.available_update = None
                self._update_version_file(target_version)
                return True
            else:
                self.logger.error("Update failed, attempting rollback")
                if self.backup_before_update and backup_path:
                    self._rollback_update(backup_path)
                return False
                
        except Exception as e:
            self.logger.error(f"Error during update: {e}")
            return False
        finally:
            # Cleanup downloaded files
            if 'download_path' in locals() and os.path.exists(download_path):
                try:
                    os.remove(download_path)
                except:
                    pass
    
    def _create_backup(self):
        """Create backup of current installation."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"zehrashield_backup_{self.current_version}_{timestamp}"
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            # Create backup using tar
            result = subprocess.run([
                "sudo", "tar", "-czf", f"{backup_path}.tar.gz",
                "-C", "/opt", "zehrashield"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                return f"{backup_path}.tar.gz"
            else:
                self.logger.error(f"Backup creation failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return None
    
    def _download_update(self, version):
        """Download update package."""
        try:
            download_url = f"{self.download_base}/v{version}.tar.gz"
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as temp_file:
                self.logger.info(f"Downloading update from {download_url}")
                
                response = requests.get(download_url, stream=True, timeout=300)
                response.raise_for_status()
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        temp_file.write(chunk)
                        downloaded += len(chunk)
                        
                        # Log progress every 10MB
                        if downloaded % (10 * 1024 * 1024) == 0:
                            percent = (downloaded / total_size) * 100 if total_size > 0 else 0
                            self.logger.info(f"Download progress: {percent:.1f}%")
                
                return temp_file.name
                
        except Exception as e:
            self.logger.error(f"Error downloading update: {e}")
            return None
    
    def _verify_download(self, download_path):
        """Verify downloaded update package."""
        try:
            # Basic verification - check if it's a valid tar.gz file
            result = subprocess.run([
                "tar", "-tzf", download_path
            ], capture_output=True, text=True)
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error verifying download: {e}")
            return False
    
    def _install_update(self, download_path):
        """Install the downloaded update."""
        try:
            # Extract to temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract the archive
                result = subprocess.run([
                    "tar", "-xzf", download_path, "-C", temp_dir
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.logger.error(f"Failed to extract update: {result.stderr}")
                    return False
                
                # Find the extracted directory
                extracted_dirs = [d for d in os.listdir(temp_dir) 
                                if os.path.isdir(os.path.join(temp_dir, d))]
                
                if not extracted_dirs:
                    self.logger.error("No extracted directory found")
                    return False
                
                source_dir = os.path.join(temp_dir, extracted_dirs[0])
                
                # Copy files to installation directory
                result = subprocess.run([
                    "sudo", "cp", "-r", f"{source_dir}/.", self.install_dir
                ], capture_output=True, text=True)
                
                if result.returncode != 0:
                    self.logger.error(f"Failed to install update: {result.stderr}")
                    return False
                
                # Set proper permissions
                subprocess.run([
                    "sudo", "chown", "-R", "root:root", self.install_dir
                ])
                subprocess.run([
                    "sudo", "chmod", "+x", f"{self.install_dir}/scripts/*.sh"
                ])
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error installing update: {e}")
            return False
    
    def _rollback_update(self, backup_path):
        """Rollback to previous version from backup."""
        try:
            self.logger.info(f"Rolling back from backup: {backup_path}")
            
            # Stop service
            subprocess.run(["sudo", "systemctl", "stop", "zehrashield"])
            
            # Remove current installation
            subprocess.run(["sudo", "rm", "-rf", self.install_dir])
            
            # Restore from backup
            result = subprocess.run([
                "sudo", "tar", "-xzf", backup_path, "-C", "/opt"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Start service
                subprocess.run(["sudo", "systemctl", "start", "zehrashield"])
                self.logger.info("Rollback completed successfully")
                return True
            else:
                self.logger.error(f"Rollback failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error during rollback: {e}")
            return False
    
    def _update_version_file(self, version):
        """Update the version file."""
        try:
            with open(self.current_version_file, 'w') as f:
                f.write(version)
        except Exception as e:
            self.logger.error(f"Error updating version file: {e}")
    
    def get_update_status(self):
        """Get current update status."""
        return {
            "current_version": self.current_version,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "available_update": self.available_update,
            "auto_updates_enabled": self.auto_updates_enabled,
            "update_channel": self.update_channel
        }
    
    def list_backups(self):
        """List available backups."""
        try:
            backups = []
            if os.path.exists(self.backup_dir):
                for file in os.listdir(self.backup_dir):
                    if file.endswith(".tar.gz") and "zehrashield_backup" in file:
                        file_path = os.path.join(self.backup_dir, file)
                        stat = os.stat(file_path)
                        backups.append({
                            "filename": file,
                            "path": file_path,
                            "size": stat.st_size,
                            "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
                        })
            
            return sorted(backups, key=lambda x: x["created"], reverse=True)
            
        except Exception as e:
            self.logger.error(f"Error listing backups: {e}")
            return []
    
    def restore_from_backup(self, backup_path):
        """Restore system from a specific backup."""
        if not os.path.exists(backup_path):
            self.logger.error(f"Backup file not found: {backup_path}")
            return False
        
        return self._rollback_update(backup_path)
