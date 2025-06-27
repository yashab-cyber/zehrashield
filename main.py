#!/usr/bin/env python3
"""
ZehraShield - Enterprise 6-Layer Firewall System
Copyright © 2025 ZehraSec - Yashab Alam
https://github.com/yashab-cyber/zehrashield

Main entry point for the ZehraShield firewall system.
"""

import sys
import os
import signal
import argparse
import threading
import time
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.firewall_engine import FirewallEngine
from core.config_manager import ConfigManager
from core.logger import setup_logging
from web.dashboard import create_app


class ZehraShield:
    """Main ZehraShield firewall application."""
    
    def __init__(self, config_path=None):
        """Initialize ZehraShield with configuration."""
        self.config_path = config_path or "config/firewall.json"
        self.config_manager = ConfigManager(self.config_path)
        self.firewall_engine = None
        self.web_app = None
        self.running = False
        
        # Setup logging
        setup_logging(self.config_manager.get_log_level())
        self.logger = logging.getLogger(__name__)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        
    def start(self):
        """Start the ZehraShield firewall system."""
        try:
            self.logger.info("🛡️  Starting ZehraShield Enterprise Firewall System")
            self.logger.info("Copyright © 2025 ZehraSec - Yashab Alam")
            
            # Check system requirements
            self._check_requirements()
            
            # Initialize firewall engine
            self.firewall_engine = FirewallEngine(self.config_manager)
            
            # Start firewall layers
            self.logger.info("Initializing 6-layer security architecture...")
            self.firewall_engine.start()
            
            # Start web dashboard
            if self.config_manager.get('web_console', {}).get('enabled', True):
                self.logger.info("Starting web management console...")
                self._start_web_console()
            
            self.running = True
            self.logger.info("✅ ZehraShield is now active and protecting your network!")
            self.logger.info(f"🌐 Web Console: https://localhost:{self.config_manager.get('web_console', {}).get('port', 8443)}")
            
            # Keep the main thread alive
            self._main_loop()
            
        except Exception as e:
            self.logger.error(f"Failed to start ZehraShield: {e}")
            sys.exit(1)
            
    def stop(self):
        """Stop the ZehraShield firewall system."""
        if not self.running:
            return
            
        self.logger.info("Stopping ZehraShield...")
        self.running = False
        
        if self.firewall_engine:
            self.firewall_engine.stop()
            
        self.logger.info("ZehraShield stopped successfully")
        
    def _check_requirements(self):
        """Check system requirements and permissions."""
        # Check if running as administrator/root
        if os.name == 'nt':  # Windows
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError("ZehraShield requires administrator privileges on Windows")
        else:  # Unix-like systems
            if os.geteuid() != 0:
                raise PermissionError("ZehraShield requires root privileges on Unix-like systems")
                
        # Check Python version
        if sys.version_info < (3, 8):
            raise RuntimeError("ZehraShield requires Python 3.8 or newer")
            
        self.logger.info("✅ System requirements check passed")
        
    def _start_web_console(self):
        """Start the web management console in a separate thread."""
        try:
            from web.dashboard import create_app
            
            app = create_app(self.config_manager, self.firewall_engine)
            
            def run_web_server():
                port = self.config_manager.get('web_console', {}).get('port', 8443)
                host = self.config_manager.get('web_console', {}).get('host', '0.0.0.0')
                
                # Use HTTPS for production
                ssl_context = 'adhoc' if self.config_manager.get('web_console', {}).get('ssl', True) else None
                
                app.run(
                    host=host,
                    port=port,
                    debug=False,
                    ssl_context=ssl_context,
                    threaded=True
                )
            
            web_thread = threading.Thread(target=run_web_server, daemon=True)
            web_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start web console: {e}")
            
    def _main_loop(self):
        """Main application loop."""
        try:
            while self.running:
                time.sleep(1)
                
                # Health check
                if self.firewall_engine and not self.firewall_engine.is_healthy():
                    self.logger.warning("Firewall engine health check failed")
                    
        except KeyboardInterrupt:
            pass
        except Exception as e:
            self.logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ZehraShield - Enterprise 6-Layer Firewall System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Start with default config
  python main.py --config custom.json    # Start with custom config
  python main.py --verbose               # Start with verbose logging
  python main.py --test-mode             # Start in test mode
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        default='config/firewall.json',
        help='Path to configuration file (default: config/firewall.json)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--test-mode', '-t',
        action='store_true',
        help='Run in test mode (no actual packet filtering)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='ZehraShield v3.0.0 - Enterprise Edition'
    )
    
    args = parser.parse_args()
    
    # Set environment variables based on arguments
    if args.verbose:
        os.environ['ZEHRASHIELD_LOG_LEVEL'] = 'DEBUG'
        
    if args.test_mode:
        os.environ['ZEHRASHIELD_TEST_MODE'] = '1'
    
    # Create and start ZehraShield
    try:
        firewall = ZehraShield(config_path=args.config)
        firewall.start()
    except KeyboardInterrupt:
        print("\n🛡️  ZehraShield shutdown requested by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
