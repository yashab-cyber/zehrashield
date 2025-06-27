"""
ZehraShield Web Dashboard - Management Console
Copyright © 2025 ZehraSec - Yashab Alam

Enterprise web management console for ZehraShield firewall system.
Provides real-time monitoring, configuration, and incident management.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
from threading import Lock

logger = logging.getLogger(__name__)

# Thread lock for session management
session_lock = Lock()

def create_app(config_manager, firewall_engine):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.secret_key = os.urandom(24)
    app.config['SECRET_KEY'] = os.urandom(24)
    
    # Initialize SocketIO for real-time updates
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Store references to firewall components
    app.config_manager = config_manager
    app.firewall_engine = firewall_engine
    
    def require_auth(f):
        """Decorator for routes that require authentication."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'authenticated' not in session:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    @app.route('/')
    def index():
        """Redirect to dashboard or login."""
        if 'authenticated' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page."""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Get credentials from config
            config_username = config_manager.get('web_console', {}).get('username', 'admin')
            config_password = config_manager.get('web_console', {}).get('password', 'zehrashield123')
            
            if username == config_username and password == config_password:
                with session_lock:
                    session['authenticated'] = True
                    session['username'] = username
                    session['login_time'] = datetime.now().isoformat()
                
                flash('Successfully logged in!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials!', 'error')
        
        return render_template('login.html')
    
    @app.route('/logout')
    def logout():
        """Logout and clear session."""
        with session_lock:
            session.clear()
        flash('Successfully logged out!', 'info')
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    @require_auth
    def dashboard():
        """Main dashboard."""
        try:
            # Get real-time statistics from all layers
            stats = {}
            
            if firewall_engine:
                for layer_name, layer in firewall_engine.layers.items():
                    if hasattr(layer, 'get_statistics'):
                        stats[layer_name] = layer.get_statistics()
                
                # Get overall engine stats
                stats['engine'] = firewall_engine.get_statistics()
            
            return render_template('dashboard.html', stats=stats)
            
        except Exception as e:
            logger.error(f"Error loading dashboard: {e}")
            flash('Error loading dashboard data', 'error')
            return render_template('dashboard.html', stats={})
    
    @app.route('/api/stats')
    @require_auth
    def api_stats():
        """API endpoint for real-time statistics."""
        try:
            stats = {}
            
            if firewall_engine:
                for layer_name, layer in firewall_engine.layers.items():
                    if hasattr(layer, 'get_statistics'):
                        stats[layer_name] = layer.get_statistics()
                
                stats['engine'] = firewall_engine.get_statistics()
                stats['timestamp'] = datetime.now().isoformat()
            
            return jsonify(stats)
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/events')
    @require_auth
    def events():
        """Security events page."""
        try:
            # Get recent events from SIEM layer
            siem_layer = firewall_engine.layers.get('layer6_siem_integration')
            recent_events = []
            
            if siem_layer and hasattr(siem_layer, 'get_recent_events'):
                recent_events = siem_layer.get_recent_events(limit=100)
            
            return render_template('events.html', events=recent_events)
            
        except Exception as e:
            logger.error(f"Error loading events: {e}")
            flash('Error loading security events', 'error')
            return render_template('events.html', events=[])
    
    @app.route('/api/events')
    @require_auth
    def api_events():
        """API endpoint for security events."""
        try:
            limit = request.args.get('limit', 50, type=int)
            severity = request.args.get('severity')
            
            siem_layer = firewall_engine.layers.get('layer6_siem_integration')
            events = []
            
            if siem_layer and hasattr(siem_layer, 'get_recent_events'):
                events = siem_layer.get_recent_events(limit=limit, severity=severity)
            
            return jsonify({'events': events, 'timestamp': datetime.now().isoformat()})
            
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/incidents')
    @require_auth
    def incidents():
        """Security incidents page."""
        try:
            siem_layer = firewall_engine.layers.get('layer6_siem_integration')
            active_incidents = []
            
            if siem_layer and hasattr(siem_layer, 'get_active_incidents'):
                active_incidents = siem_layer.get_active_incidents()
            
            return render_template('incidents.html', incidents=active_incidents)
            
        except Exception as e:
            logger.error(f"Error loading incidents: {e}")
            flash('Error loading security incidents', 'error')
            return render_template('incidents.html', incidents=[])
    
    @app.route('/api/incidents')
    @require_auth
    def api_incidents():
        """API endpoint for security incidents."""
        try:
            siem_layer = firewall_engine.layers.get('layer6_siem_integration')
            incidents = []
            
            if siem_layer and hasattr(siem_layer, 'get_active_incidents'):
                incidents = siem_layer.get_active_incidents()
            
            return jsonify({'incidents': incidents, 'timestamp': datetime.now().isoformat()})
            
        except Exception as e:
            logger.error(f"Error getting incidents: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/devices')
    @require_auth
    def devices():
        """Network devices page."""
        try:
            nac_layer = firewall_engine.layers.get('layer5_network_access_control')
            devices_info = []
            
            if nac_layer and hasattr(nac_layer, 'known_devices'):
                for mac, device in nac_layer.known_devices.items():
                    device_info = nac_layer.get_device_info(mac)
                    if device_info:
                        devices_info.append(device_info)
            
            return render_template('devices.html', devices=devices_info)
            
        except Exception as e:
            logger.error(f"Error loading devices: {e}")
            flash('Error loading network devices', 'error')
            return render_template('devices.html', devices=[])
    
    @app.route('/api/devices')
    @require_auth
    def api_devices():
        """API endpoint for network devices."""
        try:
            nac_layer = firewall_engine.layers.get('layer5_network_access_control')
            devices = []
            
            if nac_layer and hasattr(nac_layer, 'known_devices'):
                for mac, device in nac_layer.known_devices.items():
                    device_info = nac_layer.get_device_info(mac)
                    if device_info:
                        devices.append(device_info)
            
            return jsonify({'devices': devices, 'timestamp': datetime.now().isoformat()})
            
        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/device/<mac>/authorize', methods=['POST'])
    @require_auth
    def authorize_device(mac):
        """Authorize a network device."""
        try:
            nac_layer = firewall_engine.layers.get('layer5_network_access_control')
            
            if nac_layer and hasattr(nac_layer, 'authorize_device'):
                success = nac_layer.authorize_device(mac)
                
                if success:
                    return jsonify({'success': True, 'message': 'Device authorized successfully'})
                else:
                    return jsonify({'success': False, 'message': 'Device not found'}), 404
            else:
                return jsonify({'success': False, 'message': 'NAC layer not available'}), 500
                
        except Exception as e:
            logger.error(f"Error authorizing device {mac}: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    @app.route('/api/device/<mac>/revoke', methods=['POST'])
    @require_auth
    def revoke_device(mac):
        """Revoke device access."""
        try:
            reason = request.json.get('reason', 'Manual revocation from web console')
            
            nac_layer = firewall_engine.layers.get('layer5_network_access_control')
            
            if nac_layer and hasattr(nac_layer, 'revoke_device_access'):
                nac_layer.revoke_device_access(mac, reason)
                return jsonify({'success': True, 'message': 'Device access revoked successfully'})
            else:
                return jsonify({'success': False, 'message': 'NAC layer not available'}), 500
                
        except Exception as e:
            logger.error(f"Error revoking device {mac}: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    @app.route('/config')
    @require_auth
    def config():
        """Configuration page."""
        try:
            current_config = config_manager.config
            return render_template('config.html', config=current_config)
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            flash('Error loading configuration', 'error')
            return render_template('config.html', config={})
    
    @app.route('/api/config', methods=['GET', 'POST'])
    @require_auth
    def api_config():
        """API endpoint for configuration management."""
        if request.method == 'GET':
            try:
                return jsonify(config_manager.config)
            except Exception as e:
                logger.error(f"Error getting configuration: {e}")
                return jsonify({'error': str(e)}), 500
        
        elif request.method == 'POST':
            try:
                new_config = request.json
                
                # Validate configuration (basic validation)
                if not isinstance(new_config, dict):
                    return jsonify({'success': False, 'message': 'Invalid configuration format'}), 400
                
                # Update configuration
                config_manager.config.update(new_config)
                config_manager.save_config()
                
                # Notify that restart may be required
                flash('Configuration updated. Some changes may require a restart.', 'warning')
                
                return jsonify({'success': True, 'message': 'Configuration updated successfully'})
                
            except Exception as e:
                logger.error(f"Error updating configuration: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500
    
    @app.route('/logs')
    @require_auth
    def logs():
        """Logs viewer page."""
        try:
            # Read recent log entries
            log_entries = []
            log_file = 'logs/zehrashield.log'
            
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    # Get last 100 lines
                    log_entries = lines[-100:]
            
            return render_template('logs.html', log_entries=log_entries)
            
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            flash('Error loading log files', 'error')
            return render_template('logs.html', log_entries=[])
    
    @app.route('/api/logs')
    @require_auth
    def api_logs():
        """API endpoint for log entries."""
        try:
            lines = request.args.get('lines', 100, type=int)
            log_file = request.args.get('file', 'zehrashield.log')
            
            log_entries = []
            log_path = f'logs/{log_file}'
            
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    all_lines = f.readlines()
                    log_entries = all_lines[-lines:]
            
            return jsonify({'logs': log_entries, 'timestamp': datetime.now().isoformat()})
            
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/reports')
    @require_auth
    def reports():
        """Security reports page."""
        try:
            # Get available reports
            reports = []
            reports_dir = 'reports'
            
            if os.path.exists(reports_dir):
                for file in os.listdir(reports_dir):
                    if file.endswith('.json'):
                        file_path = os.path.join(reports_dir, file)
                        stat = os.stat(file_path)
                        
                        reports.append({
                            'filename': file,
                            'size': stat.st_size,
                            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                        })
            
            reports.sort(key=lambda x: x['modified'], reverse=True)
            
            return render_template('reports.html', reports=reports)
            
        except Exception as e:
            logger.error(f"Error loading reports: {e}")
            flash('Error loading security reports', 'error')
            return render_template('reports.html', reports=[])
    
    @app.route('/api/system/status')
    @require_auth
    def system_status():
        """API endpoint for system status."""
        try:
            status = {
                'firewall_running': firewall_engine.running if firewall_engine else False,
                'uptime': None,
                'layers': {},
                'system': {
                    'cpu_percent': 0,
                    'memory_percent': 0,
                    'disk_usage': 0
                }
            }
            
            if firewall_engine:
                # Get uptime
                if firewall_engine.start_time:
                    uptime_seconds = (datetime.now() - firewall_engine.start_time).total_seconds()
                    status['uptime'] = uptime_seconds
                
                # Check layer health
                for layer_name, layer in firewall_engine.layers.items():
                    if hasattr(layer, 'is_healthy'):
                        status['layers'][layer_name] = layer.is_healthy()
                    else:
                        status['layers'][layer_name] = True
            
            # Get system metrics (simplified)
            try:
                import psutil
                status['system'] = {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent
                }
            except ImportError:
                pass
            
            return jsonify(status)
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/restart', methods=['POST'])
    @require_auth
    def restart_firewall():
        """API endpoint to restart the firewall."""
        try:
            if firewall_engine:
                # This would implement graceful restart
                # For now, just return success
                return jsonify({'success': True, 'message': 'Restart initiated'})
            else:
                return jsonify({'success': False, 'message': 'Firewall engine not available'}), 500
                
        except Exception as e:
            logger.error(f"Error restarting firewall: {e}")
            return jsonify({'success': False, 'message': str(e)}), 500
    
    # SocketIO events for real-time updates
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        if 'authenticated' not in session:
            return False  # Reject unauthenticated connections
        
        emit('connected', {'message': 'Connected to ZehraShield dashboard'})
    
    @socketio.on('subscribe_stats')
    def handle_subscribe_stats():
        """Handle subscription to real-time statistics."""
        if 'authenticated' not in session:
            return
        
        # Send initial stats
        try:
            stats = {}
            if firewall_engine:
                for layer_name, layer in firewall_engine.layers.items():
                    if hasattr(layer, 'get_statistics'):
                        stats[layer_name] = layer.get_statistics()
                stats['engine'] = firewall_engine.get_statistics()
            
            emit('stats_update', stats)
        except Exception as e:
            logger.error(f"Error sending stats update: {e}")
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html', error='Page not found'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html', error='Internal server error'), 500
    
    return app
