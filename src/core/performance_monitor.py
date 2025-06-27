"""
ZehraShield Performance Monitor
Advanced Enterprise Firewall System
Developed by Yashab Alam for ZehraSec

System performance monitoring and alerting.
"""

import psutil
import time
import threading
import json
from datetime import datetime, timedelta
from collections import deque, defaultdict
import logging


class PerformanceMonitor:
    """Monitor system performance and firewall health."""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.monitoring_enabled = config.get("performance_monitoring", {}).get("enabled", True)
        self.monitoring_interval = config.get("performance_monitoring", {}).get("interval", 30)
        self.alert_thresholds = config.get("performance_monitoring", {}).get("thresholds", {})
        
        # Performance metrics storage (last 24 hours)
        self.max_samples = int(86400 / self.monitoring_interval)  # 24 hours of samples
        self.metrics = {
            "cpu_usage": deque(maxlen=self.max_samples),
            "memory_usage": deque(maxlen=self.max_samples),
            "disk_usage": deque(maxlen=self.max_samples),
            "network_io": deque(maxlen=self.max_samples),
            "packet_rate": deque(maxlen=self.max_samples),
            "threat_rate": deque(maxlen=self.max_samples),
            "response_time": deque(maxlen=self.max_samples),
            "active_connections": deque(maxlen=self.max_samples)
        }
        
        # Timestamps for metrics
        self.timestamps = deque(maxlen=self.max_samples)
        
        # Alert tracking
        self.last_alerts = defaultdict(lambda: datetime.min)
        self.alert_cooldown = timedelta(minutes=15)
        
        # Performance counters
        self.packet_counter = 0
        self.threat_counter = 0
        self.last_packet_count = 0
        self.last_threat_count = 0
        
        # Monitoring thread
        self.monitoring_thread = None
        self.stop_monitoring = threading.Event()
        
        # Default thresholds
        self.default_thresholds = {
            "cpu_usage": 80.0,
            "memory_usage": 85.0,
            "disk_usage": 90.0,
            "response_time": 5000,  # milliseconds
            "packet_rate": 10000,   # packets per second
            "threat_rate": 100      # threats per minute
        }
        
        # Merge with config thresholds
        for key, value in self.default_thresholds.items():
            if key not in self.alert_thresholds:
                self.alert_thresholds[key] = value
    
    def start_monitoring(self):
        """Start performance monitoring."""
        if not self.monitoring_enabled:
            self.logger.info("Performance monitoring is disabled")
            return
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.logger.warning("Performance monitoring already running")
            return
        
        self.stop_monitoring.clear()
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="PerformanceMonitor",
            daemon=True
        )
        self.monitoring_thread.start()
        self.logger.info("Performance monitoring started")
    
    def stop_monitoring_service(self):
        """Stop performance monitoring."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.stop_monitoring.set()
            self.monitoring_thread.join(timeout=5)
            self.logger.info("Performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while not self.stop_monitoring.is_set():
            try:
                # Collect metrics
                timestamp = datetime.now()
                metrics = self._collect_metrics()
                
                # Store metrics
                self.timestamps.append(timestamp)
                for key, value in metrics.items():
                    self.metrics[key].append(value)
                
                # Check thresholds and send alerts
                self._check_thresholds(metrics, timestamp)
                
                # Log performance summary periodically
                if len(self.timestamps) % 10 == 0:  # Every 10 samples
                    self._log_performance_summary(metrics)
                
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
            
            # Wait for next interval
            self.stop_monitoring.wait(self.monitoring_interval)
    
    def _collect_metrics(self):
        """Collect current system metrics."""
        metrics = {}
        
        try:
            # CPU usage
            metrics["cpu_usage"] = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            metrics["memory_usage"] = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage("/")
            metrics["disk_usage"] = disk.percent
            
            # Network I/O
            net_io = psutil.net_io_counters()
            metrics["network_io"] = net_io.bytes_sent + net_io.bytes_recv
            
            # Active network connections
            connections = len(psutil.net_connections())
            metrics["active_connections"] = connections
            
            # Calculate packet rate
            current_packets = self.packet_counter
            packet_rate = (current_packets - self.last_packet_count) / self.monitoring_interval
            metrics["packet_rate"] = packet_rate
            self.last_packet_count = current_packets
            
            # Calculate threat rate (per minute)
            current_threats = self.threat_counter
            threat_rate = ((current_threats - self.last_threat_count) / self.monitoring_interval) * 60
            metrics["threat_rate"] = threat_rate
            self.last_threat_count = current_threats
            
            # Response time (simulated - would be measured from actual responses)
            metrics["response_time"] = self._measure_response_time()
            
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
            # Return default values on error
            for key in self.metrics.keys():
                if key not in metrics:
                    metrics[key] = 0
        
        return metrics
    
    def _measure_response_time(self):
        """Measure system response time."""
        try:
            start_time = time.time()
            # Simple operation to measure system responsiveness
            _ = [i for i in range(1000)]
            end_time = time.time()
            return (end_time - start_time) * 1000  # Convert to milliseconds
        except:
            return 0
    
    def _check_thresholds(self, metrics, timestamp):
        """Check if any metrics exceed thresholds."""
        for metric, value in metrics.items():
            if metric in self.alert_thresholds:
                threshold = self.alert_thresholds[metric]
                
                if value > threshold:
                    # Check alert cooldown
                    if timestamp - self.last_alerts[metric] > self.alert_cooldown:
                        self._send_alert(metric, value, threshold, timestamp)
                        self.last_alerts[metric] = timestamp
    
    def _send_alert(self, metric, value, threshold, timestamp):
        """Send performance alert."""
        alert_data = {
            "type": "performance_alert",
            "metric": metric,
            "value": value,
            "threshold": threshold,
            "timestamp": timestamp.isoformat(),
            "severity": self._get_alert_severity(metric, value, threshold)
        }
        
        # Log the alert
        self.logger.warning(
            f"Performance alert: {metric} = {value:.2f} (threshold: {threshold})",
            extra={"alert_data": alert_data}
        )
        
        # Send to SIEM if configured
        self._send_to_siem(alert_data)
    
    def _get_alert_severity(self, metric, value, threshold):
        """Determine alert severity based on how much threshold is exceeded."""
        ratio = value / threshold
        if ratio > 1.5:
            return "critical"
        elif ratio > 1.2:
            return "high"
        else:
            return "medium"
    
    def _send_to_siem(self, alert_data):
        """Send alert to SIEM system."""
        try:
            # This would integrate with actual SIEM systems
            siem_config = self.config.get("siem_integration", {})
            if siem_config.get("enabled", False):
                # Send to configured SIEM endpoint
                pass
        except Exception as e:
            self.logger.error(f"Failed to send alert to SIEM: {e}")
    
    def _log_performance_summary(self, current_metrics):
        """Log performance summary."""
        summary = {
            "cpu_usage": f"{current_metrics.get('cpu_usage', 0):.1f}%",
            "memory_usage": f"{current_metrics.get('memory_usage', 0):.1f}%",
            "packet_rate": f"{current_metrics.get('packet_rate', 0):.0f} pps",
            "active_connections": current_metrics.get('active_connections', 0)
        }
        
        self.logger.info(f"Performance summary: {summary}")
    
    def increment_packet_counter(self, count=1):
        """Increment packet counter."""
        self.packet_counter += count
    
    def increment_threat_counter(self, count=1):
        """Increment threat counter."""
        self.threat_counter += count
    
    def get_current_metrics(self):
        """Get current performance metrics."""
        if not self.metrics["cpu_usage"]:
            return {}
        
        # Return latest metrics
        latest_metrics = {}
        for key, values in self.metrics.items():
            if values:
                latest_metrics[key] = values[-1]
        
        return latest_metrics
    
    def get_historical_metrics(self, hours=1):
        """Get historical metrics for specified hours."""
        if not self.timestamps:
            return {}
        
        # Calculate how many samples to include
        samples_per_hour = int(3600 / self.monitoring_interval)
        num_samples = min(hours * samples_per_hour, len(self.timestamps))
        
        if num_samples == 0:
            return {}
        
        # Extract recent data
        recent_timestamps = list(self.timestamps)[-num_samples:]
        historical_data = {}
        
        for key, values in self.metrics.items():
            if values:
                recent_values = list(values)[-num_samples:]
                historical_data[key] = {
                    "timestamps": [ts.isoformat() for ts in recent_timestamps],
                    "values": recent_values,
                    "average": sum(recent_values) / len(recent_values),
                    "maximum": max(recent_values),
                    "minimum": min(recent_values)
                }
        
        return historical_data
    
    def get_performance_report(self):
        """Generate comprehensive performance report."""
        current = self.get_current_metrics()
        historical = self.get_historical_metrics(24)  # Last 24 hours
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "monitoring_interval": self.monitoring_interval,
            "current_metrics": current,
            "historical_metrics": historical,
            "thresholds": self.alert_thresholds,
            "system_info": self._get_system_info(),
            "health_status": self._get_health_status(current)
        }
        
        return report
    
    def _get_system_info(self):
        """Get basic system information."""
        try:
            return {
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_total": psutil.disk_usage("/").total,
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "python_version": psutil.version_info if hasattr(psutil, 'version_info') else "unknown"
            }
        except:
            return {}
    
    def _get_health_status(self, current_metrics):
        """Determine overall system health status."""
        if not current_metrics:
            return "unknown"
        
        # Check if any metric exceeds threshold
        critical_issues = 0
        warning_issues = 0
        
        for metric, value in current_metrics.items():
            if metric in self.alert_thresholds:
                threshold = self.alert_thresholds[metric]
                ratio = value / threshold
                
                if ratio > 1.2:
                    critical_issues += 1
                elif ratio > 0.9:
                    warning_issues += 1
        
        if critical_issues > 0:
            return "critical"
        elif warning_issues > 2:
            return "warning"
        else:
            return "healthy"
    
    def export_metrics(self, filepath, format="json"):
        """Export metrics to file."""
        try:
            report = self.get_performance_report()
            
            if format.lower() == "json":
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Performance metrics exported to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export metrics: {e}")
            return False
