#!/usr/bin/env python3
"""
Linux System Monitor for DLP Security System
Runs as a background daemon to monitor system health
"""
import os
import sys
import time
import json
import psutil
import socket
import logging
from datetime import datetime
from pathlib import Path
import threading
import subprocess
import signal

class LinuxSystemMonitor:
    def __init__(self):
        self.log_dir = Path('/var/log/dlp_system')
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.setup_logging()
        
        self.monitoring = False
        self.metrics_file = self.log_dir / 'system_metrics.json'
        self.alerts_file = self.log_dir / 'system_alerts.json'
        self.status_file = self.log_dir / 'monitor_status.json'
        
        # Thresholds for alerts
        self.thresholds = {
            'cpu_percent': 85,
            'memory_percent': 90,
            'disk_percent': 95,
            'load_1min': 5.0,
            'temperature': 80,  # Celsius
            'process_count': 1000,
            'network_errors': 100,
            'swap_usage': 50
        }
        
        self.alerts = []
        self.metrics_history = []
        self.max_history = 1000  # Keep last 1000 metrics
        self.check_interval = 30  # seconds
        
        self.load_alerts()
        self.load_metrics()
        
    def setup_logging(self):
        """Setup monitoring logging"""
        log_file = self.log_dir / 'monitor.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('LinuxMonitor')
        
        # Set up error logging
        error_handler = logging.FileHandler(self.log_dir / 'monitor_errors.log')
        error_handler.setLevel(logging.ERROR)
        error_formatter = logging.Formatter('%(asctime)s - %(name)s - ERROR - %(message)s')
        error_handler.setFormatter(error_formatter)
        self.logger.addHandler(error_handler)
        
    def load_alerts(self):
        """Load existing alerts from file"""
        if self.alerts_file.exists():
            try:
                with open(self.alerts_file, 'r') as f:
                    self.alerts = json.load(f)
            except json.JSONDecodeError:
                self.logger.warning("Could not load alerts file, starting fresh")
                self.alerts = []
        else:
            self.alerts = []
            
    def load_metrics(self):
        """Load metrics history"""
        if self.metrics_file.exists():
            try:
                with open(self.metrics_file, 'r') as f:
                    self.metrics_history = json.load(f)
            except json.JSONDecodeError:
                self.logger.warning("Could not load metrics file, starting fresh")
                self.metrics_history = []
        else:
            self.metrics_history = []
            
    def save_alerts(self):
        """Save alerts to file"""
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump(self.alerts[-500:], f, indent=2)  # Keep last 500 alerts
        except Exception as e:
            self.logger.error(f"Failed to save alerts: {e}")
            
    def save_metrics(self):
        """Save metrics to file"""
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(self.metrics_history[-self.max_history:], f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save metrics: {e}")
            
    def get_cpu_metrics(self):
        """Collect CPU metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_times = psutil.cpu_times_percent(interval=1)
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            
            return {
                'percent': cpu_percent,
                'user': getattr(cpu_times, 'user', 0),
                'system': getattr(cpu_times, 'system', 0),
                'idle': getattr(cpu_times, 'idle', 0),
                'load_1min': load_avg[0],
                'load_5min': load_avg[1],
                'load_15min': load_avg[2],
                'cpu_count': psutil.cpu_count(),
                'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else None
            }
        except Exception as e:
            self.logger.error(f"Error getting CPU metrics: {e}")
            return {}
            
    def get_memory_metrics(self):
        """Collect memory metrics"""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'free': memory.free,
                'percent': memory.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_free': swap.free,
                'swap_percent': swap.percent
            }
        except Exception as e:
            self.logger.error(f"Error getting memory metrics: {e}")
            return {}
            
    def get_disk_metrics(self):
        """Collect disk metrics"""
        try:
            disk_metrics = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_metrics.append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except Exception as e:
                    self.logger.warning(f"Could not get disk usage for {partition.mountpoint}: {e}")
                    continue
            return disk_metrics
        except Exception as e:
            self.logger.error(f"Error getting disk metrics: {e}")
            return []
            
    def get_network_metrics(self):
        """Collect network metrics"""
        try:
            net_io = psutil.net_io_counters()
            net_if_stats = {}
            
            # Get per-interface stats
            for interface, stats in psutil.net_if_stats().items():
                net_if_stats[interface] = {
                    'isup': stats.isup,
                    'speed': stats.speed,
                    'mtu': stats.mtu
                }
                
            # Get per-interface IO counters
            net_if_io = psutil.net_io_counters(pernic=True)
            for interface in net_if_io:
                if interface in net_if_stats:
                    net_if_stats[interface]['bytes_sent'] = net_if_io[interface].bytes_sent
                    net_if_stats[interface]['bytes_recv'] = net_if_io[interface].bytes_recv
                    net_if_stats[interface]['packets_sent'] = net_if_io[interface].packets_sent
                    net_if_stats[interface]['packets_recv'] = net_if_io[interface].packets_recv
                    net_if_stats[interface]['errin'] = net_if_io[interface].errin
                    net_if_stats[interface]['errout'] = net_if_io[interface].errout
                    net_if_stats[interface]['dropin'] = net_if_io[interface].dropin
                    net_if_stats[interface]['dropout'] = net_if_io[interface].dropout
                    
            return {
                'total_bytes_sent': net_io.bytes_sent,
                'total_bytes_recv': net_io.bytes_recv,
                'total_packets_sent': net_io.packets_sent,
                'total_packets_recv': net_io.packets_recv,
                'total_errin': net_io.errin,
                'total_errout': net_io.errout,
                'total_dropin': net_io.dropin,
                'total_dropout': net_io.dropout,
                'interfaces': net_if_stats
            }
        except Exception as e:
            self.logger.error(f"Error getting network metrics: {e}")
            return {}
            
    def get_process_metrics(self):
        """Collect process metrics"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    process_info = proc.info
                    processes.append({
                        'pid': process_info['pid'],
                        'name': process_info['name'],
                        'user': process_info['username'],
                        'cpu': process_info['cpu_percent'],
                        'memory': process_info['memory_percent'],
                        'status': process_info['status']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Get top processes by CPU and memory
            top_cpu = sorted(processes, key=lambda x: x['cpu'], reverse=True)[:10]
            top_memory = sorted(processes, key=lambda x: x['memory'], reverse=True)[:10]
            
            return {
                'total_count': len(processes),
                'top_cpu': top_cpu,
                'top_memory': top_memory,
                'zombie_count': len([p for p in processes if p['status'] == psutil.STATUS_ZOMBIE])
            }
        except Exception as e:
            self.logger.error(f"Error getting process metrics: {e}")
            return {}
            
    def get_temperature(self):
        """Get system temperature if available"""
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if entry.current:
                            return {
                                'sensor': name,
                                'current': entry.current,
                                'high': entry.high,
                                'critical': entry.critical
                            }
            return None
        except Exception as e:
            self.logger.warning(f"Could not get temperature: {e}")
            return None
            
    def check_services(self):
        """Check important DLP services"""
        services = {
            'dlp_web': self.check_dlp_web_service(),
            'dlp_monitor': 'running',  # We're running
            'database': self.check_database_service(),
            'firewall': self.check_firewall_service()
        }
        return services
        
    def check_dlp_web_service(self):
        """Check if DLP web service is running"""
        try:
            # Check if port 5000 is listening
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', 5000))
            sock.close()
            return 'running' if result == 0 else 'stopped'
        except:
            return 'unknown'
            
    def check_database_service(self):
        """Check database service"""
        try:
            # Check common database ports
            ports = [5432, 3306, 27017]  # PostgreSQL, MySQL, MongoDB
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    return f'running on port {port}'
            return 'stopped'
        except:
            return 'unknown'
            
    def check_firewall_service(self):
        """Check firewall service"""
        try:
            # Try different firewall systems
            for cmd in ['systemctl is-active firewalld', 'systemctl is-active ufw', 'iptables -L']:
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if result.returncode == 0:
                    return 'active'
            return 'inactive'
        except:
            return 'unknown'
            
    def check_thresholds(self, metrics):
        """Check metrics against thresholds and generate alerts"""
        alerts_generated = []
        
        # Check CPU
        if 'cpu' in metrics and 'percent' in metrics['cpu']:
            if metrics['cpu']['percent'] > self.thresholds['cpu_percent']:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'warning' if metrics['cpu']['percent'] < 95 else 'critical',
                    'type': 'cpu_usage',
                    'message': f"High CPU usage: {metrics['cpu']['percent']}%",
                    'value': metrics['cpu']['percent'],
                    'threshold': self.thresholds['cpu_percent']
                }
                alerts_generated.append(alert)
                
        # Check memory
        if 'memory' in metrics and 'percent' in metrics['memory']:
            if metrics['memory']['percent'] > self.thresholds['memory_percent']:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'warning' if metrics['memory']['percent'] < 95 else 'critical',
                    'type': 'memory_usage',
                    'message': f"High memory usage: {metrics['memory']['percent']}%",
                    'value': metrics['memory']['percent'],
                    'threshold': self.thresholds['memory_percent']
                }
                alerts_generated.append(alert)
                
        # Check disk
        if 'disk' in metrics and isinstance(metrics['disk'], list):
            for disk in metrics['disk']:
                if disk['percent'] > self.thresholds['disk_percent']:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'warning' if disk['percent'] < 98 else 'critical',
                        'type': 'disk_usage',
                        'message': f"High disk usage on {disk['mountpoint']}: {disk['percent']}%",
                        'value': disk['percent'],
                        'threshold': self.thresholds['disk_percent'],
                        'mountpoint': disk['mountpoint']
                    }
                    alerts_generated.append(alert)
                    
        # Check swap
        if 'memory' in metrics and 'swap_percent' in metrics['memory']:
            if metrics['memory']['swap_percent'] > self.thresholds['swap_usage']:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'warning',
                    'type': 'swap_usage',
                    'message': f"High swap usage: {metrics['memory']['swap_percent']}%",
                    'value': metrics['memory']['swap_percent'],
                    'threshold': self.thresholds['swap_usage']
                }
                alerts_generated.append(alert)
                
        # Check network errors
        if 'network' in metrics and 'total_errin' in metrics['network']:
            if metrics['network']['total_errin'] > self.thresholds['network_errors']:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'warning',
                    'type': 'network_errors',
                    'message': f"High network errors: {metrics['network']['total_errin']}",
                    'value': metrics['network']['total_errin'],
                    'threshold': self.thresholds['network_errors']
                }
                alerts_generated.append(alert)
                
        # Add alerts to history
        for alert in alerts_generated:
            self.alerts.append(alert)
            self.logger.warning(f"Alert: {alert['message']}")
            
        # Save alerts if any were generated
        if alerts_generated:
            self.save_alerts()
            # Also send notification (could be email, webhook, etc.)
            self.send_notifications(alerts_generated)
            
        return alerts_generated
        
    def send_notifications(self, alerts):
        """Send notifications for alerts"""
        # This is a placeholder for notification logic
        # You could integrate with email, Slack, webhooks, etc.
        for alert in alerts:
            if alert['severity'] == 'critical':
                # Log critical alerts prominently
                self.logger.critical(f"CRITICAL ALERT: {alert['message']}")
                
    def collect_all_metrics(self):
        """Collect all system metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'cpu': self.get_cpu_metrics(),
            'memory': self.get_memory_metrics(),
            'disk': self.get_disk_metrics(),
            'network': self.get_network_metrics(),
            'processes': self.get_process_metrics(),
            'temperature': self.get_temperature(),
            'services': self.check_services(),
            'uptime': time.time() - psutil.boot_time()
        }
        
        # Check thresholds and generate alerts
        self.check_thresholds(metrics)
        
        # Add to history
        self.metrics_history.append(metrics)
        
        # Save metrics
        self.save_metrics()
        
        # Save status
        self.save_status(metrics)
        
        return metrics
        
    def save_status(self, metrics):
        """Save current status"""
        status = {
            'last_update': datetime.now().isoformat(),
            'status': 'healthy',
            'alerts_count': len([a for a in self.alerts[-24:] if a['severity'] == 'critical']),
            'cpu_percent': metrics.get('cpu', {}).get('percent', 0),
            'memory_percent': metrics.get('memory', {}).get('percent', 0),
            'disk_percent': max([d.get('percent', 0) for d in metrics.get('disk', [])] or [0])
        }
        
        try:
            with open(self.status_file, 'w') as f:
                json.dump(status, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save status: {e}")
            
    def monitor_loop(self):
        """Main monitoring loop"""
        self.logger.info("Starting Linux System Monitor")
        self.monitoring = True
        
        try:
            while self.monitoring:
                start_time = time.time()
                
                try:
                    metrics = self.collect_all_metrics()
                    
                    # Log summary every 10 cycles
                    if len(self.metrics_history) % 10 == 0:
                        self.logger.info(f"Metrics collected: CPU={metrics['cpu']['percent']}%, "
                                       f"Memory={metrics['memory']['percent']}%, "
                                       f"Processes={metrics['processes']['total_count']}")
                        
                except Exception as e:
                    self.logger.error(f"Error in monitoring cycle: {e}")
                    
                # Sleep for remaining interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.check_interval - elapsed)
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            self.logger.info("Monitor stopped by user")
        except Exception as e:
            self.logger.error(f"Monitor stopped unexpectedly: {e}")
        finally:
            self.monitoring = False
            self.logger.info("Linux System Monitor stopped")
            
    def start(self):
        """Start monitoring in a separate thread"""
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Monitor thread started")
        
    def stop(self):
        """Stop monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        self.logger.info("Monitor stopped")
        
    def get_recent_alerts(self, count=10):
        """Get recent alerts"""
        return self.alerts[-count:] if self.alerts else []
        
    def get_metrics_summary(self, hours=1):
        """Get metrics summary for the last N hours"""
        cutoff = datetime.now().timestamp() - (hours * 3600)
        recent_metrics = []
        
        for metric in self.metrics_history:
            try:
                metric_time = datetime.fromisoformat(metric['timestamp']).timestamp()
                if metric_time >= cutoff:
                    recent_metrics.append(metric)
            except:
                continue
                
        return recent_metrics
        
def main():
    """Main function"""
    monitor = LinuxSystemMonitor()
    
    # Handle signals
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        monitor.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("=" * 60)
    print("Linux System Monitor for DLP Security System")
    print("=" * 60)
    print(f"Log directory: {monitor.log_dir}")
    print(f"Check interval: {monitor.check_interval} seconds")
    print("Press Ctrl+C to stop")
    print("-" * 60)
    
    # Start monitoring
    monitor.start()
    
    # Keep main thread alive
    try:
        while monitor.monitoring:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        
if __name__ == "__main__":
    main()
