#!/usr/bin/env python3
"""
DLP Security System with Persistent User Storage - Linux Optimized
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import sys
import signal
from datetime import datetime
import random
import csv
import threading
import time
import subprocess
import platform
import psutil
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import logging
from logging.handlers import RotatingFileHandler

# Set up logging
def setup_logging():
    """Configure logging for the application"""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        f'{log_dir}/dlp_system.log',
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Initialize logger
logger = setup_logging()

# Detect Linux environment
def is_linux():
    return platform.system().lower() == 'linux'

def get_linux_info():
    """Get Linux system information"""
    info = {
        'system': platform.system(),
        'release': platform.release(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }
    
    try:
        # Try to get distribution info
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    info['distribution'] = line.split('=', 1)[1].strip().strip('"')
                    break
    except:
        info['distribution'] = 'Unknown'
    
    return info

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dlp-security-system-linux-secret-key-2024')

# Get absolute paths for Linux
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
REPORTS_DIR = BASE_DIR / 'reports'
LOG_DIR = BASE_DIR / 'logs'

# Create necessary directories with proper permissions
for directory in [DATA_DIR, REPORTS_DIR, LOG_DIR]:
    directory.mkdir(exist_ok=True, mode=0o755)

# Set proper file permissions for sensitive files
def set_file_permissions():
    """Set secure permissions for sensitive files"""
    sensitive_files = [
        DATA_DIR / 'users.json',
        DATA_DIR / 'config.json',
        REPORTS_DIR
    ]
    
    for file_path in sensitive_files:
        if file_path.exists():
            try:
                if file_path.is_dir():
                    os.chmod(str(file_path), 0o755)
                else:
                    os.chmod(str(file_path), 0o600)
            except Exception as e:
                logger.warning(f"Could not set permissions for {file_path}: {e}")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Custom Jinja2 filters
@app.template_filter('intcomma')
def intcomma_filter(value):
    """Format integer with commas"""
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

@app.template_filter('format_datetime')
def format_datetime_filter(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object to a string."""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime(format)

@app.template_filter('format_percent')
def format_percent_filter(value):
    """Format as percentage"""
    try:
        return f"{float(value):.1f}%"
    except (ValueError, TypeError):
        return value

@app.template_filter('format_size')
def format_size_filter(value):
    """Format file size in human readable format"""
    try:
        value = float(value)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if value < 1024.0:
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} TB"
    except (ValueError, TypeError):
        return value

@app.context_processor
def utility_processor():
    """Add utility functions to all templates"""
    return dict(
        now=datetime.now(),
        current_datetime=datetime.now(),
        datetime=datetime,
        is_linux=is_linux(),
        linux_info=get_linux_info() if is_linux() else {}
    )

# User class
class User(UserMixin):
    def __init__(self, id, username, email, role, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.role = role
        self.password_hash = password_hash
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'password_hash': self.password_hash
        }

# User database file
USERS_FILE = DATA_DIR / 'users.json'

# Sample data for templates
SAMPLE_SCANS = [
    {"id": "SCAN-001", "name": "System Scan", "status": "completed", "threats_found": 12, "files_scanned": 1250, "start_time": "14:30", "path": "/home/user/documents", "type": "full", "total_matches": 15},
    {"id": "SCAN-002", "name": "User Documents", "status": "scanning", "threats_found": 0, "files_scanned": 450, "start_time": "14:25", "path": "/var/www/html", "type": "quick", "total_matches": 0},
    {"id": "SCAN-003", "name": "Network Drive", "status": "pending", "threats_found": 0, "files_scanned": 0, "start_time": "14:20", "path": "/mnt/nas", "type": "deep", "total_matches": 0},
]

SAMPLE_THREATS = [
    {"id": "THREAT-001", "name": "Credit Card Data Leak", "severity": "high", "location": "/home/user/documents/finance.txt", "time": "2024-01-22 14:30:45", "description": "Credit card numbers found in text files", "detected_by": "Credit Card Detection Policy"},
    {"id": "THREAT-002", "name": "SSN Exposure", "severity": "high", "location": "/var/www/html/config.php", "time": "2024-01-22 14:25:32", "description": "Social Security numbers found in web files", "detected_by": "SSN Protection Policy"},
    {"id": "THREAT-003", "name": "Password File", "severity": "medium", "location": "/tmp/passwords.txt", "time": "2024-01-22 14:20:15", "description": "Unencrypted password file found", "detected_by": "Password Files Policy"},
    {"id": "THREAT-004", "name": "API Key Exposure", "severity": "medium", "location": "/home/user/code/api_keys.json", "time": "2024-01-22 14:15:22", "description": "API keys found in source code", "detected_by": "API Key Detection Policy"},
    {"id": "THREAT-005", "name": "Sensitive Database Backup", "severity": "high", "location": "/backups/db_dump.sql", "time": "2024-01-22 13:45:18", "description": "Unencrypted database backup containing PII", "detected_by": "PII Detection Policy"},
    {"id": "THREAT-006", "name": "Source Code Leak", "severity": "medium", "location": "/home/user/projects/internal_app.zip", "time": "2024-01-22 13:30:55", "description": "Proprietary source code in public folder", "detected_by": "IP Protection Policy"},
]

SAMPLE_ALERTS = [
    {"type": "danger", "icon": "exclamation-triangle", "title": "Critical", "message": "Unauthorized access attempt detected", "time": "2024-01-22 14:32:10"},
    {"type": "warning", "icon": "exclamation-circle", "title": "Warning", "message": "Policy violation in documents folder", "time": "2024-01-22 14:25:45"},
    {"type": "info", "icon": "info-circle", "title": "Info", "message": "Full system scan completed", "time": "2024-01-22 14:15:30"},
    {"type": "warning", "icon": "exclamation-circle", "title": "Warning", "message": "Multiple failed login attempts", "time": "2024-01-22 13:55:22"},
    {"type": "success", "icon": "check-circle", "title": "Success", "message": "Threat database updated successfully", "time": "2024-01-22 13:40:15"},
]

SAMPLE_POLICIES = [
    {"id": 1, "name": "Credit Card Detection", "description": "Detect credit card numbers in files", "status": "active", "type": "pattern", "severity": "high", "created": "2024-01-15", "last_modified": "2024-01-20", "rules": {"patterns": [r"\d{4}-\d{4}-\d{4}-\d{4}", r"\d{16}"]}},
    {"id": 2, "name": "SSN Protection", "description": "Detect Social Security numbers", "status": "active", "type": "pattern", "severity": "high", "created": "2024-01-10", "last_modified": "2024-01-18", "rules": {"patterns": [r"\d{3}-\d{2}-\d{4}"]}},
    {"id": 3, "name": "Password Files", "description": "Detect password files", "status": "draft", "type": "file", "severity": "medium", "created": "2024-01-05", "last_modified": "2024-01-12", "rules": {"extensions": [".pass", ".pwd", "password.txt"]}},
    {"id": 4, "name": "API Key Detection", "description": "Detect exposed API keys", "status": "active", "type": "pattern", "severity": "medium", "created": "2024-01-08", "last_modified": "2024-01-15", "rules": {"patterns": [r"[A-Z0-9]{20}", r"sk_live_[a-zA-Z0-9]{24}"]}},
    {"id": 5, "name": "PII Detection", "description": "Detect Personally Identifiable Information", "status": "active", "type": "pattern", "severity": "high", "created": "2024-01-12", "last_modified": "2024-01-19", "rules": {"patterns": [r"[A-Z][a-z]+ [A-Z][a-z]+", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"]}},
]

# Global report storage
all_reports = []

def load_users():
    """Load users from JSON file"""
    users = {}
    
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, 'r') as f:
                users_data = json.load(f)
                
            # Handle both list and dict formats
            if isinstance(users_data, list):
                # Convert list to dict
                for user_data in users_data:
                    user_id = user_data['id']
                    users[user_id] = User(
                        id=user_id,
                        username=user_data['username'],
                        email=user_data['email'],
                        role=user_data['role'],
                        password_hash=user_data['password_hash']
                    )
            else:
                # Already a dict
                for user_id, user_data in users_data.items():
                    users[int(user_id)] = User(
                        id=user_data['id'],
                        username=user_data['username'],
                        email=user_data['email'],
                        role=user_data['role'],
                        password_hash=user_data['password_hash']
                    )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error loading users: {e}. Creating default users.")
            users = create_default_users()
    else:
        # Create default users
        users = create_default_users()
    
    return users

def create_default_users():
    """Create default users"""
    default_users = {
        1: User(1, 'admin', 'admin@dlp.local', 'admin', generate_password_hash('Admin@123')),
        2: User(2, 'user', 'user@dlp.local', 'user', generate_password_hash('User@123')),
        3: User(3, 'auditor', 'auditor@dlp.local', 'auditor', generate_password_hash('Auditor@123'))
    }
    
    # Save defaults
    save_users(default_users)
    return default_users

def save_users(users):
    """Save users to JSON file"""
    # Ensure data directory exists
    DATA_DIR.mkdir(exist_ok=True)
    
    # Convert to dict format for saving
    users_dict = {}
    for user_id, user_obj in users.items():
        users_dict[user_id] = user_obj.to_dict()
    
    with open(USERS_FILE, 'w') as f:
        json.dump(users_dict, f, indent=2)
    
    # Set secure permissions
    set_file_permissions()

def get_next_user_id():
    """Get the next available user ID"""
    users = load_users()
    if users:
        return max(users.keys()) + 1
    return 1

def save_new_user(user):
    """Save a new user to the database"""
    users = load_users()
    users[user.id] = user
    save_users(users)

# Load users at startup
users_db = load_users()

@login_manager.user_loader
def load_user(user_id):
    return users_db.get(int(user_id))

# Linux-specific system functions
def get_system_stats():
    """Get Linux system statistics"""
    try:
        stats = {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'users': len([u for u in psutil.users()]),
            'processes': len(psutil.pids())
        }
        
        # Get network info
        net_io = psutil.net_io_counters()
        stats['bytes_sent'] = net_io.bytes_sent
        stats['bytes_recv'] = net_io.bytes_recv
        
        return stats
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {}

def get_running_processes():
    """Get list of running processes"""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'user': proc.info['username'],
                    'cpu': proc.info['cpu_percent'],
                    'memory': proc.info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return sorted(processes, key=lambda x: x['memory'], reverse=True)[:10]
    except Exception as e:
        logger.error(f"Error getting processes: {e}")
        return []

# Report generation functions
def generate_report_id():
    """Generate a unique report ID"""
    return f"REP-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

def create_csv_report(report_data, filename):
    """Create a CSV report file"""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ID', 'Name', 'Severity', 'Location', 'Time', 'Description', 'Detected By']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for threat in report_data:
            writer.writerow({
                'ID': threat.get('id', ''),
                'Name': threat.get('name', ''),
                'Severity': threat.get('severity', ''),
                'Location': threat.get('location', ''),
                'Time': threat.get('time', ''),
                'Description': threat.get('description', ''),
                'Detected By': threat.get('detected_by', '')
            })

def create_pdf_report(report_data, filename):
    """Create a PDF report file"""
    try:
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title = Paragraph(f"<para align=center><font size=18><b>DLP Security Report</b></font><br/>"
                         f"<font size=12>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font><br/>"
                         f"<font size=10>System: {platform.system()} {platform.release()}</font></para>", 
                         styles["Normal"])
        elements.append(title)
        elements.append(Spacer(1, 20))
        
        # Summary
        summary = Paragraph("<para><font size=14><b>Executive Summary</b></font></para>", styles["Normal"])
        elements.append(summary)
        
        summary_text = Paragraph(
            f"This report provides a comprehensive overview of detected threats and security incidents. "
            f"Total threats detected: {len(report_data)}",
            styles["Normal"]
        )
        elements.append(summary_text)
        elements.append(Spacer(1, 20))
        
        # Threats table
        if report_data:
            threats_data = [['ID', 'Name', 'Severity', 'Location', 'Time']]
            for threat in report_data:
                threats_data.append([
                    threat.get('id', ''),
                    threat.get('name', ''),
                    threat.get('severity', ''),
                    threat.get('location', ''),
                    threat.get('time', '')
                ])
            
            threats_table = Table(threats_data, colWidths=[80, 150, 80, 150, 100])
            threats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(threats_table)
        
        doc.build(elements)
        return True
    except Exception as e:
        logger.error(f"Error creating PDF report: {e}")
        return False

def generate_report_in_background(report_id, report_type, report_name, threat_data):
    """Background task to generate report"""
    try:
        # Simulate processing time
        for i in range(1, 6):
            time.sleep(1)
            # Update progress (simulated)
            for report in all_reports:
                if report['id'] == report_id:
                    report['progress'] = i * 20
                    break
        
        # Create filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = ''.join(c for c in report_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        filename = REPORTS_DIR / f"{report_id}_{safe_name.replace(' ', '_')}_{timestamp}"
        
        # Generate report based on type
        success = False
        if report_type == 'csv':
            filename = filename.with_suffix('.csv')
            create_csv_report(threat_data, str(filename))
            success = True
            report_format = 'csv'
        elif report_type == 'pdf':
            filename = filename.with_suffix('.pdf')
            success = create_pdf_report(threat_data, str(filename))
            report_format = 'pdf'
        else:  # Default to HTML
            filename = filename.with_suffix('.html')
            # Simple HTML report
            with open(filename, 'w') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>{report_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .threat {{ border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high {{ background-color: #f8d7da; border-color: #f5c6cb; }}
        .medium {{ background-color: #fff3cd; border-color: #ffeaa7; }}
        .low {{ background-color: #d1ecf1; border-color: #bee5eb; }}
        .severity-badge {{ padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        .severity-high {{ background-color: #dc3545; color: white; }}
        .severity-medium {{ background-color: #ffc107; color: black; }}
        .severity-low {{ background-color: #28a745; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report_name}</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Report ID:</strong> {report_id}</p>
        <p><strong>System:</strong> {platform.system()} {platform.release()}</p>
    </div>
    
    <h2>Threat Summary ({len(threat_data)} threats detected)</h2>
                """)
                
                for threat in threat_data:
                    severity = threat.get('severity', 'low').lower()
                    severity_class = f"severity-{severity}"
                    threat_class = severity
                    
                    f.write(f"""
    <div class="threat {threat_class}">
        <h3>{threat.get('name', 'Unknown')} 
            <span class="severity-badge {severity_class}">{threat.get('severity', 'Unknown')}</span>
        </h3>
        <p><strong>Location:</strong> <code>{threat.get('location', 'Unknown')}</code></p>
        <p><strong>Time:</strong> {threat.get('time', 'Unknown')}</p>
        <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
        <p><strong>Detected by:</strong> {threat.get('detected_by', 'Unknown policy')}</p>
    </div>
                    """)
                
                f.write("""
    <footer style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
        <p>Generated by DLP Security System - Linux Edition</p>
        <p>© 2024 Data Loss Prevention System</p>
    </footer>
</body>
</html>
                """)
            success = True
            report_format = 'html'
        
        if success and filename.exists():
            file_size = filename.stat().st_size
            # Update report status
            for report in all_reports:
                if report['id'] == report_id:
                    report['status'] = 'completed'
                    report['path'] = str(filename)
                    report['size'] = f"{file_size / 1024:.1f} KB"
                    report['generated'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    report['format'] = report_format
                    report['download_url'] = f"/download_report/{report_id}"
                    break
        else:
            for report in all_reports:
                if report['id'] == report_id:
                    report['status'] = 'failed'
                    report['error'] = 'Failed to generate report file'
                    break
    except Exception as e:
        logger.error(f"Error in report generation: {e}")
        for report in all_reports:
            if report['id'] == report_id:
                report['status'] = 'failed'
                report['error'] = str(e)
                break

# Initialize with some sample reports
def init_sample_reports():
    """Initialize with sample reports"""
    sample_reports = [
        {"id": "REP-001", "name": "Monthly Compliance Report", "type": "pdf", "report_type": "compliance", 
         "size": "2.5 MB", "generated": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "status": "completed", 
         "path": "", "download_url": "#", "format": "pdf", "progress": 100},
        {"id": "REP-002", "name": "Threat Analysis", "type": "csv", "report_type": "threat", 
         "size": "1.2 MB", "generated": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "status": "completed", 
         "path": "", "download_url": "#", "format": "csv", "progress": 100},
        {"id": "REP-003", "name": "Scan Summary", "type": "html", "report_type": "scan", 
         "size": "850 KB", "generated": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "status": "completed", 
         "path": "", "download_url": "#", "format": "html", "progress": 100},
    ]
    
    # Only add if not already in all_reports
    for sample in sample_reports:
        if not any(r['id'] == sample['id'] for r in all_reports):
            all_reports.append(sample)

# Linux system monitoring endpoint
@app.route('/system_info')
@login_required
def system_info():
    """Display Linux system information"""
    if not is_linux():
        flash('System information is only available on Linux systems', 'warning')
        return redirect(url_for('dashboard'))
    
    stats = get_system_stats()
    processes = get_running_processes()
    linux_info = get_linux_info()
    
    return render_template('system_info.html',
                         user=current_user,
                         stats=stats,
                         processes=processes,
                         linux_info=linux_info,
                         disk_usage=psutil.disk_usage('/') if is_linux() else None)

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find user
        user = None
        for u in users_db.values():
            if u.username == username:
                user = u
                break
        
        if user and user.check_password(password):
            login_user(user)
            logger.info(f"User {username} logged in successfully")
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        # Check password strength
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('register.html')
        
        # Check if user exists
        for user in users_db.values():
            if user.username == username or user.email == email:
                flash('Username or email already exists', 'danger')
                return render_template('register.html')
        
        # Create new user
        user_id = get_next_user_id()
        password_hash = generate_password_hash(password)
        new_user = User(user_id, username, email, 'user', password_hash)
        
        # Save to database
        save_new_user(new_user)
        
        # Add to in-memory database
        users_db[user_id] = new_user
        
        logger.info(f"New user registered: {username} ({email})")
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    logger.info(f"User {username} logged out")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        flash('All fields are required', 'danger')
        return redirect(url_for('profile'))
    
    # Check current password
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    # Check if new passwords match
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))
    
    # Check password strength
    if len(new_password) < 8:
        flash('New password must be at least 8 characters long', 'danger')
        return redirect(url_for('profile'))
    
    # Update password
    current_user.password_hash = generate_password_hash(new_password)
    
    # Save to database
    users_db[current_user.id].password_hash = current_user.password_hash
    save_users(users_db)
    
    logger.info(f"User {current_user.username} changed their password")
    flash('Password changed successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Convert users_db to list for template
    users_list = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'last_login': 'Today'
    } for user in users_db.values()]
    
    # Get system stats for dashboard
    system_stats = get_system_stats() if is_linux() else {}
    
    # Sample recent activity for dashboard
    recent_activity = [
        {"icon": "search", "title": "System Scan Started", "description": "Full system scan initiated", "time": "14:30", "user": "admin"},
        {"icon": "exclamation-triangle", "title": "Threat Detected", "description": "Credit card data found", "time": "14:25", "user": "system"},
        {"icon": "user-plus", "title": "New User Added", "description": "New auditor account created", "time": "14:20", "user": "admin"},
        {"icon": "file-text", "title": "Report Generated", "description": "Monthly compliance report", "time": "14:15", "user": "system"},
    ]
    
    return render_template('dashboard_simple.html', 
                         user=current_user,
                         total_scans=len(SAMPLE_SCANS),
                         total_threats=len(SAMPLE_THREATS),
                         total_users=len(users_db),
                         active_policies=len([p for p in SAMPLE_POLICIES if p['status'] == 'active']),
                         recent_scans=SAMPLE_SCANS[:3],
                         recent_threats=SAMPLE_THREATS[:3],
                         recent_activity=recent_activity,
                         system_stats=system_stats)

@app.route('/scanner')
@login_required
def scanner():
    # Combine sample scans with any user scans
    all_scans = SAMPLE_SCANS.copy()
    
    return render_template('scanner.html', 
                         user=current_user,
                         scans=all_scans,
                         dlp_available=True)

@app.route('/monitor')
@login_required
def monitor():
    # Generate some active scans for the monitor page
    current_scans = [
        {"id": "SCAN-002", "name": "User Documents", "progress": 65, "files_scanned": 450, "threats_found": 0, "started": "14:25"},
        {"id": "SCAN-004", "name": "Email Archive", "progress": 30, "files_scanned": 220, "threats_found": 2, "started": "14:35"},
    ]
    
    recent_activity = [
        {"type": "scan", "message": "System scan completed", "time": "14:30", "user": "system"},
        {"type": "alert", "message": "New threat detected in /tmp", "time": "14:25", "user": "system"},
        {"type": "user", "message": "User 'auditor' logged in", "time": "14:20", "user": "system"},
        {"type": "policy", "message": "New policy 'API Key Detection' activated", "time": "14:15", "user": "admin"},
    ]
    
    # Get system stats
    system_stats = get_system_stats() if is_linux() else {}
    
    return render_template('monitor.html', 
                         user=current_user,
                         alerts=SAMPLE_ALERTS,
                         threats=SAMPLE_THREATS[:8],
                         current_scans=current_scans,
                         recent_activity=recent_activity,
                         system_stats=system_stats,
                         dlp_available=True)

@app.route('/alerts')
@login_required
def alerts():
    return render_template('alerts.html', 
                         user=current_user,
                         alerts=SAMPLE_ALERTS,
                         threats=SAMPLE_THREATS[:4])

@app.route('/policies')
@login_required
def policies():
    return render_template('policies.html', 
                         user=current_user,
                         policies=SAMPLE_POLICIES,
                         dlp_available=True)

@app.route('/reports')
@login_required
def reports():
    # Initialize sample reports if empty
    if not all_reports:
        init_sample_reports()
    
    return render_template('reports.html', 
                         user=current_user,
                         reports=all_reports,
                         dlp_available=True)

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    report_name = request.form.get('report_name', 'Security Report')
    report_type = request.form.get('report_type', 'pdf')
    report_range = request.form.get('report_range', 'all')
    
    # Generate report ID
    report_id = generate_report_id()
    
    # Prepare threat data based on range
    if report_range == 'today':
        threat_data = SAMPLE_THREATS[:3]  # Recent threats
    elif report_range == 'week':
        threat_data = SAMPLE_THREATS[:5]  # Last week's threats
    else:
        threat_data = SAMPLE_THREATS  # All threats
    
    # Create report entry
    new_report = {
        'id': report_id,
        'name': report_name,
        'type': report_type,
        'report_type': 'custom',
        'size': '0 KB',
        'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'generating',
        'path': '',
        'download_url': '',
        'format': report_type,
        'progress': 0
    }
    
    all_reports.insert(0, new_report)  # Add at beginning
    
    # Start background generation
    thread = threading.Thread(
        target=generate_report_in_background,
        args=(report_id, report_type, report_name, threat_data)
    )
    thread.daemon = True
    thread.start()
    
    logger.info(f"Report generation started: {report_id} ({report_name})")
    flash(f'Report "{report_name}" is being generated. It will be available shortly.', 'info')
    return redirect(url_for('reports'))

@app.route('/get_report_status/<report_id>')
@login_required
def get_report_status(report_id):
    """Get the status of a report for AJAX updates"""
    for report in all_reports:
        if report['id'] == report_id:
            return jsonify({
                'status': report.get('status', 'unknown'),
                'progress': report.get('progress', 0),
                'download_url': report.get('download_url', ''),
                'generated': report.get('generated', ''),
                'size': report.get('size', '')
            })
    return jsonify({'status': 'not_found'}), 404

@app.route('/download_report/<report_id>')
@login_required
def download_report(report_id):
    """Download a generated report"""
    for report in all_reports:
        if report['id'] == report_id and report['status'] == 'completed':
            file_path = Path(report.get('path', ''))
            if file_path.exists():
                filename = file_path.name
                logger.info(f"User {current_user.username} downloaded report: {report_id}")
                return send_file(
                    str(file_path),
                    as_attachment=True,
                    download_name=filename,
                    mimetype=f'application/{report.get("format", "octet-stream")}'
                )
    
    flash('Report not found or not ready for download', 'warning')
    return redirect(url_for('reports'))

@app.route('/view_report/<report_id>')
@login_required
def view_report(report_id):
    """View a report in browser"""
    for report in all_reports:
        if report['id'] == report_id and report['status'] == 'completed':
            file_path = Path(report.get('path', ''))
            if file_path.exists():
                # For HTML reports, we can display directly
                if report.get('format') == 'html':
                    with open(file_path, 'r') as f:
                        content = f.read()
                    return content
                # For other formats, offer download
                else:
                    return redirect(url_for('download_report', report_id=report_id))
    
    flash('Report not found or not ready for viewing', 'warning')
    return redirect(url_for('reports'))

@app.route('/threats')
@login_required
def threats():
    return render_template('threats.html', 
                         user=current_user,
                         threats=SAMPLE_THREATS)

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Convert users_db to list for template
    users_list = [{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'last_login': 'Today'
    } for user in users_db.values()]
    
    return render_template('users.html', 
                         user=current_user,
                         users=users_list)

@app.route('/profile')
@login_required
def profile():
    # Sample user activity for profile page
    user_activity = [
        {"action": "login", "timestamp": "2024-01-22 14:25:30", "ip": "192.168.1.100", "browser": "Chrome/120.0"},
        {"action": "scan_started", "timestamp": "2024-01-22 14:20:15", "details": "Initiated full system scan", "location": "/"},
        {"action": "report_viewed", "timestamp": "2024-01-22 14:15:45", "details": "Viewed monthly compliance report", "report": "REP-001"},
        {"action": "policy_updated", "timestamp": "2024-01-22 14:10:22", "details": "Modified SSN Protection policy", "policy": "SSN Protection"},
        {"action": "login", "timestamp": "2024-01-22 09:30:15", "ip": "192.168.1.100", "browser": "Chrome/120.0"},
    ]
    
    return render_template('profile.html', 
                         user=current_user,
                         activity=user_activity,
                         join_date="2024-01-01")

# Favicon route to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204

# Error handlers
@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.path}")
    return render_template('404.html', 
                         user=current_user if current_user.is_authenticated else None), 404

@app.errorhandler(500)
def server_error(error):
    logger.error(f"500 error: {error}")
    return render_template('500.html', 
                         user=current_user if current_user.is_authenticated else None,
                         dlp_available=True), 500

# Graceful shutdown handler
def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Shutdown signal received. Gracefully shutting down...")
    print("\n🔄 Shutting down DLP Security System gracefully...")
    sys.exit(0)

if __name__ == '__main__':
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize sample reports
    init_sample_reports()
    
    # Set file permissions
    set_file_permissions()
    
    print("=" * 60)
    print("🔐 DLP SECURITY SYSTEM - LINUX EDITION")
    print("=" * 60)
    print(f"📁 Project directory: {BASE_DIR}")
    print(f"📊 Data directory: {DATA_DIR}")
    print(f"📄 Reports directory: {REPORTS_DIR}")
    print(f"📝 Log directory: {LOG_DIR}")
    print("\n✅ System checks:")
    print(f"   • Python version: {platform.python_version()}")
    print(f"   • Operating System: {platform.system()} {platform.release()}")
    print(f"   • System architecture: {platform.machine()}")
    print(f"   • Virtual environment: {'Active' if hasattr(sys, 'real_prefix') or sys.base_prefix != sys.prefix else 'Not active'}")
    
    print("\n👤 Default Users:")
    print("   admin:Admin@123    (Admin role)")
    print("   user:User@123      (User role)")
    print("   auditor:Auditor@123 (Auditor role)")
    
    print("\n📊 Features:")
    print("   • Real-time report generation")
    print("   • PDF/CSV/HTML report formats")
    print("   • Background processing")
    print("   • File download and viewing")
    print("   • Progress tracking")
    print("   • Linux system monitoring")
    print("   • Process management")
    print("   • Secure file permissions")
    print("   • Comprehensive logging")
    
    print("\n🌐 Access: http://localhost:5000")
    print("   Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Check if running on Linux
    if is_linux():
        print("🐧 Running on Linux - System monitoring enabled")
    else:
        print("⚠️  Not running on Linux - Some features limited")
    
    # Run the application
    try:
        app.run(
            debug=True,
            host='0.0.0.0',
            port=5000,
            use_reloader=False  # Disable reloader for better signal handling
        )
    except KeyboardInterrupt:
        print("\n👋 Shutdown requested by user")
        logger.info("Application shutdown by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"\n❌ Error: {e}")
