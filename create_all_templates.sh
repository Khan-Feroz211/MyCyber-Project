#!/bin/bash

echo "🎨 Creating ALL Missing Templates..."
echo ""

# Create templates directory structure
mkdir -p templates/components
mkdir -p templates/admin
mkdir -p templates/user
mkdir -p templates/errors

# ══════════════════════════════════════════════════════════════
# CORE TEMPLATES
# ══════════════════════════════════════════════════════════════

# 1. index.html (Home/Landing Page)
cat > templates/index.html << 'EOF1'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLP Security System - Home</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="landing-page">
        <div class="container text-center">
            <div class="landing-logo">
                <i class="fas fa-shield-alt"></i>
            </div>
            <h1 class="landing-title">Advanced DLP Security System</h1>
            <p class="landing-subtitle">Real-time Data Loss Prevention & Threat Detection</p>
            
            <div class="mt-5">
                <a href="{{ url_for('login') }}" class="btn-landing me-3">
                    <i class="fas fa-sign-in-alt"></i> Login
                </a>
                <a href="{{ url_for('register') }}" class="btn-landing-outline">
                    <i class="fas fa-user-plus"></i> Register
                </a>
            </div>
            
            <div class="row mt-5">
                <div class="col-md-4 mb-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-brain"></i>
                        </div>
                        <h3>ML-Powered Detection</h3>
                        <p>Advanced machine learning algorithms detect threats in real-time</p>
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-lock"></i>
                        </div>
                        <h3>AES-256 Encryption</h3>
                        <p>Military-grade encryption protects your sensitive data</p>
                    </div>
                </div>
                <div class="col-md-4 mb-4">
                    <div class="feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-chart-line"></i>
                        </div>
                        <h3>Real-time Monitoring</h3>
                        <p>24/7 monitoring and instant threat alerts</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF1

echo "✅ index.html created"

# 2. encrypt.html
cat > templates/encrypt.html << 'EOF2'
{% extends "base.html" %}

{% block title %}Encrypt Files{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <div class="card">
                <div class="card-header">
                    <h3><i class="fas fa-lock"></i> File Encryption</h3>
                </div>
                <div class="card-body">
                    <form method="POST" enctype="multipart/form-data" id="encryptForm">
                        <div class="form-group mb-4">
                            <label for="file" class="form-label">
                                <i class="fas fa-file"></i> Select File to Encrypt
                            </label>
                            <input type="file" class="form-control" id="file" name="file" required>
                            <small class="form-text text-muted">Maximum file size: 10MB</small>
                        </div>
                        
                        <div class="form-group mb-4">
                            <label for="algorithm" class="form-label">
                                <i class="fas fa-cog"></i> Encryption Algorithm
                            </label>
                            <select class="form-control" id="algorithm" name="algorithm">
                                <option value="AES-256" selected>AES-256 (Recommended)</option>
                                <option value="ChaCha20">ChaCha20 Poly1305</option>
                                <option value="RSA-2048">RSA-2048</option>
                            </select>
                        </div>
                        
                        <div class="form-group mb-4">
                            <label for="password" class="form-label">
                                <i class="fas fa-key"></i> Encryption Password (Optional)
                            </label>
                            <input type="password" class="form-control" id="password" name="password" 
                                   placeholder="Leave empty for system-generated key">
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-primary btn-lg">
                                <i class="fas fa-lock"></i> Encrypt File
                            </button>
                            <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">
                                <i class="fas fa-arrow-left"></i> Back to Dashboard
                            </a>
                        </div>
                    </form>
                </div>
            </div>
            
            <div class="card mt-4">
                <div class="card-body">
                    <h5><i class="fas fa-info-circle"></i> How It Works</h5>
                    <ul>
                        <li>Upload your file securely</li>
                        <li>Choose encryption algorithm</li>
                        <li>File is encrypted with AES-256 or selected algorithm</li>
                        <li>Download encrypted file and encryption key</li>
                        <li>Keep the key safe - you'll need it to decrypt</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF2

echo "✅ encrypt.html created"

# 3. decrypt.html
cat > templates/decrypt.html << 'EOF3'
{% extends "base.html" %}

{% block title %}Decrypt Files{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <div class="card">
                <div class="card-header">
                    <h3><i class="fas fa-unlock"></i> File Decryption</h3>
                </div>
                <div class="card-body">
                    <form method="POST" enctype="multipart/form-data">
                        <div class="form-group mb-4">
                            <label for="encrypted_file" class="form-label">
                                <i class="fas fa-file-lock"></i> Encrypted File
                            </label>
                            <input type="file" class="form-control" id="encrypted_file" 
                                   name="encrypted_file" required>
                        </div>
                        
                        <div class="form-group mb-4">
                            <label for="key_file" class="form-label">
                                <i class="fas fa-key"></i> Encryption Key File
                            </label>
                            <input type="file" class="form-control" id="key_file" 
                                   name="key_file" accept=".key">
                            <small class="form-text text-muted">Or enter password below</small>
                        </div>
                        
                        <div class="form-group mb-4">
                            <label for="password" class="form-label">
                                <i class="fas fa-lock"></i> Decryption Password
                            </label>
                            <input type="password" class="form-control" id="password" 
                                   name="password" placeholder="Enter encryption password">
                        </div>
                        
                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-success btn-lg">
                                <i class="fas fa-unlock"></i> Decrypt File
                            </button>
                            <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">
                                <i class="fas fa-arrow-left"></i> Back to Dashboard
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF3

echo "✅ decrypt.html created"

# 4. scan.html
cat > templates/scan.html << 'EOF4'
{% extends "base.html" %}

{% block title %}File Scanning{% endblock %}

{% block content %}
<div class="container mt-4">
    <h2><i class="fas fa-search"></i> File & Directory Scanning</h2>
    
    <div class="row mt-4">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h4><i class="fas fa-folder-open"></i> Scan Directory</h4>
                </div>
                <div class="card-body">
                    <form method="POST" action="{{ url_for('scan_directory') }}">
                        <div class="form-group mb-3">
                            <label for="directory_path">Directory Path</label>
                            <input type="text" class="form-control" id="directory_path" 
                                   name="directory_path" placeholder="/path/to/directory" required>
                        </div>
                        <div class="form-check mb-3">
                            <input type="checkbox" class="form-check-input" id="recursive" 
                                   name="recursive" checked>
                            <label class="form-check-label" for="recursive">
                                Scan subdirectories
                            </label>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-play"></i> Start Scan
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-6">
            <div class="card">
                <div class="card-header bg-success text-white">
                    <h4><i class="fas fa-file-upload"></i> Scan File</h4>
                </div>
                <div class="card-body">
                    <form method="POST" action="{{ url_for('scan_file') }}" 
                          enctype="multipart/form-data">
                        <div class="form-group mb-3">
                            <label for="file">Upload File</label>
                            <input type="file" class="form-control" id="file" 
                                   name="file" required>
                        </div>
                        <div class="form-group mb-3">
                            <label for="scan_type">Scan Type</label>
                            <select class="form-control" id="scan_type" name="scan_type">
                                <option value="quick">Quick Scan</option>
                                <option value="deep" selected>Deep Scan</option>
                                <option value="ml">ML Analysis</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-success w-100">
                            <i class="fas fa-upload"></i> Upload & Scan
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <div class="card mt-4">
        <div class="card-header">
            <h4><i class="fas fa-history"></i> Recent Scans</h4>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Target</th>
                            <th>Type</th>
                            <th>Threats Found</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>2026-01-12 20:30</td>
                            <td>/home/user/documents</td>
                            <td>Directory</td>
                            <td><span class="badge badge-warning">3</span></td>
                            <td><span class="badge badge-success">Completed</span></td>
                            <td>
                                <button class="btn btn-sm btn-primary">View</button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF4

echo "✅ scan.html created"

# 5. reports.html
cat > templates/reports.html << 'EOF5'
{% extends "base.html" %}

{% block title %}Reports{% endblock %}

{% block content %}
<div class="container mt-4">
    <h2><i class="fas fa-file-alt"></i> Security Reports</h2>
    
    <div class="row mt-4">
        <div class="col-md-12">
            <div class="card">
                <div class="card-header">
                    <h4>Generate New Report</h4>
                </div>
                <div class="card-body">
                    <form method="POST" class="row g-3">
                        <div class="col-md-3">
                            <label for="report_type">Report Type</label>
                            <select class="form-control" id="report_type" name="report_type">
                                <option value="daily">Daily Summary</option>
                                <option value="weekly">Weekly Summary</option>
                                <option value="monthly">Monthly Summary</option>
                                <option value="custom">Custom Range</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label for="start_date">Start Date</label>
                            <input type="date" class="form-control" id="start_date" name="start_date">
                        </div>
                        <div class="col-md-3">
                            <label for="end_date">End Date</label>
                            <input type="date" class="form-control" id="end_date" name="end_date">
                        </div>
                        <div class="col-md-3">
                            <label for="format">Format</label>
                            <select class="form-control" id="format" name="format">
                                <option value="pdf">PDF</option>
                                <option value="csv">CSV</option>
                                <option value="excel">Excel</option>
                                <option value="html">HTML</option>
                            </select>
                        </div>
                        <div class="col-12">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-file-download"></i> Generate Report
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
    
    <div class="card mt-4">
        <div class="card-header">
            <h4><i class="fas fa-list"></i> Generated Reports</h4>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Generated</th>
                            <th>Report Type</th>
                            <th>Period</th>
                            <th>Format</th>
                            <th>Size</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>2026-01-12</td>
                            <td>Daily Summary</td>
                            <td>Jan 11, 2026</td>
                            <td>PDF</td>
                            <td>2.3 MB</td>
                            <td>
                                <button class="btn btn-sm btn-success">
                                    <i class="fas fa-download"></i> Download
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF5

echo "✅ reports.html created"

# 6. settings.html
cat > templates/settings.html << 'EOF6'
{% extends "base.html" %}

{% block title %}Settings{% endblock %}

{% block content %}
<div class="container mt-4">
    <h2><i class="fas fa-cog"></i> System Settings</h2>
    
    <div class="row mt-4">
        <div class="col-md-3">
            <div class="list-group">
                <a href="#profile" class="list-group-item list-group-item-action active" 
                   data-bs-toggle="list">
                    <i class="fas fa-user"></i> Profile
                </a>
                <a href="#security" class="list-group-item list-group-item-action" 
                   data-bs-toggle="list">
                    <i class="fas fa-shield-alt"></i> Security
                </a>
                <a href="#notifications" class="list-group-item list-group-item-action" 
                   data-bs-toggle="list">
                    <i class="fas fa-bell"></i> Notifications
                </a>
                <a href="#system" class="list-group-item list-group-item-action" 
                   data-bs-toggle="list">
                    <i class="fas fa-server"></i> System
                </a>
            </div>
        </div>
        
        <div class="col-md-9">
            <div class="tab-content">
                <!-- Profile Tab -->
                <div class="tab-pane fade show active" id="profile">
                    <div class="card">
                        <div class="card-header">
                            <h4>Profile Settings</h4>
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <div class="form-group mb-3">
                                    <label>Username</label>
                                    <input type="text" class="form-control" 
                                           value="{{ current_user.username }}" readonly>
                                </div>
                                <div class="form-group mb-3">
                                    <label>Email</label>
                                    <input type="email" class="form-control" 
                                           value="{{ current_user.email }}" name="email">
                                </div>
                                <div class="form-group mb-3">
                                    <label>Role</label>
                                    <input type="text" class="form-control" 
                                           value="{{ current_user.role }}" readonly>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    Update Profile
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Security Tab -->
                <div class="tab-pane fade" id="security">
                    <div class="card">
                        <div class="card-header">
                            <h4>Security Settings</h4>
                        </div>
                        <div class="card-body">
                            <form method="POST" action="{{ url_for('change_password') }}">
                                <div class="form-group mb-3">
                                    <label>Current Password</label>
                                    <input type="password" class="form-control" 
                                           name="current_password" required>
                                </div>
                                <div class="form-group mb-3">
                                    <label>New Password</label>
                                    <input type="password" class="form-control" 
                                           name="new_password" required>
                                </div>
                                <div class="form-group mb-3">
                                    <label>Confirm New Password</label>
                                    <input type="password" class="form-control" 
                                           name="confirm_password" required>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    Change Password
                                </button>
                            </form>
                            
                            <hr class="my-4">
                            
                            <h5>Two-Factor Authentication</h5>
                            <p>Add an extra layer of security to your account.</p>
                            <button class="btn btn-success">
                                <i class="fas fa-mobile-alt"></i> Enable 2FA
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Notifications Tab -->
                <div class="tab-pane fade" id="notifications">
                    <div class="card">
                        <div class="card-header">
                            <h4>Notification Preferences</h4>
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" 
                                           id="email_threats" checked>
                                    <label class="form-check-label" for="email_threats">
                                        Email notifications for threats
                                    </label>
                                </div>
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" 
                                           id="email_scans" checked>
                                    <label class="form-check-label" for="email_scans">
                                        Email notifications for completed scans
                                    </label>
                                </div>
                                <div class="form-check mb-3">
                                    <input type="checkbox" class="form-check-input" 
                                           id="email_reports">
                                    <label class="form-check-label" for="email_reports">
                                        Weekly email reports
                                    </label>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    Save Preferences
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- System Tab -->
                <div class="tab-pane fade" id="system">
                    <div class="card">
                        <div class="card-header">
                            <h4>System Configuration</h4>
                        </div>
                        <div class="card-body">
                            <h5>System Information</h5>
                            <table class="table">
                                <tr>
                                    <td><strong>Version:</strong></td>
                                    <td>1.0.0</td>
                                </tr>
                                <tr>
                                    <td><strong>Database:</strong></td>
                                    <td>SQLite</td>
                                </tr>
                                <tr>
                                    <td><strong>Python:</strong></td>
                                    <td>3.12.3</td>
                                </tr>
                            </table>
                            
                            <hr>
                            
                            <h5>Danger Zone</h5>
                            <p class="text-danger">
                                Irreversible actions. Use with caution.
                            </p>
                            <button class="btn btn-danger">
                                <i class="fas fa-trash"></i> Clear All Logs
                            </button>
                            <button class="btn btn-danger">
                                <i class="fas fa-sync"></i> Reset to Defaults
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
{% endblock %}
EOF6

echo "✅ settings.html created"

# 7. users.html (Admin only)
cat > templates/users.html << 'EOF7'
{% extends "base.html" %}

{% block title %}User Management{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="fas fa-users"></i> User Management</h2>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal">
            <i class="fas fa-user-plus"></i> Add New User
        </button>
    </div>
    
    <div class="card">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>1</td>
                            <td>admin</td>
                            <td>admin@dlp.local</td>
                            <td><span class="badge bg-danger">Admin</span></td>
                            <td><span class="badge bg-success">Active</span></td>
                            <td>2026-01-12 21:50</td>
                            <td>
                                <button class="btn btn-sm btn-primary">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-danger">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Add User Modal -->
<div class="modal fade" id="addUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Add New User</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form method="POST">
                    <div class="form-group mb-3">
                        <label>Username</label>
                        <input type="text" class="form-control" name="username" required>
                    </div>
                    <div class="form-group mb-3">
                        <label>Email</label>
                        <input type="email" class="form-control" name="email" required>
                    </div>
                    <div class="form-group mb-3">
                        <label>Password</label>
                        <input type="password" class="form-control" name="password" required>
                    </div>
                    <div class="form-group mb-3">
                        <label>Role</label>
                        <select class="form-control" name="role">
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Create User</button>
                </form>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
{% endblock %}
EOF7

echo "✅ users.html created"

# 8. alerts.html
cat > templates/alerts.html << 'EOF8'
{% extends "base.html" %}

{% block title %}Security Alerts{% endblock %}

{% block content %}
<div class="container mt-4">
    <h2><i class="fas fa-exclamation-triangle"></i> Security Alerts</h2>
    
    <div class="row mt-4">
        <div class="col-md-12">
            <div class="card">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h4>Active Alerts</h4>
                        <div>
                            <select class="form-select form-select-sm">
                                <option>All Severities</option>
                                <option>Critical</option>
                                <option>High</option>
                                <option>Medium</option>
                                <option>Low</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="alert alert-danger">
                        <div class="d-flex justify-content-between">
                            <div>
                                <h5><i class="fas fa-exclamation-circle"></i> Critical: Unauthorized Access Attempt</h5>
                                <p>Multiple failed login attempts detected from IP: 192.168.1.100</p>
                                <small>2026-01-12 21:45:30</small>
                            </div>
                            <div>
                                <button class="btn btn-sm btn-primary">View Details</button>
                                <button class="btn btn-sm btn-success">Mark Resolved</button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="alert alert-warning">
                        <div class="d-flex justify-content-between">
                            <div>
                                <h5><i class="fas fa-exclamation-triangle"></i> High: Suspicious File Detected</h5>
                                <p>File with potential malware signature found in /uploads/document.pdf</p>
                                <small>2026-01-12 20:30:15</small>
                            </div>
                            <div>
                                <button class="btn btn-sm btn-primary">View Details</button>
                                <button class="btn btn-sm btn-success">Mark Resolved</button>
                            </div>
                        </div>
                    </div>
                    
                    <div class="alert alert-info">
                        <div class="d-flex justify-content-between">
                            <div>
                                <h5><i class="fas fa-info-circle"></i> Medium: Data Exposure Risk</h5>
                                <p>Sensitive data detected in public directory</p>
                                <small>2026-01-12 19:15:00</small>
                            </div>
                            <div>
                                <button class="btn btn-sm btn-primary">View Details</button>
                                <button class="btn btn-sm btn-success">Mark Resolved</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF8

echo "✅ alerts.html created"

echo ""
echo "════════════════════════════════════════════"
echo "✅ ALL TEMPLATES CREATED SUCCESSFULLY!"
echo "════════════════════════════════════════════"
echo ""
echo "Templates created:"
echo "  ✓ index.html (Landing page)"
echo "  ✓ encrypt.html (File encryption)"
echo "  ✓ decrypt.html (File decryption)"
echo "  ✓ scan.html (File scanning)"
echo "  ✓ reports.html (Reports generation)"
echo "  ✓ settings.html (User settings)"
echo "  ✓ users.html (User management)"
echo "  ✓ alerts.html (Security alerts)"
echo ""
echo "Existing templates:"
echo "  ✓ login.html"
echo "  ✓ register.html"
echo "  ✓ dashboard.html"
echo "  ✓ base.html"
echo "  ✓ 404.html"
echo "  ✓ 500.html"
echo "  ✓ test_responsive.html"
echo ""
echo "Total: 15 templates"
echo ""

