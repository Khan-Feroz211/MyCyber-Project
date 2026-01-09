"""
DLP Security System Configuration
Linux-optimized settings
"""
import os
from pathlib import Path
import secrets

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', secrets.token_hex(32))

# Database configuration
DATABASES = {
    'default': {
        'engine': 'sqlite',
        'name': BASE_DIR / 'data' / 'dlp_database.db',
        'timeout': 30
    },
    'logs': {
        'engine': 'sqlite',
        'name': BASE_DIR / 'data' / 'logs.db',
        'timeout': 30
    }
}

# File upload settings
UPLOAD_FOLDER = BASE_DIR / 'uploads'
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'csv', 'json', 'xml', 'html', 'log', 'zip', 'tar', 'gz'
}

# DLP Patterns (sensitive data patterns)
DLP_PATTERNS = {
    'credit_card': [
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        r'\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b'
    ],
    'ssn': [
        r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'
    ],
    'email': [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    ],
    'phone': [
        r'\b(?:\+?1[-.]?)?\(?[2-9][0-8][0-9]\)?[-.]?[2-9][0-9]{2}[-.]?[0-9]{4}\b'
    ],
    'ip_address': [
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ]
}

# Threat Intelligence feeds
THREAT_INTELLIGENCE_FEEDS = {
    'malware_domains': 'https://mirror1.malwaredomains.com/files/justdomains',
    'emerging_threats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'alienvault': 'https://reputation.alienvault.com/reputation.data',
    'firehol': 'https://iplists.firehol.org/files/firehol_level1.netset'
}

# Monitoring settings
MONITORING = {
    'interval': 30,  # seconds
    'retention_days': 90,
    'alert_thresholds': {
        'cpu': 85,
        'memory': 90,
        'disk': 95,
        'network_errors': 100,
        'failed_logins': 5
    }
}

# Backup settings
BACKUP = {
    'enabled': True,
    'schedule': '0 2 * * *',  # Daily at 2 AM
    'retention_days': 30,
    'locations': [
        BASE_DIR / 'backups',
        '/var/lib/dlp_system/backups',
        '/opt/dlp_system/external_storage/backups'
    ]
}

# Compliance frameworks
COMPLIANCE_FRAMEWORKS = {
    'hipaa': {
        'name': 'HIPAA',
        'description': 'Health Insurance Portability and Accountability Act',
        'rules': [
            'phi_protection',
            'access_controls',
            'audit_logs',
            'encryption'
        ]
    },
    'gdpr': {
        'name': 'GDPR',
        'description': 'General Data Protection Regulation',
        'rules': [
            'data_minimization',
            'consent_management',
            'right_to_be_forgotten',
            'data_portability'
        ]
    },
    'pci_dss': {
        'name': 'PCI DSS',
        'description': 'Payment Card Industry Data Security Standard',
        'rules': [
            'cardholder_data_protection',
            'network_security',
            'access_control',
            'monitoring'
        ]
    }
}

# Linux-specific settings
LINUX_CONFIG = {
    'system_logs': [
        '/var/log/syslog',
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/kern.log',
        '/var/log/dmesg'
    ],
    'critical_paths': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/etc/ssh/sshd_config',
        '/etc/crontab',
        '/etc/hosts'
    ],
    'service_checks': [
        'sshd',
        'firewalld',
        'auditd',
        'crond',
        'rsyslog'
    ]
}

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'simple': {
            'format': '%(levelname)s - %(message)s'
        }
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/dlp_system/system.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'detailed'
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'syslog': {
            'level': 'WARNING',
            'class': 'logging.handlers.SysLogHandler',
            'address': '/dev/log',
            'formatter': 'detailed'
        }
    },
    'loggers': {
        'dlp_system': {
            'handlers': ['file', 'console', 'syslog'],
            'level': 'INFO',
            'propagate': True
        }
    }
}

# API settings
API = {
    'enabled': True,
    'rate_limit': '100 per minute',
    'authentication': 'jwt',
    'cors_origins': ['http://localhost:3000', 'http://127.0.0.1:5000']
}

# Email notifications
EMAIL = {
    'enabled': False,
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'use_tls': True,
    'sender': 'dlp@yourdomain.com',
    'recipients': ['admin@yourdomain.com']
}

# Webhook notifications
WEBHOOKS = {
    'slack': {
        'enabled': False,
        'url': 'https://hooks.slack.com/services/...'
    },
    'teams': {
        'enabled': False,
        'url': 'https://outlook.office.com/webhook/...'
    }
}

# Machine Learning settings
ML_CONFIG = {
    'model_path': BASE_DIR / 'models',
    'training_data': BASE_DIR / 'data' / 'training',
    'vectorizer': 'tfidf',
    'algorithm': 'random_forest',
    'confidence_threshold': 0.8
}

# Performance optimization
PERFORMANCE = {
    'cache_enabled': True,
    'cache_ttl': 300,  # 5 minutes
    'database_pool_size': 10,
    'worker_threads': 4,
    'compression_enabled': True
}

# Incident response
INCIDENT_RESPONSE = {
    'auto_quarantine': True,
    'notify_admin': True,
    'escalation_levels': 3,
    'response_teams': ['security', 'it', 'management'],
    'playbooks': {
        'data_breach': 'playbooks/data_breach.yaml',
        'malware': 'playbooks/malware_response.yaml',
        'insider_threat': 'playbooks/insider_threat.yaml'
    }
}

# Risk scoring
RISK_SCORING = {
    'weights': {
        'severity': 0.4,
        'confidence': 0.3,
        'frequency': 0.2,
        'data_value': 0.1
    },
    'thresholds': {
        'low': 30,
        'medium': 60,
        'high': 80,
        'critical': 90
    }
}
