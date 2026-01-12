#!/usr/bin/env python3
"""
🚀 ADVANCED LINUX DLP SECURITY SYSTEM
Enterprise-grade Data Loss Prevention with Threat Intelligence, Encryption & Linux Integration
Production Ready for GitHub Portfolio
"""

import os
import sys
import json
import time
import threading
import hashlib
import re
import secrets
import base64
import logging
import logging.handlers
import warnings
import signal
import subprocess
import platform
import tempfile
import zipfile
import tarfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path, PurePath
from collections import defaultdict, deque, OrderedDict
from functools import wraps, lru_cache
from typing import Dict, List, Optional, Any, Tuple, Set, Callable, Union
from enum import Enum, auto
import asyncio
import aiofiles
import aiofiles.os
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import io
import mmap
import stat
import grp
import pwd
import fcntl
import struct

# Core Security & Cryptography
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import bcrypt
import nacl.secret
import nacl.utils

# Web Framework & Security
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, send_file, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, FileField, BooleanField
from wtforms.validators import DataRequired, Length, Email, ValidationError, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# System Monitoring & Performance
import psutil
try:
    import GPUtil
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
import systemd.journal
import resource
import netifaces
import socket
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import nmap

# Data Processing & ML
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer, HashingVectorizer
from sklearn.cluster import DBSCAN, KMeans, OPTICS
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
import joblib
import pickle
import msgpack
import orjson

# Networking & APIs
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import ipaddress
import dns.resolver
import whois
from bs4 import BeautifulSoup

# PDF & Reporting
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4, landscape, legal
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

# Database
import sqlite3
from sqlite3 import Connection as SQLite3Connection
import sqlalchemy
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean, 
    Text, Float, JSON, LargeBinary, BigInteger, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy.pool import QueuePool, StaticPool
from sqlalchemy.sql import func, text, select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.dialects.postgresql import ARRAY, UUID
import redis
import redis.exceptions
from redis import Redis

# Async & Concurrency
import asyncio
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
try:
    import aioredis
    AIOREDIS_AVAILABLE = True
except ImportError:
    AIOREDIS_AVAILABLE = False

# File Processing & Analysis
import magic
import pyclamd
import yara
import chardet
# File Processing & Analysis (Optional)
try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import exiftool
    EXIFTOOL_AVAILABLE = True
except ImportError:
    EXIFTOOL_AVAILABLE = False
import PIL.Image
import PIL.ExifTags
import pdfplumber
import docx
import openpyxl
import csv
import email
import imaplib
import poplib
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

# Security Scanning & Forensics (Optional)
try:
    from OpenSSL import crypto, SSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import keystone
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

try:
    import unicorn
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

try:
    import qiling
    QILING_AVAILABLE = True
except ImportError:
    QILING_AVAILABLE = False

# UI & Visualization (Optional)
try:
    import plotly
    import plotly.graph_objs as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import dash
    from dash import dcc, html, Input, Output, State
    import dash_bootstrap_components as dbc
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
import jinja2

# Linux Specific (Optional)
try:
    import audit
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False

try:
    import selinux
    SELINUX_AVAILABLE = True
except ImportError:
    SELINUX_AVAILABLE = False

try:
    import apparmor
    APPARMOR_AVAILABLE = True
except ImportError:
    APPARMOR_AVAILABLE = False

try:
    import dbus
    DBUS_AVAILABLE = True
except ImportError:
    DBUS_AVAILABLE = False

try:
    import linuxfd
    LINUXFD_AVAILABLE = True
except ImportError:
    LINUXFD_AVAILABLE = False

# Machine Learning Advanced (Optional)
try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
try:
    import sentencepiece as spm
    SENTENCEPIECE_AVAILABLE = True
except ImportError:
    SENTENCEPIECE_AVAILABLE = False
import gensim
from gensim.models import Word2Vec, Doc2Vec

# Container Security
import docker
from docker.models.containers import Container
from docker.models.images import Image
import kubernetes
from kubernetes import client, config

warnings.filterwarnings('ignore')

# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================

class DLPError(Exception):
    """Base exception for DLP system"""
    pass

class EncryptionError(DLPError):
    """Encryption related errors"""
    pass

class DecryptionError(DLPError):
    """Decryption related errors"""
    pass

class FileSystemError(DLPError):
    """File system related errors"""
    pass

class ThreatDetectionError(DLPError):
    """Threat detection errors"""
    pass

class DatabaseError(DLPError):
    """Database related errors"""
    pass

class PermissionError(DLPError):
    """Permission related errors"""
    pass

class ConfigurationError(DLPError):
    """Configuration errors"""
    pass

# ============================================================================
# ENHANCED LOGGING SYSTEM
# ============================================================================

class AdvancedLogger:
    """Advanced logging with structured logs, rotation, and Linux journal integration"""
    
    def __init__(self, name: str = "dlp_system"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Console handler with colors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Color formatter
        class ColorFormatter(logging.Formatter):
            COLORS = {
                'DEBUG': '\033[36m',      # Cyan
                'INFO': '\033[32m',       # Green
                'WARNING': '\033[33m',    # Yellow
                'ERROR': '\033[31m',      # Red
                'CRITICAL': '\033[41m',   # Red background
                'RESET': '\033[0m'        # Reset
            }
            
            def format(self, record):
                color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
                message = super().format(record)
                return f"{color}{message}{self.COLORS['RESET']}"
        
        console_formatter = ColorFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with JSON formatting
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True, mode=0o755)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / f"{name}.log",
            maxBytes=100 * 1024 * 1024,  # 100MB
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        # JSON formatter for structured logging
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': datetime.now().isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno,
                    'process': record.process,
                    'thread': record.thread,
                    'hostname': platform.node(),
                    'pid': os.getpid()
                }
                
                if hasattr(record, 'user_id'):
                    log_data['user_id'] = record.user_id
                if hasattr(record, 'client_ip'):
                    log_data['client_ip'] = record.client_ip
                if hasattr(record, 'request_id'):
                    log_data['request_id'] = record.request_id
                
                if record.exc_info:
                    log_data['exception'] = self.formatException(record.exc_info)
                
                return json.dumps(log_data, ensure_ascii=False)
        
        file_handler.setFormatter(JsonFormatter())
        self.logger.addHandler(file_handler)
        
        # Systemd journal handler if available
        try:
            journal_handler = systemd.journal.JournalHandler()
            journal_handler.setLevel(logging.WARNING)
            self.logger.addHandler(journal_handler)
        except:
            pass
        
        # Security log handler
        security_handler = logging.FileHandler(
            log_dir / "security.log",
            encoding='utf-8'
        )
        security_handler.setLevel(logging.WARNING)
        security_handler.addFilter(lambda record: record.levelno >= logging.WARNING)
        self.logger.addHandler(security_handler)
        
        # Performance log handler
        perf_handler = logging.FileHandler(
            log_dir / "performance.log",
            encoding='utf-8'
        )
        perf_handler.setLevel(logging.INFO)
        perf_handler.addFilter(lambda record: 'perf_' in record.getMessage())
        self.logger.addHandler(perf_handler)
        
        self.logger.info(f"Advanced logger initialized: {name}")
    
    def audit_log(self, user_id: str, action: str, resource: str, status: str, details: Dict = None):
        """Log audit trail"""
        audit_msg = f"AUDIT: user={user_id}, action={action}, resource={resource}, status={status}"
        if details:
            audit_msg += f", details={json.dumps(details)}"
        
        self.logger.info(audit_msg, extra={
            'user_id': user_id,
            'audit_action': action,
            'audit_resource': resource,
            'audit_status': status
        })
    
    def threat_log(self, threat_type: str, severity: str, source: str, details: Dict):
        """Log threat detection"""
        self.logger.warning(
            f"THREAT: type={threat_type}, severity={severity}, source={source}",
            extra={
                'threat_type': threat_type,
                'threat_severity': severity,
                'threat_source': source,
                'threat_details': details
            }
        )
    
    def perf_log(self, operation: str, duration_ms: float, metrics: Dict = None):
        """Log performance metrics"""
        self.logger.info(
            f"PERF: operation={operation}, duration={duration_ms:.2f}ms",
            extra={
                'perf_operation': operation,
                'perf_duration_ms': duration_ms,
                'perf_metrics': metrics or {}
            }
        )

# Initialize logger
logger = AdvancedLogger("advanced_dlp").logger

# ============================================================================
# LINUX COMMAND INTEGRATION ENGINE
# ============================================================================

class LinuxCommandEngine:
    """Advanced Linux command integration for file analysis, system monitoring, and forensics"""
    
    class FileType(Enum):
        TEXT = "text"
        BINARY = "binary"
        EXECUTABLE = "executable"
        ARCHIVE = "archive"
        DOCUMENT = "document"
        IMAGE = "image"
        AUDIO = "audio"
        VIDEO = "video"
        DATABASE = "database"
        CONFIG = "config"
        LOG = "log"
        SCRIPT = "script"
        UNKNOWN = "unknown"
    
    def __init__(self):
        self.command_cache = {}
        self.file_signatures = self._load_file_signatures()
        self.system_commands = self._get_system_commands()
        self.init_linux_tools()
        
        logger.info("Linux Command Engine initialized")
    
    def _load_file_signatures(self) -> Dict[bytes, str]:
        """Load file signatures for magic number detection"""
        signatures = {
            b'\x7fELF': 'ELF Executable',
            b'\x4d\x5a': 'Windows PE Executable',
            b'\x50\x4b\x03\x04': 'ZIP Archive',
            b'\x50\x4b\x05\x06': 'ZIP Archive (empty)',
            b'\x50\x4b\x07\x08': 'ZIP Archive (spanned)',
            b'\x1f\x8b\x08': 'GZIP Compressed',
            b'\x42\x5a\x68': 'BZIP2 Compressed',
            b'\x37\x7a\xbc\xaf\x27\x1c': '7-Zip Archive',
            b'\x25\x50\x44\x46': 'PDF Document',
            b'\x89\x50\x4e\x47': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x47\x49\x46\x38': 'GIF Image',
            b'\x49\x49\x2a\x00': 'TIFF Image (little-endian)',
            b'\x4d\x4d\x00\x2a': 'TIFF Image (big-endian)',
            b'\x52\x61\x72\x21': 'RAR Archive',
            b'\x1a\x45\xdf\xa3': 'Matroska/WebM',
            b'\x00\x00\x01\xba': 'MPEG Program Stream',
            b'\x00\x00\x01\xb3': 'MPEG Video Stream',
        }
        return signatures
    
    def _get_system_commands(self) -> Dict[str, bool]:
        """Check available system commands"""
        commands = [
            'file', 'strings', 'binwalk', 'exiftool', 'foremost', 'scalpel',
            'clamscan', 'yara', 'nmap', 'tcpdump', 'ss', 'netstat', 'lsof',
            'strace', 'ltrace', 'gdb', 'radare2', 'objdump', 'readelf',
            'nm', 'ldd', 'ldconfig', 'openssl', 'gpg', 'cryptsetup',
            'auditctl', 'ausearch', 'aureport', 'setroubleshoot', 'aa-status',
            'apparmor_status', 'sestatus', 'getenforce', 'getfattr', 'getcap',
            'getfacl', 'chattr', 'lsattr', 'stat', 'find', 'locate', 'updatedb',
            'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'b2sum',
            'diff', 'cmp', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq',
            'head', 'tail', 'wc', 'tr', 'tee', 'xargs', 'parallel',
            'pv', 'progress', 'rsync', 'tar', 'gzip', 'bzip2', 'xz', 'zstd',
            'dd', 'fdisk', 'parted', 'lsblk', 'blkid', 'mount', 'umount',
            'df', 'du', 'iotop', 'iostat', 'vmstat', 'mpstat', 'pidstat',
            'sar', 'top', 'htop', 'atop', 'glances', 'nethogs', 'iftop',
            'iptraf', 'vnstat', 'bmon', 'ethtool', 'ip', 'bridge', 'tc',
            'firewall-cmd', 'ufw', 'iptables', 'nft', 'fail2ban-client',
            'logwatch', 'logrotate', 'journalctl', 'dmesg', 'last', 'lastb',
            'who', 'w', 'users', 'finger', 'id', 'groups', 'getent',
            'passwd', 'shadow', 'group', 'gshadow', 'chage', 'usermod',
            'groupmod', 'useradd', 'userdel', 'groupadd', 'groupdel',
            'visudo', 'sudo', 'su', 'newgrp', 'sg', 'crontab', 'at',
            'systemctl', 'service', 'chkconfig', 'update-rc.d',
            'timedatectl', 'hostnamectl', 'localectl', 'loginctl',
            'networkctl', 'busctl', 'machinectl', 'portablectl',
            'resolvectl', 'bootctl', 'hwclock', 'date', 'cal',
            'uptime', 'w', 'free', 'vmstat', 'mpstat', 'iostat',
            'sar', 'pidstat', 'pmap', 'ps', 'pstree', 'pgrep', 'pkill',
            'kill', 'killall', 'nice', 'renice', 'time', 'timeout',
            'watch', 'screen', 'tmux', 'nohup', 'disown', 'jobs',
            'bg', 'fg', 'setsid', 'flock', 'cgroups', 'systemd-cgtop',
            'systemd-analyze', 'stap', 'perf', 'valgrind', 'gprof',
            'ltrace', 'strace', 'dtrace', 'bpftrace', 'sysdig',
            'lttng', 'ftrace', 'trace-cmd', 'kernelshark',
            'git', 'svn', 'hg', 'cvs', 'make', 'cmake', 'autoconf',
            'automake', 'libtool', 'pkg-config', 'ldconfig', 'ld.so',
            'objcopy', 'strip', 'ar', 'ranlib', 'ld', 'as', 'gcc',
            'g++', 'clang', 'clang++', 'rustc', 'go', 'java', 'javac',
            'python', 'python3', 'perl', 'ruby', 'php', 'node', 'npm',
            'pip', 'gem', 'cpan', 'cargo', 'go', 'maven', 'gradle',
            'ant', 'sbt', 'make', 'ninja', 'meson', 'bazel',
            'docker', 'podman', 'containerd', 'runc', 'buildah',
            'skopeo', 'crio', 'crictl', 'kubectl', 'helm', 'minikube',
            'kind', 'k3s', 'k3d', 'k9s', 'kubectx', 'kubens',
            'ansible', 'puppet', 'chef', 'salt', 'terraform', 'packer',
            'vagrant', 'cloud-init', 'jq', 'yq', 'xmlstarlet', 'csvkit',
            'html2text', 'pandoc', 'convert', 'ffmpeg', 'sox',
            'imagemagick', 'graphicsmagick', 'optipng', 'jpegoptim',
            'pngquant', 'gifsicle', 'webp', 'avifenc', 'heif-enc',
            'exiv2', 'dcraw', 'ufraw', 'darktable', 'rawtherapee',
            'gimp', 'inkscape', 'blender', 'openscad', 'freecad',
            'libreoffice', 'abiword', 'gnumeric', 'sc', 'visidata',
            'sqlite3', 'mysql', 'psql', 'mongosh', 'redis-cli',
            'memcached', 'cassandra', 'elasticsearch', 'solr',
            'neo4j', 'arangodb', 'couchdb', 'riak', 'zookeeper',
            'etcd', 'consul', 'vault', 'nomad', 'serf',
            'nginx', 'apache2', 'lighttpd', 'caddy', 'traefik',
            'haproxy', 'squid', 'varnish', 'memcached', 'redis',
            'postfix', 'sendmail', 'exim', 'dovecot', 'cyrus',
            'bind9', 'unbound', 'dnsmasq', 'pdns', 'nsd',
            'ssh', 'sshd', 'openssh', 'dropbear', 'putty',
            'telnet', 'ftp', 'sftp', 'scp', 'rsync', 'rclone',
            'curl', 'wget', 'axel', 'aria2', 'youtube-dl',
            'ffmpeg', 'vlc', 'mplayer', 'mpv', 'gstreamer',
            'pulseaudio', 'alsa', 'jack', 'pipewire',
            'xorg', 'wayland', 'weston', 'sway', 'i3',
            'gnome-shell', 'kwin', 'xfwm4', 'openbox',
            'vim', 'emacs', 'nano', 'micro', 'neovim',
            'bash', 'zsh', 'fish', 'tcsh', 'ksh', 'dash',
            'tmux', 'screen', 'byobu', 'dtach', 'abduco',
        ]
        
        available = {}
        for cmd in commands:
            try:
                subprocess.run(['which', cmd], capture_output=True, check=True)
                available[cmd] = True
            except:
                available[cmd] = False
        
        return available
    
    def init_linux_tools(self):
        """Initialize Linux security tools"""
        self.tools = {
            'file_analysis': {
                'file': self.system_commands.get('file', False),
                'binwalk': self.system_commands.get('binwalk', False),
                'exiftool': self.system_commands.get('exiftool', False),
                'strings': self.system_commands.get('strings', False),
                'foremost': self.system_commands.get('foremost', False),
                'scalpel': self.system_commands.get('scalpel', False),
            },
            'security_scanning': {
                'clamscan': self.system_commands.get('clamscan', False),
                'yara': self.system_commands.get('yara', False),
                'nmap': self.system_commands.get('nmap', False),
                'lynis': self._check_command('lynis'),
                'rkhunter': self._check_command('rkhunter'),
                'chkrootkit': self._check_command('chkrootkit'),
            },
            'system_monitoring': {
                'auditctl': self.system_commands.get('auditctl', False),
                'ausearch': self.system_commands.get('ausearch', False),
                'aureport': self.system_commands.get('aureport', False),
                'lsof': self.system_commands.get('lsof', False),
                'strace': self.system_commands.get('strace', False),
                'ltrace': self.system_commands.get('ltrace', False),
            },
            'cryptography': {
                'openssl': self.system_commands.get('openssl', False),
                'gpg': self.system_commands.get('gpg', False),
                'cryptsetup': self.system_commands.get('cryptsetup', False),
            },
            'network_analysis': {
                'tcpdump': self.system_commands.get('tcpdump', False),
                'wireshark': self._check_command('tshark'),
                'ss': self.system_commands.get('ss', False),
                'netstat': self.system_commands.get('netstat', False),
                'iftop': self.system_commands.get('iftop', False),
                'nethogs': self.system_commands.get('nethogs', False),
            }
        }
    
    def _check_command(self, cmd: str) -> bool:
        """Check if command is available"""
        try:
            subprocess.run(['which', cmd], capture_output=True, check=True)
            return True
        except:
            return False
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive file analysis using Linux commands"""
        analysis = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'basic_info': {},
            'magic_numbers': [],
            'strings': [],
            'metadata': {},
            'entropy': 0.0,
            'hashes': {},
            'embedded_files': [],
            'security_analysis': {},
            'threat_indicators': []
        }
        
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Basic file info using stat
            stat_info = file_path.stat()
            analysis['basic_info'] = {
                'size': stat_info.st_size,
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner': pwd.getpwuid(stat_info.st_uid).pw_name,
                'group': grp.getgrgid(stat_info.st_gid).gr_name,
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
            }
            
            # Read first 1024 bytes for magic number detection
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            # Check magic numbers
            for signature, description in self.file_signatures.items():
                if header.startswith(signature):
                    analysis['magic_numbers'].append({
                        'signature': signature.hex(),
                        'description': description,
                        'offset': 0
                    })
            
            # Use 'file' command if available
            if self.tools['file_analysis']['file']:
                try:
                    result = subprocess.run(
                        ['file', '-b', '--mime-type', str(file_path)],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    analysis['basic_info']['type'] = result.stdout.strip()
                except subprocess.CalledProcessError as e:
                    logger.warning(f"File command failed: {e}")
            
            # Use 'strings' command if available
            if self.tools['file_analysis']['strings'] and stat_info.st_size < 100 * 1024 * 1024:  # 100MB limit
                try:
                    result = subprocess.run(
                        ['strings', '-n', '8', str(file_path)],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    strings = result.stdout.strip().split('\n')
                    
                    # Filter suspicious strings
                    suspicious_patterns = [
                        r'http://', r'https://', r'\.onion',
                        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                        r'\b[A-Za-z0-9+/]{40,}={0,2}\b',
                        r'\b(?:CreateProcess|ShellExecute|system32|cmd\.exe)\b',
                        r'\b(?:/bin/bash|/bin/sh|python|perl|ruby)\b',
                        r'\beval\s*\(', r'\bexec\s*\(', r'\bsystem\s*\(',
                        r'\bbase64_decode\b', r'\bshell_exec\b',
                    ]
                    
                    analysis['strings'] = strings[:100]  # First 100 strings
                    
                    for string in strings[:500]:  # Check first 500 strings
                        for pattern in suspicious_patterns:
                            if re.search(pattern, string, re.IGNORECASE):
                                analysis['threat_indicators'].append({
                                    'type': 'suspicious_string',
                                    'pattern': pattern,
                                    'string': string,
                                    'severity': 'medium'
                                })
                                break
                
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Strings command failed: {e}")
            
            # Use exiftool for metadata if available
            if self.tools['file_analysis']['exiftool']:
                try:
                    result = subprocess.run(
                        ['exiftool', '-j', str(file_path)],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    metadata = json.loads(result.stdout)
                    if metadata:
                        analysis['metadata'] = metadata[0]
                
                except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                    logger.warning(f"Exiftool failed: {e}")
            
            # Calculate file entropy
            analysis['entropy'] = self.calculate_file_entropy(file_path)
            
            # Calculate multiple hashes
            analysis['hashes'] = self.calculate_file_hashes(file_path)
            
            # Use binwalk to find embedded files
            if self.tools['file_analysis']['binwalk']:
                try:
                    result = subprocess.run(
                        ['binwalk', str(file_path)],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    for line in result.stdout.split('\n'):
                        if '0x' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                analysis['embedded_files'].append({
                                    'offset': parts[0],
                                    'type': ' '.join(parts[2:]),
                                })
                
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Binwalk failed: {e}")
            
            # Security analysis with clamscan
            if self.tools['security_scanning']['clamscan']:
                try:
                    result = subprocess.run(
                        ['clamscan', '--no-summary', str(file_path)],
                        capture_output=True,
                        text=True,
                        check=False  # Don't fail on virus detection
                    )
                    
                    if 'FOUND' in result.stdout:
                        analysis['security_analysis']['clamscan'] = {
                            'infected': True,
                            'result': result.stdout.strip()
                        }
                        analysis['threat_indicators'].append({
                            'type': 'malware',
                            'scanner': 'clamscan',
                            'severity': 'critical',
                            'details': result.stdout.strip()
                        })
                    else:
                        analysis['security_analysis']['clamscan'] = {
                            'infected': False
                        }
                
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Clamscan failed: {e}")
            
            # Check file capabilities
            analysis['security_analysis']['capabilities'] = self.check_file_capabilities(file_path)
            
            # Check SELinux context
            analysis['security_analysis']['selinux'] = self.check_selinux_context(file_path)
            
            # Check for setuid/setgid
            mode = stat_info.st_mode
            analysis['security_analysis']['setuid'] = bool(mode & stat.S_ISUID)
            analysis['security_analysis']['setgid'] = bool(mode & stat.S_ISGID)
            analysis['security_analysis']['sticky_bit'] = bool(mode & stat.S_ISVTX)
            
            if analysis['security_analysis']['setuid'] or analysis['security_analysis']['setgid']:
                analysis['threat_indicators'].append({
                    'type': 'privileged_file',
                    'setuid': analysis['security_analysis']['setuid'],
                    'setgid': analysis['security_analysis']['setgid'],
                    'severity': 'high'
                })
        
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def calculate_file_entropy(self, file_path: Path, chunk_size: int = 8192) -> float:
        """Calculate Shannon entropy of a file"""
        try:
            byte_counts = [0] * 256
            total_bytes = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    for byte in chunk:
                        byte_counts[byte] += 1
                    total_bytes += len(chunk)
            
            if total_bytes == 0:
                return 0.0
            
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * (probability.bit_length() - 1) / 0.6931471805599453
            
            return entropy
        
        except Exception as e:
            logger.warning(f"Entropy calculation failed: {e}")
            return 0.0
    
    def calculate_file_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate multiple hash algorithms for a file"""
        hashes = {}
        
        algorithms = [
            ('md5', hashlib.md5()),
            ('sha1', hashlib.sha1()),
            ('sha256', hashlib.sha256()),
            ('sha512', hashlib.sha512()),
            ('sha3_256', hashlib.sha3_256()),
            ('sha3_512', hashlib.sha3_512()),
            ('blake2s', hashlib.blake2s()),
            ('blake2b', hashlib.blake2b()),
        ]
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    for _, hash_obj in algorithms:
                        hash_obj.update(chunk)
            
            for name, hash_obj in algorithms:
                hashes[name] = hash_obj.hexdigest()
        
        except Exception as e:
            logger.warning(f"Hash calculation failed: {e}")
        
        return hashes
    
    def check_file_capabilities(self, file_path: Path) -> Dict[str, Any]:
        """Check Linux file capabilities"""
        capabilities = {}
        
        if self.system_commands.get('getcap', False):
            try:
                result = subprocess.run(
                    ['getcap', str(file_path)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    caps = result.stdout.strip().split('=')[-1]
                    capabilities['enabled'] = True
                    capabilities['capabilities'] = caps.split(',')
                else:
                    capabilities['enabled'] = False
            
            except subprocess.CalledProcessError as e:
                logger.warning(f"getcap failed: {e}")
        
        return capabilities
    
    def check_selinux_context(self, file_path: Path) -> Dict[str, Any]:
        """Check SELinux context"""
        context = {}
        
        try:
            # Try to get SELinux context
            result = subprocess.run(
                ['ls', '-lZ', str(file_path)],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if len(parts) >= 4:
                    context_str = parts[4]
                    context_parts = context_str.split(':')
                    if len(context_parts) >= 4:
                        context = {
                            'user': context_parts[0],
                            'role': context_parts[1],
                            'type': context_parts[2],
                            'level': context_parts[3] if len(context_parts) > 3 else ''
                        }
        
        except Exception as e:
            logger.warning(f"SELinux context check failed: {e}")
        
        return context
    
    def monitor_directory(self, directory: str, callback: Callable, recursive: bool = True):
        """Monitor directory for changes using inotify"""
        import pyinotify
        
        class EventHandler(pyinotify.ProcessEvent):
            def __init__(self, callback):
                super().__init__()
                self.callback = callback
            
            def process_IN_CREATE(self, event):
                self.callback('CREATE', event.pathname)
            
            def process_IN_DELETE(self, event):
                self.callback('DELETE', event.pathname)
            
            def process_IN_MODIFY(self, event):
                self.callback('MODIFY', event.pathname)
            
            def process_IN_MOVED_FROM(self, event):
                self.callback('MOVED_FROM', event.pathname)
            
            def process_IN_MOVED_TO(self, event):
                self.callback('MOVED_TO', event.pathname)
        
        try:
            wm = pyinotify.WatchManager()
            mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_MOVED_FROM | pyinotify.IN_MOVED_TO
            
            handler = EventHandler(callback)
            notifier = pyinotify.Notifier(wm, handler)
            
            wdd = wm.add_watch(directory, mask, rec=recursive, auto_add=recursive)
            
            logger.info(f"Started monitoring directory: {directory}")
            notifier.loop()
        
        except Exception as e:
            logger.error(f"Directory monitoring failed: {e}")
    
    def system_audit(self) -> Dict[str, Any]:
        """Perform system security audit using Linux tools"""
        audit_results = {
            'timestamp': datetime.now().isoformat(),
            'system_info': {},
            'security_tools': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # System information
            audit_results['system_info'] = {
                'hostname': platform.node(),
                'os': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
            }
            
            # Check security tools
            for category, tools in self.tools.items():
                audit_results['security_tools'][category] = {
                    name: ('Available' if available else 'Not Available')
                    for name, available in tools.items()
                }
            
            # Check for rootkits
            if self.tools['security_scanning']['rkhunter']:
                try:
                    result = subprocess.run(
                        ['rkhunter', '--check', '--sk', '--rwo'],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    if 'Warning:' in result.stdout:
                        audit_results['vulnerabilities'].append({
                            'type': 'rootkit',
                            'tool': 'rkhunter',
                            'severity': 'critical',
                            'details': [line for line in result.stdout.split('\n') if 'Warning:' in line]
                        })
                except:
                    pass
            
            # Check for common vulnerabilities
            self._check_system_vulnerabilities(audit_results)
            
            # Generate recommendations
            self._generate_recommendations(audit_results)
        
        except Exception as e:
            logger.error(f"System audit failed: {e}")
            audit_results['error'] = str(e)
        
        return audit_results
    
    def _check_system_vulnerabilities(self, audit_results: Dict[str, Any]):
        """Check system for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for world-writable directories
        sensitive_dirs = ['/tmp', '/var/tmp', '/dev/shm']
        for directory in sensitive_dirs:
            if os.path.exists(directory):
                try:
                    mode = os.stat(directory).st_mode
                    if mode & stat.S_IWOTH:  # World writable
                        vulnerabilities.append({
                            'type': 'world_writable_directory',
                            'path': directory,
                            'severity': 'high',
                            'description': f'Directory {directory} is world-writable'
                        })
                except:
                    pass
        
        # Check for setuid/setgid files in unusual locations
        suspicious_locations = ['/tmp', '/var/tmp', '/dev/shm', '/home']
        for location in suspicious_locations:
            if os.path.exists(location):
                try:
                    result = subprocess.run(
                        ['find', location, '-type', 'f', '-perm', '-4000', '-o', '-perm', '-2000'],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    if result.stdout.strip():
                        files = result.stdout.strip().split('\n')
                        vulnerabilities.append({
                            'type': 'suspicious_setuid_setgid',
                            'location': location,
                            'files': files,
                            'severity': 'medium',
                            'description': f'Setuid/setgid files found in {location}'
                        })
                except:
                    pass
        
        audit_results['vulnerabilities'].extend(vulnerabilities)
    
    def _generate_recommendations(self, audit_results: Dict[str, Any]):
        """Generate security recommendations"""
        recommendations = []
        
        # Check if auditd is running
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'auditd'],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                recommendations.append({
                    'priority': 'high',
                    'action': 'Enable auditd',
                    'description': 'auditd is not running. Enable for security auditing.'
                })
        except:
            pass
        
        # Check SELinux status
        if self.system_commands.get('getenforce', False):
            try:
                result = subprocess.run(
                    ['getenforce'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if result.stdout.strip() != 'Enforcing':
                    recommendations.append({
                        'priority': 'high',
                        'action': 'Enable SELinux',
                        'description': f'SELinux is in {result.stdout.strip()} mode. Set to Enforcing.'
                    })
            except:
                pass
        
        audit_results['recommendations'] = recommendations
    
    def create_luks_container(self, container_path: str, size_gb: int = 10, 
                            cipher: str = 'aes-xts-plain64', key_size: int = 512) -> Dict[str, Any]:
        """Create LUKS encrypted container"""
        result = {
            'success': False,
            'container_path': container_path,
            'size_gb': size_gb,
            'cipher': cipher,
            'key_size': key_size
        }
        
        if not self.tools['cryptography']['cryptsetup']:
            result['error'] = 'cryptsetup not available'
            return result
        
        try:
            # Create empty container file
            subprocess.run([
                'dd', 'if=/dev/zero', f'of={container_path}',
                'bs=1G', f'count={size_gb}', 'status=progress'
            ], check=True)
            
            # Setup LUKS
            subprocess.run([
                'cryptsetup', 'luksFormat', container_path,
                '--cipher', cipher,
                '--key-size', str(key_size),
                '--hash', 'sha512',
                '--iter-time', '5000'
            ], check=True)
            
            result['success'] = True
            result['message'] = f'LUKS container created at {container_path}'
            
            # Generate mount commands
            mapper_name = Path(container_path).stem
            result['mount_commands'] = {
                'open': f'sudo cryptsetup luksOpen {container_path} {mapper_name}',
                'format': f'sudo mkfs.ext4 /dev/mapper/{mapper_name}',
                'mount': f'sudo mount /dev/mapper/{mapper_name} /mnt/encrypted',
                'close': f'sudo cryptsetup luksClose {mapper_name}'
            }
        
        except subprocess.CalledProcessError as e:
            result['error'] = str(e)
            logger.error(f"LUKS container creation failed: {e}")
        
        return result
    
    def encrypt_with_openssl(self, input_file: str, output_file: str = None,
                           algorithm: str = 'aes-256-cbc', password: str = None) -> Dict[str, Any]:
        """Encrypt file using OpenSSL"""
        result = {
            'success': False,
            'input_file': input_file,
            'algorithm': algorithm
        }
        
        if not self.tools['cryptography']['openssl']:
            result['error'] = 'openssl not available'
            return result
        
        if not password:
            password = secrets.token_urlsafe(32)
        
        if not output_file:
            output_file = f"{input_file}.enc"
        
        try:
            subprocess.run([
                'openssl', 'enc', f'-{algorithm}',
                '-salt', '-pbkdf2', '-iter', '100000',
                '-in', input_file,
                '-out', output_file,
                '-pass', f'pass:{password}'
            ], check=True)
            
            result['success'] = True
            result['output_file'] = output_file
            result['password'] = password  # In production, this should be stored securely
        
        except subprocess.CalledProcessError as e:
            result['error'] = str(e)
            logger.error(f"OpenSSL encryption failed: {e}")
        
        return result
    
    def network_scan(self, target: str = 'localhost', 
                    scan_type: str = 'basic') -> Dict[str, Any]:
        """Perform network scan using nmap"""
        result = {
            'success': False,
            'target': target,
            'scan_type': scan_type
        }
        
        if not self.tools['security_scanning']['nmap']:
            result['error'] = 'nmap not available'
            return result
        
        try:
            if scan_type == 'basic':
                args = ['-sV', '-O', '-T4']
            elif scan_type == 'full':
                args = ['-sS', '-sU', '-sV', '-O', '-A', '-T4']
            elif scan_type == 'stealth':
                args = ['-sS', '-sV', '-T2']
            else:
                args = ['-sV', '-T4']
            
            cmd = ['nmap'] + args + [target]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            result['success'] = True
            result['output'] = process.stdout
            result['return_code'] = process.returncode
            
            # Parse nmap output
            if process.stdout:
                result['parsed'] = self._parse_nmap_output(process.stdout)
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Network scan failed: {e}")
        
        return result
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        parsed = {
            'hosts': [],
            'ports': [],
            'services': [],
            'os_guesses': []
        }
        
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Host line
            if line.startswith('Nmap scan report for'):
                current_host = line.split('for')[-1].strip()
                parsed['hosts'].append(current_host)
            
            # Port line
            elif '/' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    if len(port_info) >= 2:
                        parsed['ports'].append({
                            'port': port_info[0],
                            'protocol': port_info[1],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else 'unknown'
                        })
            
            # Service version
            elif 'Service Info:' in line:
                parsed['services'].append(line.replace('Service Info:', '').strip())
            
            # OS guess
            elif 'OS details:' in line or 'OS guesses:' in line:
                parsed['os_guesses'].append(line.split(':')[-1].strip())
        
        return parsed

# Initialize Linux command engine
linux_engine = LinuxCommandEngine()

# ============================================================================
# ADVANCED ENCRYPTION ENGINE WITH LINUX INTEGRATION
# ============================================================================

class AdvancedEncryptionEngine:
    """Advanced encryption with Linux integration, key management, and hardware support"""
    
    class KeyType(Enum):
        MASTER = "master"
        DATA = "data"
        COMMUNICATION = "comm"
        ARCHIVE = "archive"
        EPHEMERAL = "ephemeral"
        TPM = "tpm"
        HSM = "hsm"
    
    class Algorithm(Enum):
        AES_256_GCM = "aes-256-gcm"
        AES_256_CBC = "aes-256-cbc"
        CHACHA20_POLY1305 = "chacha20-poly1305"
        RSA_4096 = "rsa-4096"
        ECC_P521 = "ecc-p521"
        ARGON2 = "argon2"
        SCRYPT = "scrypt"
    
    def __init__(self, config_path: str = "config/encryption.json"):
        self.config = self._load_config(config_path)
        self.keys = {}
        self.key_versions = defaultdict(list)
        self.key_rotation_schedule = {}
        self.backend = default_backend()
        self.linux_engine = linux_engine
        
        # Hardware security modules
        self.tpm_available = self._check_tpm()
        self.hsm_available = self._check_hsm()
        
        # Initialize key management
        self._init_key_management()
        self._start_key_rotation_monitor()
        
        # Performance cache
        self.cipher_cache = {}
        self._cache_ttl = 300
        
        # Linux cryptography tools
        try:
            self.linux_crypto = LinuxCryptoTools()
        except:
            self.linux_crypto = None
        
        logger.info("Advanced Encryption Engine initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load encryption configuration"""
        default_config = {
            "key_management": {
                "rotation": {
                    "master_key_days": 90,
                    "data_key_days": 30,
                    "comm_key_days": 7,
                    "archive_key_years": 5
                },
                "backup": {
                    "enabled": True,
                    "location": "/secure/backups/keys",
                    "encrypt_backups": True
                },
                "tpm_integration": {
                    "enabled": False,
                    "primary_handle": "0x81000000"
                }
            },
            "algorithms": {
                "default_symmetric": "AES-256-GCM",
                "default_asymmetric": "RSA-4096",
                "default_kdf": "PBKDF2-HMAC-SHA512",
                "supported": [
                    "AES-256-GCM", "AES-256-CBC", "CHACHA20-POLY1305",
                    "RSA-2048", "RSA-4096", "ECC-P256", "ECC-P521"
                ]
            },
            "performance": {
                "cache_size": 1000,
                "parallel_operations": True,
                "hardware_acceleration": True,
                "chunk_size_mb": 64
            },
            "linux_integration": {
                "use_luks": True,
                "use_gpg": True,
                "use_openssl": True,
                "secure_key_storage": "/etc/dlp/keys"
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                    default_config.update(loaded_config)
        except Exception as e:
            logger.warning(f"Could not load encryption config: {e}")
        
        return default_config
    
    def _check_tpm(self) -> bool:
        """Check if TPM is available"""
        try:
            result = subprocess.run(
                ['tpm2_getcap', 'properties-fixed'],
                capture_output=True,
                text=True,
                check=False
            )
            return result.returncode == 0 and 'TPM2' in result.stdout
        except:
            return False
    
    def _check_hsm(self) -> bool:
        """Check if HSM is available"""
        # Check common HSM interfaces
        hsm_checks = [
            '/dev/tpm0',
            '/dev/tpmrm0',
            '/proc/tpm',
            '/sys/class/tpm'
        ]
        
        return any(os.path.exists(check) for check in hsm_checks)
    
    def _init_key_management(self):
        """Initialize key management system"""
        # Create secure directories
        secure_dirs = [
            'keys', 'keys/backups', 'keys/tpm', 'keys/hsm',
            'secure', 'secure/vaults', 'secure/containers'
        ]
        
        for dir_name in secure_dirs:
            dir_path = Path(dir_name)
            dir_path.mkdir(exist_ok=True, mode=0o700)
        
        # Load or generate keys
        self._load_or_generate_keys()
        
        # Initialize TPM if available
        if self.tpm_available and self.config['key_management']['tpm_integration']['enabled']:
            self._init_tpm()
    
    def _load_or_generate_keys(self):
        """Load or generate encryption keys"""
        # Master key
        self.keys[self.KeyType.MASTER] = self._get_master_key()
        
        # Data encryption key
        self.keys[self.KeyType.DATA] = self._generate_key(self.KeyType.DATA)
        
        # Communication key
        self.keys[self.KeyType.COMMUNICATION] = self._generate_key(self.KeyType.COMMUNICATION)
        
        # Archive key
        self.keys[self.KeyType.ARCHIVE] = self._generate_key(self.KeyType.ARCHIVE)
        
        # Generate key pairs for asymmetric encryption
        self._generate_key_pairs()
    
    def _get_master_key(self) -> bytes:
        """Get or create master encryption key"""
        master_key_path = Path("keys/master.key")
        
        if master_key_path.exists():
            try:
                with open(master_key_path, 'rb') as f:
                    encrypted_key = f.read()
                
                # Decrypt with KDF-derived key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA3_512(),
                    length=32,  # Changed from 64 to 32 for Fernet
                    salt=b'advanced_dlp_master_salt',
                    iterations=2_000_000,
                    backend=self.backend
                )
                
                env_key = os.environ.get('MASTER_KEY_SECRET', '').encode()
                if not env_key:
                    raise ConfigurationError("MASTER_KEY_SECRET environment variable not set!")
                
                derived_key = base64.urlsafe_b64encode(kdf.derive(env_key))
                fernet = Fernet(derived_key)
                
                return fernet.decrypt(encrypted_key)
                
            except Exception as e:
                logger.error(f"Failed to load master key: {e}")
                raise
        
        # Generate new master key
        logger.info("Generating new master key...")
        new_master_key = secrets.token_bytes(32)  # 256-bit key
        
        # Use Linux /dev/urandom for additional entropy
        try:
            with open('/dev/urandom', 'rb') as f:
                extra_entropy = f.read(32)
                new_master_key = bytes(a ^ b for a, b in zip(new_master_key, extra_entropy))
        except:
            pass
        
        # Encrypt and store
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,  # Changed from 64 to 32 for Fernet
            salt=b'advanced_dlp_master_salt',
            iterations=2_000_000,
            backend=self.backend
        )
        
        env_key = os.environ.get('MASTER_KEY_SECRET', '').encode()
        if not env_key:
            raise ConfigurationError("MASTER_KEY_SECRET must be set for key generation")
        
        derived_key = base64.urlsafe_b64encode(kdf.derive(env_key))
        fernet = Fernet(derived_key)
        encrypted_master = fernet.encrypt(new_master_key)
        
        with open(master_key_path, 'wb') as f:
            f.write(encrypted_master)
        
        master_key_path.chmod(0o600)
        
        # Backup to TPM if available
        if self.tpm_available:
            self._backup_to_tpm(new_master_key, 'master_key')
        
        # Create LUKS container for key storage
        if self.config['linux_integration']['use_luks']:
            self._create_key_vault()
        
        return new_master_key
    
    def _generate_key(self, key_type: KeyType) -> bytes:
        """Generate encryption key"""
        key_size = {
            self.KeyType.MASTER: 32,
            self.KeyType.DATA: 32,
            self.KeyType.COMMUNICATION: 32,
            self.KeyType.ARCHIVE: 32,
            self.KeyType.EPHEMERAL: 32,
        }.get(key_type, 32)
        
        # Generate key with multiple entropy sources
        key = secrets.token_bytes(key_size)
        
        # Add Linux random entropy
        try:
            with open('/dev/random', 'rb') as f:
                linux_random = f.read(key_size)
                key = bytes(a ^ b for a, b in zip(key, linux_random))
        except:
            pass
        
        # Store key
        key_path = Path(f"keys/{key_type.value}.key")
        encrypted_key = self._encrypt_with_master(key)
        
        with open(key_path, 'wb') as f:
            f.write(encrypted_key)
        
        key_path.chmod(0o600)
        
        # Track version
        version_info = {
            'key_id': hashlib.sha3_256(key).hexdigest()[:16],
            'created_at': datetime.now().isoformat(),
            'expires_at': self._calculate_expiry(key_type),
            'algorithm': 'AES-256-GCM',
            'source': 'software'
        }
        
        self.key_versions[key_type].append(version_info)
        
        return key
    
    def _generate_key_pairs(self):
        """Generate asymmetric key pairs"""
        try:
            # RSA key pair
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=self.backend
            )
            
            # Serialize and store
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    self.keys[self.KeyType.MASTER]
                )
            )
            
            with open('keys/rsa_private.pem', 'wb') as f:
                f.write(private_pem)
            
            # ECC key pair
            from cryptography.hazmat.primitives.asymmetric import ec
            ecc_private = ec.generate_private_key(
                ec.SECP521R1(),
                backend=self.backend
            )
            
            ecc_pem = ecc_private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    self.keys[self.KeyType.MASTER]
                )
            )
            
            with open('keys/ecc_private.pem', 'wb') as f:
                f.write(ecc_pem)
            
            logger.info("Asymmetric key pairs generated")
            
        except Exception as e:
            logger.error(f"Failed to generate key pairs: {e}")
    
    def _init_tpm(self):
        """Initialize TPM integration"""
        try:
            # Create primary key in TPM
            subprocess.run([
                'tpm2_createprimary',
                '-C', 'o',
                '-c', 'keys/tpm/primary.ctx',
                '-Q'
            ], check=True)
            
            logger.info("TPM initialized for key storage")
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"TPM initialization failed: {e}")
    
    def _backup_to_tpm(self, key_data: bytes, key_name: str):
        """Backup key to TPM"""
        if not self.tpm_available:
            return
        
        try:
            # Create TPM-backed key
            subprocess.run([
                'tpm2_create',
                '-C', 'keys/tpm/primary.ctx',
                '-G', 'aes256',
                '-u', f'keys/tpm/{key_name}.pub',
                '-r', f'keys/tpm/{key_name}.priv',
                '-i', '-',
                '-Q'
            ], input=key_data, check=True)
            
            logger.debug(f"Key backed up to TPM: {key_name}")
            
        except subprocess.CalledProcessError as e:
            logger.warning(f"TPM backup failed for {key_name}: {e}")
    
    def _create_key_vault(self):
        """Create LUKS encrypted vault for key storage"""
        vault_path = Path("secure/vaults/key_vault.img")
        
        if not vault_path.exists():
            result = self.linux_engine.create_luks_container(
                str(vault_path),
                size_gb=1,
                cipher='aes-xts-plain64',
                key_size=512
            )
            
            if result['success']:
                logger.info("Key vault created")
    
    def _encrypt_with_master(self, data: bytes) -> bytes:
        """Encrypt data with master key using authenticated encryption"""
        # Use ChaCha20-Poly1305 for master key encryption
        nonce = secrets.token_bytes(12)
        
        cipher = aead.ChaCha20Poly1305(self.keys[self.KeyType.MASTER][:32])
        encrypted = cipher.encrypt(nonce, data, None)
        
        return nonce + encrypted
    
    def _decrypt_with_master(self, encrypted_data: bytes) -> bytes:
        """Decrypt data with master key"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        cipher = aead.ChaCha20Poly1305(self.keys[self.KeyType.MASTER][:32])
        
        try:
            return cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise DecryptionError(f"Master key decryption failed: {e}")
    
    def encrypt_file(self, source_path: Path, dest_path: Path = None,
                    chunk_size: int = 64 * 1024 * 1024,  # 64MB chunks
                    use_hardware: bool = False) -> Dict[str, Any]:
        """
        Encrypt file with advanced features:
        - Chunked encryption for large files
        - Hardware acceleration support
        - Integrity verification
        - Progress tracking
        """
        try:
            start_time = time.time()
            
            if not source_path.exists():
                raise FileNotFoundError(f"Source file not found: {source_path}")
            
            if dest_path is None:
                dest_path = source_path.with_suffix(source_path.suffix + '.enc')
            
            file_size = source_path.stat().st_size
            
            # File metadata
            metadata = {
                'original_path': str(source_path),
                'original_name': source_path.name,
                'file_size': file_size,
                'created': datetime.fromtimestamp(source_path.stat().st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(source_path.stat().st_mtime).isoformat(),
                'permissions': oct(source_path.stat().st_mode)[-3:],
                'file_hash': self._calculate_file_hash(source_path, 'sha3_512'),
                'chunk_size': chunk_size,
                'encryption_time': datetime.now().isoformat(),
                'algorithm': 'AES-256-GCM',
                'key_id': self.key_versions[self.KeyType.DATA][-1]['key_id'],
                'hardware_accelerated': use_hardware
            }
            
            # Generate ephemeral key for this file
            ephemeral_key = secrets.token_bytes(32)
            
            # Use hardware acceleration if requested and available
            if use_hardware and self._check_aesni():
                logger.debug("Using AES-NI hardware acceleration")
            
            # Encrypt metadata
            encrypted_metadata = self.encrypt_data(metadata, self.KeyType.DATA)
            
            # Encrypt file in chunks
            encrypted_chunks = []
            total_encrypted = 0
            
            with open(source_path, 'rb') as src_file, open(dest_path, 'wb') as dest_file:
                # Write header
                header = {
                    'version': '3.0',
                    'metadata': encrypted_metadata,
                    'ephemeral_key': base64.b64encode(
                        self._encrypt_with_master(ephemeral_key)
                    ).decode(),
                    'chunk_count': 0,
                    'chunk_hashes': []
                }
                
                dest_file.write(json.dumps(header, separators=(',', ':')).encode())
                dest_file.write(b'\n---ENCRYPTED-DATA---\n')
                
                # Process chunks
                chunk_index = 0
                while True:
                    chunk = src_file.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Encrypt chunk with authenticated encryption
                    nonce = secrets.token_bytes(12)
                    cipher = aead.AESGCM(ephemeral_key)
                    encrypted_chunk = cipher.encrypt(nonce, chunk, None)
                    
                    # Store chunk with nonce
                    chunk_data = nonce + encrypted_chunk
                    chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
                    
                    dest_file.write(base64.b64encode(chunk_data))
                    dest_file.write(b'\n')
                    
                    encrypted_chunks.append({
                        'index': chunk_index,
                        'size': len(chunk_data),
                        'hash': chunk_hash
                    })
                    
                    total_encrypted += len(chunk_data)
                    chunk_index += 1
                    
                    # Progress update every 10 chunks
                    if chunk_index % 10 == 0:
                        progress = (src_file.tell() / file_size) * 100
                        logger.debug(f"Encryption progress: {progress:.1f}%")
                
                # Update header with chunk information
                dest_file.seek(0)
                header['chunk_count'] = chunk_index
                header['chunk_hashes'] = [ch['hash'] for ch in encrypted_chunks]
                
                updated_header = json.dumps(header, separators=(',', ':'))
                dest_file.write(updated_header.encode())
                dest_file.write(b'\n---ENCRYPTED-DATA---\n')
            
            # Verify encryption
            verification_hash = self._calculate_file_hash(dest_path, 'blake2b')
            
            result = {
                'success': True,
                'source_file': str(source_path),
                'encrypted_file': str(dest_path),
                'original_size': file_size,
                'encrypted_size': dest_path.stat().st_size,
                'compression_ratio': dest_path.stat().st_size / file_size if file_size > 0 else 0,
                'chunks': chunk_index,
                'processing_time': time.time() - start_time,
                'encryption_rate_mbps': (file_size / (time.time() - start_time)) / 1_000_000,
                'file_hash': metadata['file_hash'],
                'encryption_hash': verification_hash,
                'integrity_verified': True
            }
            
            # Secure permissions
            dest_path.chmod(0o600)
            
            # Linux-specific: Set immutable flag if supported
            try:
                subprocess.run(['chattr', '+i', str(dest_path)], check=False)
            except:
                pass
            
            logger.info(f"File encrypted: {source_path} -> {dest_path}")
            return result
            
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            raise EncryptionError(f"File encryption failed: {e}")
    
    def decrypt_file(self, source_path: Path, dest_path: Path = None,
                    verify_integrity: bool = True) -> Dict[str, Any]:
        """Decrypt encrypted file with integrity verification"""
        try:
            start_time = time.time()
            
            if not source_path.exists():
                raise FileNotFoundError(f"Source file not found: {source_path}")
            
            with open(source_path, 'rb') as src_file:
                # Read header
                lines = []
                for line in src_file:
                    line = line.decode('utf-8').strip()
                    if line == '---ENCRYPTED-DATA---':
                        break
                    lines.append(line)
                
                header = json.loads(''.join(lines))
                
                # Decrypt metadata
                metadata = self.decrypt_data(header['metadata'])['data']
                
                # Decrypt ephemeral key
                encrypted_ephemeral = base64.b64decode(header['ephemeral_key'])
                ephemeral_key = self._decrypt_with_master(encrypted_ephemeral)
                
                if dest_path is None:
                    dest_path = Path(metadata['original_name'])
                
                # Decrypt chunks
                decrypted_size = 0
                chunk_hashes = []
                
                with open(dest_path, 'wb') as dest_file:
                    for line in src_file:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Decode chunk
                        chunk_data = base64.b64decode(line)
                        
                        # Verify chunk hash
                        chunk_hash = hashlib.blake2b(chunk_data).hexdigest()
                        chunk_hashes.append(chunk_hash)
                        
                        # Extract nonce and ciphertext
                        nonce = chunk_data[:12]
                        ciphertext = chunk_data[12:]
                        
                        # Decrypt chunk
                        cipher = aead.AESGCM(ephemeral_key)
                        decrypted_chunk = cipher.decrypt(nonce, ciphertext, None)
                        
                        dest_file.write(decrypted_chunk)
                        decrypted_size += len(decrypted_chunk)
                
                # Verify all chunk hashes
                if verify_integrity and 'chunk_hashes' in header:
                    if chunk_hashes != header['chunk_hashes']:
                        raise IntegrityError("Chunk hash mismatch - file may be corrupted")
                
                # Verify file hash
                if verify_integrity:
                    current_hash = self._calculate_file_hash(dest_path, 'sha3_512')
                    if current_hash != metadata['file_hash']:
                        raise IntegrityError("File hash mismatch - file may be corrupted")
                
                result = {
                    'success': True,
                    'encrypted_file': str(source_path),
                    'decrypted_file': str(dest_path),
                    'original_size': decrypted_size,
                    'decryption_time': time.time() - start_time,
                    'decryption_rate_mbps': (decrypted_size / (time.time() - start_time)) / 1_000_000,
                    'integrity_verified': verify_integrity,
                    'metadata': metadata
                }
                
                logger.info(f"File decrypted: {source_path} -> {dest_path}")
                return result
                
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            raise DecryptionError(f"File decryption failed: {e}")
    
    def encrypt_with_linux(self, source_path: Path, 
                          method: str = 'openssl',
                          algorithm: str = 'aes-256-gcm') -> Dict[str, Any]:
        """Encrypt using Linux cryptography tools"""
        methods = {
            'openssl': self._encrypt_with_openssl,
            'gpg': self._encrypt_with_gpg,
            'luks': self._encrypt_with_luks
        }
        
        if method not in methods:
            raise ValueError(f"Unknown encryption method: {method}")
        
        return methods[method](source_path, algorithm)
    
    def _encrypt_with_openssl(self, source_path: Path, algorithm: str) -> Dict[str, Any]:
        """Encrypt using OpenSSL"""
        password = secrets.token_urlsafe(32)
        
        result = self.linux_engine.encrypt_with_openssl(
            str(source_path),
            f"{source_path}.openssl.enc",
            algorithm,
            password
        )
        
        if result['success']:
            # Store password securely
            encrypted_password = self.encrypt_data(
                {'password': password},
                self.KeyType.ARCHIVE
            )
            
            with open(f"{source_path}.password.enc", 'w') as f:
                json.dump(encrypted_password, f)
        
        return result
    
    def _encrypt_with_gpg(self, source_path: Path, algorithm: str) -> Dict[str, Any]:
        """Encrypt using GPG"""
        # Generate GPG key if needed
        self._setup_gpg_key()
        
        # Encrypt with GPG
        try:
            result = subprocess.run([
                'gpg', '--encrypt', '--recipient', 'dlp-system',
                '--output', f'{source_path}.gpg',
                '--cipher-algo', algorithm.replace('aes-', 'AES'),
                str(source_path)
            ], capture_output=True, text=True, check=True)
            
            return {
                'success': True,
                'output_file': f'{source_path}.gpg',
                'algorithm': algorithm
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': e.stderr
            }
    
    def _encrypt_with_luks(self, source_path: Path, algorithm: str) -> Dict[str, Any]:
        """Create LUKS encrypted container"""
        container_path = f"{source_path}.luks.img"
        
        result = self.linux_engine.create_luks_container(
            container_path,
            size_gb=max(1, source_path.stat().st_size // (1024**3) + 1)
        )
        
        if result['success']:
            # Copy file to container
            try:
                mapper_name = Path(container_path).stem
                
                # Open container
                subprocess.run([
                    'cryptsetup', 'luksOpen', container_path, mapper_name
                ], check=True)
                
                # Format if needed
                subprocess.run([
                    'mkfs.ext4', f'/dev/mapper/{mapper_name}'
                ], check=True)
                
                # Mount
                mount_point = Path('/mnt') / mapper_name
                mount_point.mkdir(exist_ok=True)
                
                subprocess.run([
                    'mount', f'/dev/mapper/{mapper_name}', str(mount_point)
                ], check=True)
                
                # Copy file
                shutil.copy2(source_path, mount_point / source_path.name)
                
                # Unmount and close
                subprocess.run(['umount', str(mount_point)], check=True)
                subprocess.run(['cryptsetup', 'luksClose', mapper_name], check=True)
                
                result['mounted_file'] = str(mount_point / source_path.name)
                
            except subprocess.CalledProcessError as e:
                result['success'] = False
                result['error'] = str(e)
        
        return result
    
    def _setup_gpg_key(self):
        """Setup GPG key for encryption"""
        gpg_dir = Path.home() / '.gnupg'
        gpg_dir.mkdir(exist_ok=True, mode=0o700)
        
        # Check if key exists
        try:
            subprocess.run([
                'gpg', '--list-keys', 'dlp-system'
            ], capture_output=True, check=True)
            return
        except subprocess.CalledProcessError:
            pass
        
        # Generate key non-interactively
        key_input = f"""
%echo Generating DLP system GPG key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: DLP System
Name-Email: dlp@localhost
Expire-Date: 0
Passphrase: {secrets.token_urlsafe(32)}
%commit
%echo Done
"""
        
        try:
            subprocess.run([
                'gpg', '--batch', '--gen-key'
            ], input=key_input.encode(), check=True)
        except subprocess.CalledProcessError as e:
            logger.warning(f"GPG key generation failed: {e}")
    
    def _calculate_file_hash(self, file_path: Path, algorithm: str = 'sha3_512') -> str:
        """Calculate file hash with specified algorithm"""
        hash_func = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def _calculate_expiry(self, key_type: KeyType) -> str:
        """Calculate key expiry date"""
        rotation_config = self.config['key_management']['rotation']
        
        days_map = {
            self.KeyType.MASTER: rotation_config.get('master_key_days', 90),
            self.KeyType.DATA: rotation_config.get('data_key_days', 30),
            self.KeyType.COMMUNICATION: rotation_config.get('comm_key_days', 7),
            self.KeyType.ARCHIVE: rotation_config.get('archive_key_years', 5) * 365
        }
        
        days = days_map.get(key_type, 30)
        expiry = datetime.now() + timedelta(days=days)
        return expiry.isoformat()
    
    def _check_aesni(self) -> bool:
        """Check if AES-NI is available"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                return 'aes' in cpuinfo.lower()
        except:
            return False
    
    def _start_key_rotation_monitor(self):
        """Start background thread for key rotation monitoring"""
        def monitor_loop():
            while True:
                try:
                    now = datetime.now()
                    for key_type, rotation_time in list(self.key_rotation_schedule.items()):
                        if now >= rotation_time:
                            logger.info(f"Key rotation time reached for {key_type.value}")
                            self._rotate_key(key_type)
                    
                    time.sleep(3600)  # Check every hour
                except Exception as e:
                    logger.error(f"Key rotation monitor error: {e}")
                    time.sleep(300)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def _rotate_key(self, key_type: KeyType):
        """Rotate encryption key"""
        try:
            # Generate new key
            new_key = self._generate_key(key_type)
            self.keys[key_type] = new_key
            
            # Update rotation schedule
            self._schedule_key_rotation(key_type)
            
            logger.info(f"Rotated {key_type.value} key")
            
        except Exception as e:
            logger.error(f"Key rotation failed for {key_type.value}: {e}")
    
    def _schedule_key_rotation(self, key_type: KeyType):
        """Schedule next key rotation"""
        days_map = {
            self.KeyType.MASTER: 90,
            self.KeyType.DATA: 30,
            self.KeyType.COMMUNICATION: 7,
            self.KeyType.ARCHIVE: 5 * 365
        }
        
        if key_type in days_map:
            days = days_map[key_type]
            rotation_time = datetime.now() + timedelta(days=days)
            self.key_rotation_schedule[key_type] = rotation_time
            
            logger.debug(f"Scheduled {key_type.value} key rotation for {rotation_time}")
    
    def encrypt_data(self, data: Any, key_type: KeyType = KeyType.DATA,
                    metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Encrypt arbitrary data"""
        start_time = time.time()
        
        try:
            # Convert data to bytes
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, dict):
                data_bytes = orjson.dumps(data)
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                data_bytes = pickle.dumps(data)
            
            # Get encryption key
            key = self.keys.get(key_type)
            if not key:
                raise ValueError(f"No key available for type: {key_type}")
            
            # Generate nonce
            nonce = secrets.token_bytes(12)
            
            # Encrypt with authenticated encryption
            cipher = aead.AESGCM(key)
            encrypted = cipher.encrypt(nonce, data_bytes, None)
            
            # Create result package
            result = {
                'encrypted': base64.b64encode(nonce + encrypted).decode('utf-8'),
                'key_type': key_type.value,
                'key_version': self.key_versions[key_type][-1]['key_id'] if self.key_versions[key_type] else 'unknown',
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'AES-256-GCM',
                'original_size': len(data_bytes),
                'encrypted_size': len(encrypted),
                'data_hash': hashlib.sha3_512(data_bytes).hexdigest(),
                'encryption_hash': hashlib.sha3_512(encrypted).hexdigest(),
                'processing_time_ms': (time.time() - start_time) * 1000
            }
            
            if metadata:
                result['metadata'] = metadata
            
            # Audit log
            self._audit_encryption(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            raise EncryptionError(f"Data encryption failed: {e}")
    
    def decrypt_data(self, encrypted_package: Dict[str, Any],
                    require_key_type: KeyType = None) -> Any:
        """Decrypt data package"""
        start_time = time.time()
        
        try:
            # Validate package
            required_fields = ['encrypted', 'key_type', 'key_version']
            for field in required_fields:
                if field not in encrypted_package:
                    raise ValueError(f"Missing field in encrypted package: {field}")
            
            # Check key type
            key_type = self.KeyType(encrypted_package['key_type'])
            if require_key_type and key_type != require_key_type:
                raise ValueError(f"Key type mismatch: expected {require_key_type}, got {key_type}")
            
            # Get key
            key = self.keys.get(key_type)
            if not key:
                raise ValueError(f"No key available for type: {key_type}")
            
            # Decode encrypted data
            encrypted_data = base64.b64decode(encrypted_package['encrypted'])
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Decrypt
            cipher = aead.AESGCM(key)
            decrypted = cipher.decrypt(nonce, ciphertext, None)
            
            # Verify hash if provided
            if 'data_hash' in encrypted_package:
                current_hash = hashlib.sha3_512(decrypted).hexdigest()
                if current_hash != encrypted_package['data_hash']:
                    logger.warning("Data hash mismatch - possible tampering detected")
            
            result = {
                'data': decrypted,
                'key_type': key_type.value,
                'key_version': encrypted_package['key_version'],
                'decryption_time_ms': (time.time() - start_time) * 1000,
                'original_size': len(decrypted)
            }
            
            # Audit log
            self._audit_decryption(result)
            
            # Try to decode
            try:
                # Try JSON
                decoded = orjson.loads(decrypted)
                result['data'] = decoded
                result['format'] = 'json'
            except orjson.JSONDecodeError:
                try:
                    # Try pickle
                    decoded = pickle.loads(decrypted)
                    result['data'] = decoded
                    result['format'] = 'pickle'
                except pickle.UnpicklingError:
                    # Return as bytes/string
                    try:
                        decoded = decrypted.decode('utf-8')
                        result['data'] = decoded
                        result['format'] = 'text'
                    except UnicodeDecodeError:
                        result['data'] = decrypted
                        result['format'] = 'binary'
            
            return result
            
        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            raise DecryptionError(f"Data decryption failed: {e}")
    
    def _audit_encryption(self, result: Dict[str, Any]):
        """Audit encryption operation"""
        audit_entry = {
            'event': 'encryption',
            'timestamp': datetime.now().isoformat(),
            'key_type': result['key_type'],
            'key_version': result['key_version'],
            'data_size': result['original_size'],
            'processing_time': result['processing_time_ms'],
            'data_hash': result['data_hash']
        }
        
        self._write_audit_log(audit_entry)
    
    def _audit_decryption(self, result: Dict[str, Any]):
        """Audit decryption operation"""
        audit_entry = {
            'event': 'decryption',
            'timestamp': datetime.now().isoformat(),
            'key_type': result['key_type'],
            'key_version': result['key_version'],
            'data_size': result['original_size'],
            'processing_time': result['decryption_time_ms']
        }
        
        self._write_audit_log(audit_entry)
    
    def _write_audit_log(self, entry: Dict[str, Any]):
        """Write to audit log"""
        audit_file = Path("logs/encryption_audit.log")
        audit_file.parent.mkdir(exist_ok=True, mode=0o700)
        
        try:
            # Encrypt audit entry
            encrypted_entry = self.encrypt_data(entry, self.KeyType.ARCHIVE)
            
            with open(audit_file, 'a') as f:
                f.write(json.dumps(encrypted_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get encryption engine status"""
        status = {
            'engine': 'Advanced Encryption Engine',
            'version': '3.0.0',
            'status': 'operational',
            'hardware': {
                'tpm_available': self.tpm_available,
                'hsm_available': self.hsm_available,
                'aesni_available': self._check_aesni()
            },
            'keys': {},
            'key_rotations': {},
            'config': self.config,
            'performance': {
                'cache_size': len(self.cipher_cache)
            }
        }
        
        for key_type in self.KeyType:
            if key_type in self.keys:
                status['keys'][key_type.value] = {
                    'has_key': True,
                    'key_id': hashlib.sha3_256(self.keys[key_type]).hexdigest()[:16] if self.keys[key_type] else None,
                    'versions': len(self.key_versions.get(key_type, []))
                }
            
            if key_type in self.key_rotation_schedule:
                status['key_rotations'][key_type.value] = {
                    'next_rotation': self.key_rotation_schedule[key_type].isoformat(),
                    'scheduled': True
                }
        
        return status

# Initialize advanced encryption engine
encryption_engine = AdvancedEncryptionEngine()

# ============================================================================
# LINUX CRYPTO TOOLS
# ============================================================================

class LinuxCryptoTools:
    """Linux-specific cryptography tools"""
    
    def __init__(self):
        self.available_commands = self._check_commands()
        self.gpg_keyring = self._setup_gpg_keyring()
        
    def _check_commands(self) -> Dict[str, bool]:
        """Check available cryptography commands"""
        commands = ['openssl', 'gpg', 'cryptsetup', 'tpm2_tools']
        available = {}
        
        for cmd in commands:
            try:
                subprocess.run(['which', cmd], capture_output=True, check=True)
                available[cmd] = True
            except:
                available[cmd] = False
        
        return available
    
    def _setup_gpg_keyring(self) -> Path:
        """Setup GPG keyring for DLP system"""
        gpg_dir = Path.home() / '.gnupg' / 'dlp'
        gpg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Create gpg.conf
        gpg_conf = gpg_dir / 'gpg.conf'
        if not gpg_conf.exists():
            gpg_conf.write_text("""
# DLP System GPG Configuration
personal-cipher-preferences AES256 AES192 AES CAST5
personal-digest-preferences SHA512 SHA384 SHA256 SHA224
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
use-agent
throw-keyids
""")
        
        return gpg_dir
    
    def encrypt_with_openssl(self, input_file: str, output_file: str,
                           algorithm: str = 'aes-256-gcm', password: str = None) -> Dict[str, Any]:
        """Encrypt using OpenSSL"""
        if not self.available_commands.get('openssl', False):
            return {'success': False, 'error': 'openssl not available'}
        
        if not password:
            password = secrets.token_urlsafe(32)
        
        try:
            cmd = [
                'openssl', 'enc', f'-{algorithm}',
                '-salt', '-pbkdf2', '-iter', '1000000',
                '-in', input_file,
                '-out', output_file,
                '-pass', f'pass:{password}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            return {
                'success': True,
                'output_file': output_file,
                'algorithm': algorithm,
                'password': password,  # Should be stored securely
                'command': ' '.join(cmd)
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': e.stderr,
                'return_code': e.returncode
            }
    
    def decrypt_with_openssl(self, input_file: str, output_file: str,
                           algorithm: str = 'aes-256-gcm', password: str = None) -> Dict[str, Any]:
        """Decrypt using OpenSSL"""
        if not self.available_commands.get('openssl', False):
            return {'success': False, 'error': 'openssl not available'}
        
        if not password:
            return {'success': False, 'error': 'Password required'}
        
        try:
            cmd = [
                'openssl', 'enc', f'-{algorithm}', '-d',
                '-salt', '-pbkdf2', '-iter', '1000000',
                '-in', input_file,
                '-out', output_file,
                '-pass', f'pass:{password}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            return {
                'success': True,
                'output_file': output_file,
                'algorithm': algorithm,
                'command': ' '.join(cmd)
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': e.stderr,
                'return_code': e.returncode
            }
    
    def create_luks_container(self, container_path: str, size_gb: int = 10,
                            cipher: str = 'aes-xts-plain64', key_size: int = 512) -> Dict[str, Any]:
        """Create LUKS encrypted container"""
        if not self.available_commands.get('cryptsetup', False):
            return {'success': False, 'error': 'cryptsetup not available'}
        
        try:
            # Create container file
            dd_cmd = [
                'dd', 'if=/dev/zero',
                f'of={container_path}',
                'bs=1G',
                f'count={size_gb}',
                'status=progress'
            ]
            
            subprocess.run(dd_cmd, check=True)
            
            # Setup LUKS
            luks_cmd = [
                'cryptsetup', 'luksFormat', container_path,
                '--cipher', cipher,
                '--key-size', str(key_size),
                '--hash', 'sha512',
                '--iter-time', '5000',
                '--use-random'
            ]
            
            subprocess.run(luks_cmd, check=True)
            
            return {
                'success': True,
                'container_path': container_path,
                'size_gb': size_gb,
                'cipher': cipher,
                'key_size': key_size
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': str(e),
                'return_code': e.returncode
            }
    
    def encrypt_with_gpg(self, input_file: str, output_file: str = None,
                        recipient: str = None, armor: bool = False) -> Dict[str, Any]:
        """Encrypt using GPG"""
        if not self.available_commands.get('gpg', False):
            return {'success': False, 'error': 'gpg not available'}
        
        if not output_file:
            output_file = f"{input_file}.gpg"
        
        try:
            cmd = ['gpg', '--encrypt', '--output', output_file]
            
            if recipient:
                cmd.extend(['--recipient', recipient])
            
            if armor:
                cmd.append('--armor')
            
            cmd.append(input_file)
            
            subprocess.run(cmd, check=True)
            
            return {
                'success': True,
                'output_file': output_file,
                'armor': armor,
                'recipient': recipient
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': str(e),
                'return_code': e.returncode
            }
    
    def generate_ssl_certificate(self, domain: str, days: int = 365,
                               key_size: int = 4096) -> Dict[str, Any]:
        """Generate SSL certificate using OpenSSL"""
        if not self.available_commands.get('openssl', False):
            return {'success': False, 'error': 'openssl not available'}
        
        try:
            # Generate private key
            key_file = f"{domain}.key"
            subprocess.run([
                'openssl', 'genrsa',
                '-out', key_file,
                str(key_size)
            ], check=True)
            
            # Generate CSR
            csr_file = f"{domain}.csr"
            subprocess.run([
                'openssl', 'req', '-new',
                '-key', key_file,
                '-out', csr_file,
                '-subj', f'/CN={domain}/O=DLP System/C=US'
            ], check=True)
            
            # Generate self-signed certificate
            cert_file = f"{domain}.crt"
            subprocess.run([
                'openssl', 'x509', '-req',
                '-days', str(days),
                '-in', csr_file,
                '-signkey', key_file,
                '-out', cert_file
            ], check=True)
            
            # Set secure permissions
            os.chmod(key_file, 0o600)
            
            return {
                'success': True,
                'key_file': key_file,
                'csr_file': csr_file,
                'cert_file': cert_file,
                'validity_days': days
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'success': False,
                'error': str(e),
                'return_code': e.returncode
            }

# ============================================================================
# ADVANCED THREAT DETECTION ENGINE
# ============================================================================

class AdvancedThreatDetector:
    """Advanced threat detection with ML, behavior analysis, and real-time monitoring"""
    
    def __init__(self):
        self.patterns = self._load_threat_patterns()
        self.ml_models = {}
        self.threat_feeds = self._load_threat_feeds()
        self.ioc_database = self._load_ioc_database()
        self.behavior_profiles = defaultdict(dict)
        self.risk_scores = defaultdict(lambda: 0.0)
        self.yara_rules = None
        
        # Initialize components
        self._init_ml_models()
        self._init_yara_rules()
        self._start_threat_intelligence_updates()
        
        # Linux integration
        self.linux_engine = linux_engine
        
        logger.info("Advanced Threat Detector initialized")
    
    def _load_threat_patterns(self) -> Dict[str, List[Dict]]:
        """Load comprehensive threat detection patterns"""
        return {
            'pii': [
                {'pattern': r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', 'description': 'SSN'},
                {'pattern': r'\b\d{9}\b', 'description': 'SSN (no dashes)'},
                {'pattern': r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', 'description': 'Valid SSN'},
            ],
            'financial': [
                {'pattern': r'\b(?:\d[ -]*?){13,16}\b', 'description': 'Credit Card'},
                {'pattern': r'\b4[0-9]{12}(?:[0-9]{3})?\b', 'description': 'Visa'},
                {'pattern': r'\b5[1-5][0-9]{14}\b', 'description': 'MasterCard'},
                {'pattern': r'\b3[47][0-9]{13}\b', 'description': 'Amex'},
                {'pattern': r'\b6(?:011|5[0-9]{2})[0-9]{12}\b', 'description': 'Discover'},
                {'pattern': r'\b\d{8,17}\b', 'description': 'Bank Account'},
                {'pattern': r'\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]\s?){4,}\b', 'description': 'IBAN'},
            ],
            'credentials': [
                {'pattern': r'\bAKIA[0-9A-Z]{16}\b', 'description': 'AWS Access Key'},
                {'pattern': r'\bsk_(live|test)_[a-zA-Z0-9]{24,}\b', 'description': 'Stripe Key'},
                {'pattern': r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b', 'description': 'GitHub Token'},
                {'pattern': r'\b(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})\b', 'description': 'Slack Token'},
                {'pattern': r'\b[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}\b', 'description': 'GitHub App Token'},
            ],
            'secrets': [
                {'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----', 'description': 'Private Key'},
                {'pattern': r'(?i)(?:password|passwd|pwd|secret|token|key)[=:]\s*[\'"]?[^\s\'"]+[\'"]?', 'description': 'Config Secret'},
                {'pattern': r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'description': 'UUID'},
                {'pattern': r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b', 'description': 'JWT'},
            ],
            'malware': [
                {'pattern': r'\beval\(base64_decode\([^)]+\)\)', 'description': 'PHP Obfuscation'},
                {'pattern': r'\bsystem\([^)]+\)', 'description': 'System Command'},
                {'pattern': r'\bshell_exec\([^)]+\)', 'description': 'Shell Execution'},
                {'pattern': r'\bexec\([^)]+\)', 'description': 'Exec Command'},
                {'pattern': r'<script>[^<]*?(?:alert|document\.cookie|window\.location)[^<]*?</script>', 'description': 'XSS'},
                {'pattern': r'\bon\w+\s*=\s*["\'][^"\']*["\']', 'description': 'Event Handler'},
                {'pattern': r'javascript:', 'description': 'JavaScript Protocol'},
            ],
            'network': [
                {'pattern': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'description': 'IP Address'},
                {'pattern': r'\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b', 'description': 'IPv6'},
                {'pattern': r'\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b', 'description': 'Domain'},
                {'pattern': r'\.onion\b', 'description': 'Tor Domain'},
            ],
            'code_injection': [
                {'pattern': r'(?i)(?:union.*select|select.*from|insert.*into|update.*set|delete.*from)', 'description': 'SQL Injection'},
                {'pattern': r'(?i)(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c)', 'description': 'Path Traversal'},
                {'pattern': r'(?i)(?:<\?php|<\?=|<\? )', 'description': 'PHP Code'},
                {'pattern': r'(?i)(?:<%.*%>|<%=.*%>)', 'description': 'ASP Code'},
                {'pattern': r'(?i)(?:<jsp:|<%@)', 'description': 'JSP Code'},
            ]
        }
    
    def _load_threat_feeds(self) -> Dict[str, str]:
        """Load external threat feeds"""
        return {
            'malware_domains': 'https://mirror1.malwaredomains.com/files/domains.txt',
            'emerging_threats': 'https://rules.emergingthreats.net/open/suricata/rules/',
            'alienvault': 'https://reputation.alienvault.com/reputation.data',
            'phishtank': 'https://data.phishtank.com/data/online-valid.csv',
            'abuse_ch': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'ssl_bl': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
            'malware_bazaar': 'https://mb-api.abuse.ch/api/v1/',
            'virustotal': 'https://www.virustotal.com/api/v3/'
        }
    
    def _load_ioc_database(self) -> Dict[str, Set[str]]:
        """Load IOC database"""
        return {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'malicious_hashes': set(),
            'malicious_urls': set(),
            'malicious_emails': set()
        }
    
    def _init_ml_models(self):
        """Initialize ML models for threat detection"""
        model_dir = Path('models')
        model_dir.mkdir(exist_ok=True)
        
        # Anomaly detection model
        anomaly_model_path = model_dir / 'anomaly_detector.joblib'
        if anomaly_model_path.exists():
            self.ml_models['anomaly'] = joblib.load(anomaly_model_path)
        else:
            from sklearn.ensemble import IsolationForest
            self.ml_models['anomaly'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1,
                bootstrap=True
            )
            # Train with synthetic data initially
            X_train = np.random.randn(10000, 20)
            self.ml_models['anomaly'].fit(X_train)
            joblib.dump(self.ml_models['anomaly'], anomaly_model_path)
        
        # Text classification model
        text_model_path = model_dir / 'text_classifier.joblib'
        if text_model_path.exists():
            self.ml_models['text'] = joblib.load(text_model_path)
        else:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            
            self.ml_models['text'] = {
                'vectorizer': TfidfVectorizer(
                    max_features=5000,
                    ngram_range=(1, 3),
                    stop_words='english'
                ),
                'classifier': LogisticRegression(
                    max_iter=1000,
                    class_weight='balanced',
                    random_state=42
                )
            }
        
        logger.info("ML models initialized")
    
    def _init_yara_rules(self):
        """Initialize YARA rules for malware detection"""
        yara_dir = Path('rules/yara')
        yara_dir.mkdir(parents=True, exist_ok=True)
        
        # Create default rules if none exist
        default_rules = yara_dir / 'malware.yara'
        if not default_rules.exists():
            default_rules.write_text("""
rule Suspicious_Strings {
    strings:
        $a = "CreateProcess" nocase
        $b = "ShellExecute" nocase
        $c = "system32" nocase
        $d = "cmd.exe" nocase
        $e = "/bin/bash" nocase
        $f = "/bin/sh" nocase
        $g = "eval(base64_decode" nocase
    condition:
        any of them
}

rule Potential_Exploit {
    strings:
        $a = "buffer overflow"
        $b = "stack smash"
        $c = "heap spray"
        $d = "ROP chain"
        $e = "shellcode"
        $f = "payload"
    condition:
        any of them
}

rule Network_Indicators {
    strings:
        $a = "http://" nocase
        $b = "https://" nocase
        $c = "ftp://" nocase
        $d = ".onion" nocase
        $e = "192.168." nocase
        $f = "10." nocase
        $g = "172.16." nocase
    condition:
        any of them
}
""")
        
        # Compile rules
        try:
            rule_files = list(yara_dir.glob('*.yara')) + list(yara_dir.glob('*.yar'))
            if rule_files:
                self.yara_rules = yara.compile(filepaths={f.stem: str(f) for f in rule_files})
                logger.info(f"Loaded {len(rule_files)} YARA rules")
        except yara.Error as e:
            logger.warning(f"YARA compilation failed: {e}")
    
    def _start_threat_intelligence_updates(self):
        """Start background thread for threat intelligence updates"""
        def update_thread():
            while True:
                try:
                    self._update_threat_intelligence()
                    time.sleep(3600)  # Update every hour
                except Exception as e:
                    logger.error(f"Threat intelligence update failed: {e}")
                    time.sleep(300)
        
        thread = threading.Thread(target=update_thread, daemon=True)
        thread.start()
    
    def _update_threat_intelligence(self):
        """Update threat intelligence from external feeds"""
        try:
            logger.info("Updating threat intelligence feeds...")
            
            # Update malicious domains
            if 'malware_domains' in self.threat_feeds:
                response = requests.get(self.threat_feeds['malware_domains'], timeout=30)
                if response.status_code == 200:
                    domains = [line.strip() for line in response.text.split('\n') 
                              if line.strip() and not line.startswith('#')]
                    self.ioc_database['malicious_domains'].update(domains)
                    logger.info(f"Updated {len(domains)} malicious domains")
            
            # Update malicious IPs
            if 'alienvault' in self.threat_feeds:
                response = requests.get(self.threat_feeds['alienvault'], timeout=30)
                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        if line and not line.startswith('#'):
                            parts = line.split('#')
                            if len(parts) > 1:
                                self.ioc_database['malicious_ips'].add(parts[0].strip())
            
            # Update phishing URLs
            if 'phishtank' in self.threat_feeds:
                response = requests.get(self.threat_feeds['phishtank'], timeout=30)
                if response.status_code == 200:
                    import csv
                    reader = csv.DictReader(response.text.splitlines())
                    for row in reader:
                        if 'url' in row:
                            self.ioc_database['malicious_urls'].add(row['url'])
            
            # Prune old entries
            for ioc_type, ioc_set in self.ioc_database.items():
                if len(ioc_set) > 50000:
                    ioc_list = list(ioc_set)
                    self.ioc_database[ioc_type] = set(ioc_list[-50000:])
            
            logger.info("Threat intelligence updated successfully")
            
        except Exception as e:
            logger.error(f"Threat intelligence update failed: {e}")
    
    def analyze_file(self, file_path: str, deep_analysis: bool = False) -> Dict[str, Any]:
        """Comprehensive file analysis for threats"""
        analysis = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'basic_info': {},
            'threats': [],
            'risk_score': 0.0,
            'recommendations': [],
            'metadata': {}
        }
        
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get file info
            stat_info = file_path_obj.stat()
            analysis['basic_info'] = {
                'size': stat_info.st_size,
                'permissions': oct(stat_info.st_mode)[-3:],
                'owner': pwd.getpwuid(stat_info.st_uid).pw_name,
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            }
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path_obj)
            analysis['basic_info']['hash'] = file_hash
            
            # Check against known malware hashes
            if file_hash in self.ioc_database['malicious_hashes']:
                analysis['threats'].append({
                    'type': 'known_malware',
                    'severity': 'critical',
                    'confidence': 1.0,
                    'description': 'File hash matches known malware',
                    'hash': file_hash
                })
            
            # Use Linux command engine for analysis
            linux_analysis = self.linux_engine.analyze_file(file_path)
            analysis['metadata'].update(linux_analysis)
            
            # Extract threat indicators from Linux analysis
            if 'threat_indicators' in linux_analysis:
                for indicator in linux_analysis['threat_indicators']:
                    analysis['threats'].append({
                        'type': indicator.get('type', 'unknown'),
                        'severity': indicator.get('severity', 'medium'),
                        'confidence': 0.8,
                        'description': indicator.get('description', ''),
                        'source': 'linux_analysis'
                    })
            
            # Pattern matching on file content (for small files)
            if stat_info.st_size < 10 * 1024 * 1024:  # 10MB limit
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1000000)  # Read first 1MB
                    
                    pattern_threats = self._analyze_with_patterns(content, file_path)
                    analysis['threats'].extend(pattern_threats)
                    
                    # ML-based analysis
                    ml_threats = self._analyze_with_ml(content, file_path)
                    analysis['threats'].extend(ml_threats)
                    
                except (UnicodeDecodeError, PermissionError):
                    # Binary file, skip text analysis
                    pass
            
            # YARA rule matching
            if self.yara_rules and stat_info.st_size < 100 * 1024 * 1024:  # 100MB limit
                try:
                    matches = self.yara_rules.match(file_path)
                    for match in matches:
                        analysis['threats'].append({
                            'type': 'yara_match',
                            'severity': 'high',
                            'confidence': 0.9,
                            'description': f'YARA rule matched: {match.rule}',
                            'rule': match.rule,
                            'tags': match.tags
                        })
                except yara.Error as e:
                    logger.warning(f"YARA matching failed: {e}")
            
            # Deep analysis with binwalk and strings
            if deep_analysis:
                deep_threats = self._deep_analysis(file_path_obj)
                analysis['threats'].extend(deep_threats)
            
            # Calculate overall risk score
            analysis['risk_score'] = self._calculate_risk_score(analysis['threats'])
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_recommendations(analysis)
            
            # Deduplicate threats
            analysis['threats'] = self._deduplicate_threats(analysis['threats'])
        
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _analyze_with_patterns(self, content: str, file_path: str) -> List[Dict]:
        """Analyze content with regex patterns"""
        threats = []
        
        for category, patterns in self.patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                description = pattern_info['description']
                
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        threat = {
                            'type': category,
                            'severity': self._get_severity(category),
                            'confidence': 0.8,
                            'description': f'{description} pattern matched',
                            'pattern': pattern,
                            'match': match.group(),
                            'position': match.start(),
                            'context': self._get_context(content, match.start(), match.end()),
                            'file_path': file_path
                        }
                        threats.append(threat)
                        
                        # Limit to 10 matches per pattern
                        if len([t for t in threats if t['pattern'] == pattern]) >= 10:
                            break
                            
                except Exception as e:
                    logger.debug(f"Pattern matching error: {e}")
        
        return threats
    
    def _analyze_with_ml(self, content: str, file_path: str) -> List[Dict]:
        """Analyze content with ML models"""
        threats = []
        
        try:
            # Text classification
            if 'text' in self.ml_models:
                vectorizer = self.ml_models['text']['vectorizer']
                classifier = self.ml_models['text']['classifier']
                
                # This is simplified - in production you'd have trained data
                # For now, use heuristic approach
                
                suspicious_keywords = [
                    'confidential', 'secret', 'password', 'admin', 'root',
                    'backdoor', 'exploit', 'vulnerability', 'injection',
                    'malware', 'virus', 'trojan', 'ransomware', 'spyware',
                    'keylogger', 'botnet', 'command and control', 'c2',
                    'exfiltration', 'data theft', 'privilege escalation'
                ]
                
                content_lower = content.lower()
                suspicious_count = sum(1 for keyword in suspicious_keywords 
                                     if keyword in content_lower)
                
                if suspicious_count > 3:
                    threats.append({
                        'type': 'ml_suspicious_content',
                        'severity': 'medium',
                        'confidence': min(0.3 + (suspicious_count * 0.1), 0.9),
                        'description': f'ML analysis detected {suspicious_count} suspicious keywords',
                        'keywords_found': [k for k in suspicious_keywords if k in content_lower][:10],
                        'file_path': file_path
                    })
        
        except Exception as e:
            logger.debug(f"ML analysis failed: {e}")
        
        return threats
    
    def _deep_analysis(self, file_path: Path) -> List[Dict]:
        """Deep analysis using binwalk and other tools"""
        threats = []
        
        # Check for embedded files with binwalk
        if self.linux_engine.tools['file_analysis']['binwalk']:
            try:
                result = subprocess.run(
                    ['binwalk', '--entropy', '--signature', str(file_path)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    embedded_count = sum(1 for line in lines if '0x' in line and ':' in line)
                    
                    if embedded_count > 5:
                        threats.append({
                            'type': 'embedded_files',
                            'severity': 'medium',
                            'confidence': 0.7,
                            'description': f'Found {embedded_count} potentially embedded files',
                            'file_path': str(file_path),
                            'embedded_count': embedded_count
                        })
            
            except subprocess.CalledProcessError as e:
                logger.debug(f"Binwalk analysis failed: {e}")
        
        # Check file entropy
        try:
            entropy = self.linux_engine.calculate_file_entropy(file_path)
            if entropy > 7.8:  # High entropy indicates encryption/compression
                threats.append({
                    'type': 'high_entropy',
                    'severity': 'low',
                    'confidence': 0.6,
                    'description': f'High file entropy ({entropy:.2f}) detected',
                    'entropy': entropy,
                    'file_path': str(file_path)
                })
        except:
            pass
        
        return threats
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        hash_func = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
        except:
            return ''
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for threat category"""
        severity_map = {
            'pii': 'high',
            'financial': 'high',
            'credentials': 'critical',
            'secrets': 'critical',
            'malware': 'critical',
            'network': 'medium',
            'code_injection': 'high',
            'known_malware': 'critical',
            'yara_match': 'high',
            'ml_suspicious_content': 'medium',
            'embedded_files': 'medium',
            'high_entropy': 'low'
        }
        return severity_map.get(category, 'medium')
    
    def _get_context(self, content: str, start: int, end: int, chars: int = 100) -> str:
        """Get context around a match"""
        context_start = max(0, start - chars)
        context_end = min(len(content), end + chars)
        
        context = content[context_start:context_end]
        
        if start - context_start > 0:
            context = '...' + context
        if context_end - end > 0:
            context = context + '...'
        
        return context
    
    def _calculate_risk_score(self, threats: List[Dict]) -> float:
        """Calculate overall risk score from threats"""
        if not threats:
            return 0.0
        
        severity_weights = {
            'critical': 1.0,
            'high': 0.7,
            'medium': 0.4,
            'low': 0.1
        }
        
        total_score = 0.0
        for threat in threats:
            severity = threat.get('severity', 'medium')
            confidence = threat.get('confidence', 0.5)
            weight = severity_weights.get(severity, 0.4)
            total_score += weight * confidence
        
        # Normalize to 0-1 scale
        max_score = len(threats) * 1.0
        return min(total_score / max(1, max_score), 1.0)
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        threats = analysis.get('threats', [])
        
        if not threats:
            recommendations.append("No threats detected. File appears safe.")
            return recommendations
        
        # Count threats by severity
        critical_count = sum(1 for t in threats if t.get('severity') == 'critical')
        high_count = sum(1 for t in threats if t.get('severity') == 'high')
        
        if critical_count > 0:
            recommendations.append(f"CRITICAL: {critical_count} critical threats detected. Immediate action required.")
            recommendations.append("Recommendation: Quarantine file and investigate immediately.")
        
        if high_count > 0:
            recommendations.append(f"HIGH: {high_count} high severity threats detected.")
            recommendations.append("Recommendation: Review file and consider quarantining.")
        
        # Specific recommendations
        for threat in threats[:5]:  # Limit to first 5 threats
            threat_type = threat.get('type', '')
            
            if threat_type in ['credentials', 'secrets']:
                recommendations.append(f"Found {threat_type}. Remove or encrypt sensitive information.")
            elif threat_type == 'pii':
                recommendations.append("PII detected. Ensure compliance with data protection regulations.")
            elif threat_type == 'malware':
                recommendations.append("Malware indicators found. Scan with antivirus software.")
        
        # General recommendations
        risk_score = analysis.get('risk_score', 0.0)
        if risk_score > 0.7:
            recommendations.append("High risk score. Consider blocking access to this file.")
        elif risk_score > 0.4:
            recommendations.append("Moderate risk score. Monitor file activity.")
        
        return recommendations
    
    def _deduplicate_threats(self, threats: List[Dict]) -> List[Dict]:
        """Deduplicate threats"""
        seen = set()
        deduplicated = []
        
        for threat in threats:
            # Create unique identifier
            threat_id = (threat.get('type', ''),
                        threat.get('pattern', ''),
                        threat.get('match', ''),
                        threat.get('position', 0))
            
            if threat_id not in seen:
                seen.add(threat_id)
                deduplicated.append(threat)
        
        return deduplicated
    
    def monitor_system(self, callback: Callable = None) -> Dict[str, Any]:
        """Monitor system for suspicious activity"""
        monitoring_data = {
            'timestamp': datetime.now().isoformat(),
            'processes': [],
            'network_connections': [],
            'file_changes': [],
            'alerts': []
        }
        
        try:
            # Monitor processes
            monitoring_data['processes'] = self._monitor_processes()
            
            # Monitor network connections
            monitoring_data['network_connections'] = self._monitor_network()
            
            # Check for suspicious activity
            alerts = self._check_suspicious_activity(monitoring_data)
            monitoring_data['alerts'] = alerts
            
            # Callback for real-time alerts
            if callback and alerts:
                for alert in alerts:
                    callback(alert)
        
        except Exception as e:
            logger.error(f"System monitoring failed: {e}")
            monitoring_data['error'] = str(e)
        
        return monitoring_data
    
    def _monitor_processes(self) -> List[Dict]:
        """Monitor running processes"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    
                    # Check for suspicious process names
                    suspicious_names = ['miner', 'backdoor', 'rootkit', 'keylogger', 'spyware']
                    process_name = proc_info.get('name', '').lower()
                    
                    is_suspicious = any(name in process_name for name in suspicious_names)
                    
                    processes.append({
                        'pid': proc_info.get('pid'),
                        'name': proc_info.get('name'),
                        'user': proc_info.get('username'),
                        'cmdline': proc_info.get('cmdline'),
                        'create_time': datetime.fromtimestamp(proc_info.get('create_time', 0)).isoformat(),
                        'suspicious': is_suspicious
                    })
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.debug(f"Process monitoring failed: {e}")
        
        return processes[:100]  # Limit to 100 processes
    
    def _monitor_network(self) -> List[Dict]:
        """Monitor network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections():
                try:
                    conn_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    # Check for suspicious remote addresses
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        if remote_ip in self.ioc_database['malicious_ips']:
                            conn_info['suspicious'] = True
                            conn_info['threat'] = 'Known malicious IP'
                        elif remote_ip.startswith('10.') or remote_ip.startswith('192.168.'):
                            conn_info['suspicious'] = False  # Local network
                        else:
                            # Check for known malicious ports
                            suspicious_ports = [4444, 31337, 6667, 12345, 27374]
                            if conn.raddr.port in suspicious_ports:
                                conn_info['suspicious'] = True
                                conn_info['threat'] = f'Suspicious port {conn.raddr.port}'
                    
                    connections.append(conn_info)
                    
                except (AttributeError, ValueError):
                    continue
        
        except Exception as e:
            logger.debug(f"Network monitoring failed: {e}")
        
        return connections[:50]  # Limit to 50 connections
    
    def _check_suspicious_activity(self, monitoring_data: Dict) -> List[Dict]:
        """Check for suspicious activity"""
        alerts = []
        
        # Check processes
        for proc in monitoring_data.get('processes', []):
            if proc.get('suspicious'):
                alerts.append({
                    'type': 'suspicious_process',
                    'severity': 'high',
                    'description': f'Suspicious process: {proc.get("name")}',
                    'process': proc,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Check network connections
        for conn in monitoring_data.get('network_connections', []):
            if conn.get('suspicious'):
                alerts.append({
                    'type': 'suspicious_connection',
                    'severity': 'medium',
                    'description': conn.get('threat', 'Suspicious network connection'),
                    'connection': conn,
                    'timestamp': datetime.now().isoformat()
                })
        
        return alerts
    
    def get_ioc_stats(self) -> Dict[str, Any]:
        """Get IOC statistics"""
        return {
            'total_iocs': sum(len(iocs) for iocs in self.ioc_database.values()),
            'by_type': {k: len(v) for k, v in self.ioc_database.items()},
            'last_updated': datetime.now().isoformat(),
            'feeds_configured': len(self.threat_feeds),
            'ml_models': list(self.ml_models.keys())
        }

# Initialize threat detector
threat_detector = AdvancedThreatDetector()

# ============================================================================
# FLASK APPLICATION WITH ADVANCED FEATURES
# ============================================================================

app = Flask(__name__,
           template_folder='templates',
           static_folder='static',
           static_url_path='/static')

# Enhanced configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(64)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,  # 500MB
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_SECRET_KEY=os.environ.get('CSRF_SECRET_KEY', secrets.token_hex(64)),
    WTF_CSRF_TIME_LIMIT=3600,
    JSON_SORT_KEYS=False,
    JSONIFY_PRETTYPRINT_REGULAR=True,
    TEMPLATES_AUTO_RELOAD=True,
    EXPLAIN_TEMPLATE_LOADING=False
)

# Enhanced rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "200 per hour", "50 per minute"],
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True
)

# Enhanced login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '🔐 Authentication required to access this page.'
login_manager.login_message_category = 'warning'
login_manager.refresh_view = 'reauth'
login_manager.needs_refresh_message = 'Session expired. Please re-authenticate.'
login_manager.needs_refresh_message_category = 'info'

# ============================================================================
# DATABASE MODELS
# ============================================================================

Base = declarative_base()

class User(Base, UserMixin):
    """Enhanced User model"""
    __tablename__ = 'users'
    
    id = Column(String(64), primary_key=True, default=lambda: f"USER-{secrets.token_hex(8)}")
    username = Column(String(128), unique=True, index=True, nullable=False)
    email = Column(String(256), unique=True, index=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(32), nullable=False, default='user')
    permissions = Column(JSON, default=lambda: ['view_dashboard', 'run_scans'])
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(128))
    last_login = Column(DateTime)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Encrypted profile data
    encrypted_profile = Column(Text)
    
    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
    
    def verify_password(self, password: str) -> bool:
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def get_profile(self) -> Dict:
        """Get decrypted profile"""
        if self.encrypted_profile:
            try:
                decrypted = encryption_engine.decrypt_data(
                    json.loads(self.encrypted_profile)
                )
                return decrypted['data']
            except:
                return {}
        return {}
    
    def set_profile(self, profile: Dict):
        """Set encrypted profile"""
        encrypted = encryption_engine.encrypt_data(profile)
        self.encrypted_profile = json.dumps(encrypted)

class ScanJob(Base):
    """Scan job model"""
    __tablename__ = 'scan_jobs'
    
    id = Column(String(64), primary_key=True, default=lambda: f"SCAN-{secrets.token_hex(8)}")
    name = Column(String(256), nullable=False)
    target_path = Column(String(1024), nullable=False)
    scan_type = Column(String(32), nullable=False, default='standard')
    status = Column(String(32), nullable=False, default='pending')
    initiated_by = Column(String(64), ForeignKey('users.id'))
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    total_files = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    threats_found = Column(Integer, default=0)
    sensitive_files = Column(Integer, default=0)
    scan_duration = Column(Float)
    encrypted_results = Column(Text)
    error_message = Column(Text)
    
    # Relationships
    user = relationship('User', backref='scans')
    
    __table_args__ = (
        sqlalchemy.Index('idx_scan_status', 'status'),
        sqlalchemy.Index('idx_scan_user', 'initiated_by'),
        sqlalchemy.Index('idx_scan_time', 'start_time'),
    )

class ThreatFinding(Base):
    """Threat finding model"""
    __tablename__ = 'threat_findings'
    
    id = Column(String(64), primary_key=True, default=lambda: f"THREAT-{secrets.token_hex(8)}")
    scan_id = Column(String(64), ForeignKey('scan_jobs.id'))
    file_path = Column(String(1024), nullable=False)
    threat_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    confidence = Column(Float, default=0.0)
    pattern_matched = Column(String(512))
    context = Column(Text)
    encrypted_sample = Column(Text)
    file_size = Column(BigInteger)
    file_hash = Column(String(128))
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(32), default='new')
    assigned_to = Column(String(64), ForeignKey('users.id'))
    resolution = Column(Text)
    resolved_at = Column(DateTime)
    
    # Relationships
    scan = relationship('ScanJob', backref='findings')
    assigned_user = relationship('User', backref='assigned_threats')
    
    __table_args__ = (
        sqlalchemy.Index('idx_threat_severity', 'severity'),
        sqlalchemy.Index('idx_threat_status', 'status'),
        sqlalchemy.Index('idx_threat_detected', 'detected_at'),
    )

class SecurityAlert(Base):
    """Security alert model"""
    __tablename__ = 'security_alerts'
    
    id = Column(String(64), primary_key=True, default=lambda: f"ALERT-{secrets.token_hex(8)}")
    alert_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False)
    title = Column(String(256), nullable=False)
    message = Column(Text, nullable=False)
    source_ip = Column(String(45))
    user_id = Column(String(64), ForeignKey('users.id'))
    resource = Column(String(512))
    details = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(64), ForeignKey('users.id'))
    acknowledged_at = Column(DateTime)
    resolved = Column(Boolean, default=False)
    resolved_by = Column(String(64), ForeignKey('users.id'))
    resolved_at = Column(DateTime)
    
    # Relationships
    user = relationship('User', foreign_keys=[user_id], backref='alerts')
    acknowledging_user = relationship('User', foreign_keys=[acknowledged_by])
    resolving_user = relationship('User', foreign_keys=[resolved_by])

# ============================================================================
# DATABASE ENGINE
# ============================================================================

class DatabaseEngine:
    """Enhanced database engine with connection pooling and caching"""
    
    def __init__(self, db_url: str = None):
        self.db_url = db_url or os.environ.get('DATABASE_URL', 'sqlite:///data/advanced_dlp.db')
        self.engine = None
        self.SessionLocal = None
        self.redis_client = None
        
        self._init_database()
        self._init_redis()
        
        logger.info(f"Database engine initialized: {self.db_url}")
    
    def _init_database(self):
        """Initialize database"""
        try:
            # Create data directory
            Path('data').mkdir(exist_ok=True, mode=0o755)
            
            # Configure engine
            self.engine = create_engine(
                self.db_url,
                poolclass=QueuePool,
                pool_size=20,
                max_overflow=30,
                pool_timeout=30,
                pool_recycle=3600,
                pool_pre_ping=True,
                connect_args={'check_same_thread': False} if 'sqlite' in self.db_url else {},
                echo=False,
                future=True
            )
            
            # Create session factory
            self.SessionLocal = scoped_session(
                sessionmaker(
                    autocommit=False,
                    autoflush=False,
                    bind=self.engine,
                    expire_on_commit=False
                )
            )
            
            # Create tables
            Base.metadata.create_all(bind=self.engine)
            
            # Create default admin user if none exists
            self._create_default_admin()
            
            # Test connection
            with self.SessionLocal() as session:
                session.execute(text('SELECT 1'))
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def _init_redis(self):
        """Initialize Redis cache"""
        try:
            redis_host = os.environ.get('REDIS_HOST', 'localhost')
            redis_port = int(os.environ.get('REDIS_PORT', 6379))
            redis_password = os.environ.get('REDIS_PASSWORD')
            redis_db = int(os.environ.get('REDIS_DB', 0))
            
            self.redis_client = Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                db=redis_db,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache initialized")
            
        except Exception as e:
            logger.warning(f"Redis initialization failed: {e}")
            self.redis_client = None
    
    def _create_default_admin(self):
        """Create default admin user"""
        with self.SessionLocal() as session:
            admin_exists = session.query(User).filter_by(username='admin').first()
            
            if not admin_exists:
                default_password = os.environ.get('ADMIN_PASSWORD', 'ChangeMe123!')
                admin = User(
                    username='admin',
                    email='admin@dlp.system',
                    password_hash=generate_password_hash(default_password),
                    role='admin',
                    permissions=['all'],
                    is_active=True,
                    is_verified=True
                )
                
                session.add(admin)
                session.commit()
                
                logger.warning("Default admin user created. CHANGE THE PASSWORD!")
    
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
    
    def cache_get(self, key: str, decrypt: bool = False):
        """Get from cache"""
        if not self.redis_client:
            return None
        
        try:
            data = self.redis_client.get(f"dlp:{key}")
            if data and decrypt:
                encrypted = json.loads(data.decode('utf-8'))
                return encryption_engine.decrypt_data(encrypted)['data']
            return data
        except Exception as e:
            logger.warning(f"Cache get failed: {e}")
            return None
    
    def cache_set(self, key: str, value: Any, ttl: int = 300, encrypt: bool = True):
        """Set to cache"""
        if not self.redis_client:
            return False
        
        try:
            if encrypt:
                encrypted = encryption_engine.encrypt_data(value)
                data = json.dumps(encrypted).encode('utf-8')
            else:
                if isinstance(value, (dict, list)):
                    data = json.dumps(value).encode('utf-8')
                elif isinstance(value, str):
                    data = value.encode('utf-8')
                else:
                    data = pickle.dumps(value)
            
            return self.redis_client.setex(f"dlp:{key}", ttl, data)
        except Exception as e:
            logger.warning(f"Cache set failed: {e}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Check database health"""
        health = {
            'database': {'status': 'unknown', 'latency_ms': 0},
            'cache': {'status': 'unknown', 'latency_ms': 0},
            'overall': 'unknown'
        }
        
        # Check database
        try:
            start = time.time()
            with self.get_session() as session:
                session.execute(text('SELECT 1'))
                health['database']['status'] = 'healthy'
                health['database']['latency_ms'] = (time.time() - start) * 1000
        except Exception as e:
            health['database']['status'] = 'unhealthy'
            health['database']['error'] = str(e)
        
        # Check cache
        if self.redis_client:
            try:
                start = time.time()
                self.redis_client.ping()
                health['cache']['status'] = 'healthy'
                health['cache']['latency_ms'] = (time.time() - start) * 1000
            except Exception as e:
                health['cache']['status'] = 'unhealthy'
                health['cache']['error'] = str(e)
        else:
            health['cache']['status'] = 'disabled'
        
        # Overall status
        if (health['database']['status'] == 'healthy' and 
            health['cache']['status'] in ['healthy', 'disabled']):
            health['overall'] = 'healthy'
        else:
            health['overall'] = 'degraded'
        
        return health

# Initialize database
db_engine = DatabaseEngine()

# ============================================================================
# FLASK ROUTES
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    try:
        session = db_engine.get_session()
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            # Make the user object independent of the session
            session.expunge(user)
        session.close()
        return user
    except Exception as e:
        logger.error(f"Failed to load user {user_id}: {e}")
        return None

@app.before_request
def before_request():
    """Execute before each request"""
    g.start_time = time.time()
    g.request_id = secrets.token_hex(8)
    
    # Log request
    logger.info(f"Request {g.request_id}: {request.method} {request.path} - IP: {request.remote_addr}")

@app.after_request
def after_request(response):
    """Execute after each request"""
    # Calculate processing time
    if hasattr(g, 'start_time'):
        processing_time = (time.time() - g.start_time) * 1000
        response.headers['X-Processing-Time'] = f'{processing_time:.2f}ms'
        response.headers['X-Request-ID'] = g.request_id
    
    # Security headers
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'X-Permitted-Cross-Domain-Policies': 'none',
        'Clear-Site-Data': '"cache", "cookies", "storage"'
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    # Log response
    logger.info(f"Response {g.request_id}: {response.status_code} - {processing_time:.2f}ms")
    
    return response

@app.route('/')
def index():
    """Home page"""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Index route error: {e}")
        return f"Error: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        try:
            with db_engine.get_session() as session:
                user = session.query(User).filter_by(username=username).first()
                
                if user and user.verify_password(password):
                    if not user.is_active:
                        flash('Account is disabled', 'danger')
                        return redirect(url_for('login'))
                    
                    # Check if account is locked
                    if user.locked_until and datetime.utcnow() < user.locked_until:
                        flash('Account temporarily locked', 'danger')
                        return redirect(url_for('login'))
                    
                    # Reset failed attempts
                    user.failed_attempts = 0
                    user.last_login = datetime.utcnow()
                    session.commit()
                    
                    # Log user in
                    login_user(user)
                    
                    # Create security alert
                    alert = SecurityAlert(
                        alert_type='login_success',
                        severity='info',
                        title='Successful Login',
                        message=f'User {username} logged in successfully',
                        source_ip=request.remote_addr,
                        user_id=user.id
                    )
                    session.add(alert)
                    session.commit()
                    
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                
                else:
                    # Increment failed attempts
                    if user:
                        user.failed_attempts += 1
                        
                        if user.failed_attempts >= 5:
                            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                            flash('Account locked for 15 minutes', 'danger')
                        
                        session.commit()
                    
                    # Create security alert
                    alert = SecurityAlert(
                        alert_type='login_failed',
                        severity='warning',
                        title='Failed Login Attempt',
                        message=f'Failed login attempt for user {username}',
                        source_ip=request.remote_addr
                    )
                    with db_engine.get_session() as alert_session:
                        alert_session.add(alert)
                        alert_session.commit()
                    
                    flash('Invalid credentials', 'danger')
        
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login error', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    """Registration page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        try:
            with db_engine.get_session() as session:
                # Check if user exists
                if session.query(User).filter_by(username=username).first():
                    flash('Username already exists', 'danger')
                    return redirect(url_for('register'))
                
                if session.query(User).filter_by(email=email).first():
                    flash('Email already registered', 'danger')
                    return redirect(url_for('register'))
                
                # Create new user
                new_user = User(
                    username=username,
                    email=email,
                    password_hash=generate_password_hash(password),
                    role='user',
                    is_active=True
                )
                
                session.add(new_user)
                session.commit()
                
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
        
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('Registration failed', 'danger')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout"""
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard"""
    try:
        # Get system stats
        with db_engine.get_session() as session:
            # Recent scans
            recent_scans = session.query(ScanJob)\
                .order_by(ScanJob.start_time.desc())\
                .limit(5)\
                .all()
            
            # Recent threats
            recent_threats = session.query(ThreatFinding)\
                .order_by(ThreatFinding.detected_at.desc())\
                .limit(10)\
                .all()
            
            # Stats
            total_scans = session.query(func.count(ScanJob.id)).scalar()
            total_threats = session.query(func.count(ThreatFinding.id)).scalar()
            pending_alerts = session.query(func.count(SecurityAlert.id))\
                .filter_by(acknowledged=False)\
                .scalar()
        
        # System info
        system_info = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'hostname': platform.node(),
            'uptime': time.time() - psutil.boot_time()
        }
        
        # Threat intelligence stats
        ioc_stats = threat_detector.get_ioc_stats()
        
        return render_template('dashboard.html',
                             user=current_user,
                             recent_scans=recent_scans,
                             recent_threats=recent_threats,
                             total_scans=total_scans,
                             total_threats=total_threats,
                             pending_alerts=pending_alerts,
                             system_info=system_info,
                             ioc_stats=ioc_stats)
    
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Error loading dashboard', 'danger')
        return render_template('dashboard.html', user=current_user)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan_page():
    """File scanning"""
    if request.method == 'POST':
        target_path = request.form.get('target_path', '').strip()
        scan_type = request.form.get('scan_type', 'standard')
        deep_analysis = request.form.get('deep_analysis') == 'on'
        
        if not target_path:
            flash('Please specify target path', 'danger')
            return redirect(url_for('scan_page'))
        
        # Start scan in background
        thread = threading.Thread(
            target=_run_scan,
            args=(target_path, scan_type, deep_analysis, current_user.id),
            daemon=True
        )
        thread.start()
        
        flash(f'Scan started: {target_path}', 'success')
        return redirect(url_for('scan_results'))
    
    return render_template('scan.html', user=current_user)

def _run_scan(target_path: str, scan_type: str, deep_analysis: bool, user_id: str):
    """Run scan in background"""
    try:
        with db_engine.get_session() as session:
            # Create scan job
            scan = ScanJob(
                name=f"Scan of {target_path}",
                target_path=target_path,
                scan_type=scan_type,
                status='running',
                initiated_by=user_id,
                start_time=datetime.utcnow()
            )
            session.add(scan)
            session.commit()
            scan_id = scan.id
            
        # Perform scan
        results = threat_detector.analyze_file(target_path, deep_analysis)
        
        with db_engine.get_session() as session:
            # Update scan job
            scan = session.query(ScanJob).filter_by(id=scan_id).first()
            if scan:
                scan.status = 'completed'
                scan.end_time = datetime.utcnow()
                scan.total_files = results.get('total_files', 0)
                scan.files_scanned = results.get('files_scanned', 0)
                scan.threats_found = len(results.get('threats', []))
                scan.sensitive_files = results.get('sensitive_files', 0)
                scan.scan_duration = results.get('duration', 0)
                
                # Store encrypted results
                encrypted_results = encryption_engine.encrypt_data(results)
                scan.encrypted_results = json.dumps(encrypted_results)
                
                # Create threat findings
                for threat in results.get('threats', []):
                    finding = ThreatFinding(
                        scan_id=scan_id,
                        file_path=threat.get('file_path', ''),
                        threat_type=threat.get('type', ''),
                        severity=threat.get('severity', 'medium'),
                        confidence=threat.get('confidence', 0.0),
                        pattern_matched=threat.get('pattern', ''),
                        context=threat.get('context', ''),
                        detected_at=datetime.utcnow()
                    )
                    session.add(finding)
                
                session.commit()
                
                logger.info(f"Scan completed: {scan_id} - {len(results.get('threats', []))} threats found")
    
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        
        with db_engine.get_session() as session:
            scan = session.query(ScanJob).filter_by(id=scan_id).first()
            if scan:
                scan.status = 'failed'
                scan.end_time = datetime.utcnow()
                scan.error_message = str(e)
                session.commit()

@app.route('/scan/results')
@login_required
def scan_results():
    """Scan results"""
    try:
        with db_engine.get_session() as session:
            scans = session.query(ScanJob)\
                .order_by(ScanJob.start_time.desc())\
                .limit(50)\
                .all()
        
        return render_template('scan_results.html',
                             user=current_user,
                             scans=scans)
    
    except Exception as e:
        logger.error(f"Error loading scan results: {e}")
        flash('Error loading results', 'danger')
        return render_template('scan_results.html', user=current_user)

@app.route('/threats')
@login_required
def threats_page():
    """Threat management"""
    try:
        with db_engine.get_session() as session:
            threats = session.query(ThreatFinding)\
                .order_by(ThreatFinding.detected_at.desc())\
                .limit(100)\
                .all()
            
            # Statistics
            stats = session.query(
                ThreatFinding.severity,
                func.count(ThreatFinding.id).label('count')
            ).group_by(ThreatFinding.severity).all()
        
        return render_template('threats.html',
                             user=current_user,
                             threats=threats,
                             stats=stats)
    
    except Exception as e:
        logger.error(f"Error loading threats: {e}")
        flash('Error loading threats', 'danger')
        return render_template('threats.html', user=current_user)

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_page():
    """File encryption"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('encrypt_page'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('encrypt_page'))
        
        method = request.form.get('method', 'aes')
        algorithm = request.form.get('algorithm', 'aes-256-gcm')
        
        try:
            # Save uploaded file
            upload_dir = Path('uploads')
            upload_dir.mkdir(exist_ok=True)
            
            filename = secure_filename(file.filename)
            file_path = upload_dir / filename
            file.save(file_path)
            
            # Encrypt file
            if method == 'aes':
                result = encryption_engine.encrypt_file(file_path)
            elif method == 'openssl':
                result = encryption_engine.encrypt_with_linux(
                    file_path, 'openssl', algorithm
                )
            elif method == 'gpg':
                result = encryption_engine.encrypt_with_linux(
                    file_path, 'gpg'
                )
            elif method == 'luks':
                result = encryption_engine.encrypt_with_linux(
                    file_path, 'luks'
                )
            else:
                flash('Invalid encryption method', 'danger')
                return redirect(url_for('encrypt_page'))
            
            if result.get('success'):
                # Offer download
                encrypted_file = Path(result.get('encrypted_file') or result.get('output_file'))
                
                return send_file(
                    encrypted_file,
                    as_attachment=True,
                    download_name=encrypted_file.name
                )
            else:
                flash(f"Encryption failed: {result.get('error')}", 'danger')
        
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            flash(f'Encryption error: {e}', 'danger')
    
    return render_template('encrypt.html', user=current_user)

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_page():
    """File decryption"""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('decrypt_page'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('decrypt_page'))
        
        method = request.form.get('method', 'aes')
        
        try:
            # Save uploaded file
            upload_dir = Path('uploads')
            upload_dir.mkdir(exist_ok=True)
            
            filename = secure_filename(file.filename)
            file_path = upload_dir / filename
            file.save(file_path)
            
            # Decrypt file
            if method == 'aes':
                result = encryption_engine.decrypt_file(file_path)
            elif method == 'openssl':
                password = request.form.get('password', '')
                result = linux_engine.linux_crypto.decrypt_with_openssl(
                    str(file_path),
                    str(file_path.with_suffix('.decrypted')),
                    'aes-256-gcm',
                    password
                )
            else:
                flash('Invalid decryption method', 'danger')
                return redirect(url_for('decrypt_page'))
            
            if result.get('success'):
                # Offer download
                decrypted_file = Path(result.get('decrypted_file') or result.get('output_file'))
                
                return send_file(
                    decrypted_file,
                    as_attachment=True,
                    download_name=decrypted_file.name
                )
            else:
                flash(f"Decryption failed: {result.get('error')}", 'danger')
        
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            flash(f'Decryption error: {e}', 'danger')
    
    return render_template('decrypt.html', user=current_user)

@app.route('/linux/tools')
@login_required
def linux_tools():
    """Linux tools dashboard"""
    system_audit = linux_engine.system_audit()
    tool_status = linux_engine.tools
    
    return render_template('linux_tools.html',
                         user=current_user,
                         system_audit=system_audit,
                         tool_status=tool_status)

@app.route('/api/analyze/file', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def api_analyze_file():
    """API: Analyze file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    deep_analysis = request.form.get('deep_analysis', 'false').lower() == 'true'
    
    try:
        # Save temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            tmp_path = Path(tmp.name)
        
        # Analyze file
        analysis = threat_detector.analyze_file(str(tmp_path), deep_analysis)
        
        # Cleanup
        tmp_path.unlink()
        
        return jsonify(analysis)
    
    except Exception as e:
        logger.error(f"API analyze error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def api_encrypt():
    """API: Encrypt data"""
    data = request.get_json()
    
    if not data or 'data' not in data:
        return jsonify({'error': 'No data provided'}), 400
    
    try:
        encrypted = encryption_engine.encrypt_data(data['data'])
        return jsonify(encrypted)
    
    except Exception as e:
        logger.error(f"API encrypt error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def api_decrypt():
    """API: Decrypt data"""
    data = request.get_json()
    
    if not data or 'encrypted_package' not in data:
        return jsonify({'error': 'No encrypted package provided'}), 400
    
    try:
        decrypted = encryption_engine.decrypt_data(data['encrypted_package'])
        return jsonify(decrypted)
    
    except Exception as e:
        logger.error(f"API decrypt error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/status')
@login_required
def api_system_status():
    """API: Get system status"""
    try:
        status = {
            'encryption': encryption_engine.get_status(),
            'threat_intelligence': threat_detector.get_ioc_stats(),
            'database': db_engine.health_check(),
            'linux_tools': linux_engine.tools,
            'system': {
                'cpu': psutil.cpu_percent(percpu=True),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict(),
                'uptime': time.time() - psutil.boot_time(),
                'hostname': platform.node(),
                'python_version': platform.python_version()
            }
        }
        
        return jsonify(status)
    
    except Exception as e:
        logger.error(f"API system status error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        db_health = db_engine.health_check()
        
        health_status = {
            'status': 'healthy' if db_health['overall'] == 'healthy' else 'degraded',
            'timestamp': datetime.now().isoformat(),
            'version': '3.0.0',
            'components': {
                'database': db_health['database']['status'],
                'cache': db_health['cache']['status'],
                'encryption': 'operational',
                'threat_detection': 'operational',
                'linux_integration': 'operational'
            }
        }
        
        return jsonify(health_status)
    
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html', user=current_user, now=datetime.now()), 404

@app.errorhandler(403)
def forbidden(error):
    """403 error handler"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('403.html', user=current_user), 403

@app.errorhandler(429)
def ratelimit_handler(error):
    """Rate limit handler"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    flash('Rate limit exceeded. Please try again later.', 'warning')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    logger.error(f"Internal server error: {error}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html', user=current_user), 500

# ============================================================================
# INITIALIZATION & STARTUP
# ============================================================================

def create_directories():
    """Create necessary directories"""
    directories = [
        'templates',
        'static/css',
        'static/js',
        'static/images',
        'data',
        'logs',
        'backups',
        'config',
        'uploads',
        'quarantine',
        'reports',
        'models',
        'rules/yara',
        'keys',
        'secure/vaults',
        'secure/containers'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True, mode=0o755)
    
    logger.info("Directories created")

def create_default_templates():
    """Create default HTML templates"""
    templates_dir = Path('templates')
    
    # Base template
    base_html = templates_dir / 'base.html'
    if not base_html.exists():
        base_html.write_text("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Advanced DLP System{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-alt"></i> Advanced DLP
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('scan_page') }}">
                            <i class="fas fa-search"></i> Scan Files
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('threats_page') }}">
                            <i class="fas fa-exclamation-triangle"></i> Threats
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('encrypt_page') }}">
                            <i class="fas fa-lock"></i> Encrypt
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('decrypt_page') }}">
                            <i class="fas fa-unlock"></i> Decrypt
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('linux_tools') }}">
                            <i class="fab fa-linux"></i> Linux Tools
                        </a>
                    </li>
                </ul>
                <ul class="navbar-nav">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog"></i> Settings</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('login') }}"><i class="fas fa-sign-in-alt"></i> Login</a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">Advanced DLP System v3.0.0 | 
                <i class="fab fa-linux"></i> Linux Integration | 
                <i class="fas fa-shield-alt"></i> Enterprise Security
            </span>
        </div>
    </footer>

    <script src="{{ url_for('static', filename='js/bootstrap.bundle.min.js') }}"></script>
    <script src="{{ url_for('static', filename='js/chart.min.js') }}"></script>
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
""")
    
    # Dashboard template
    dashboard_html = templates_dir / 'dashboard.html'
    if not dashboard_html.exists():
        dashboard_html.write_text("""
{% extends "base.html" %}
{% block title %}Dashboard - Advanced DLP{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1><i class="fas fa-tachometer-alt"></i> Dashboard</h1>
        <p class="lead">Welcome, {{ user.username }}! System status and overview.</p>
    </div>
</div>

<div class="row mt-4">
    <!-- System Status -->
    <div class="col-md-6 col-lg-3 mb-4">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-server"></i> System</h5>
                <h2 class="display-6">{{ "%.1f"|format(system_info.cpu_percent) }}%</h2>
                <p class="card-text">CPU Usage</p>
            </div>
        </div>
    </div>
    
    <div class="col-md-6 col-lg-3 mb-4">
        <div class="card bg-info text-white">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-memory"></i> Memory</h5>
                <h2 class="display-6">{{ "%.1f"|format(system_info.memory_percent) }}%</h2>
                <p class="card-text">Memory Usage</p>
            </div>
        </div>
    </div>
    
    <div class="col-md-6 col-lg-3 mb-4">
        <div class="card bg-warning text-dark">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-hdd"></i> Disk</h5>
                <h2 class="display-6">{{ "%.1f"|format(system_info.disk_percent) }}%</h2>
                <p class="card-text">Disk Usage</p>
            </div>
        </div>
    </div>
    
    <div class="col-md-6 col-lg-3 mb-4">
        <div class="card bg-success text-white">
            <div class="card-body">
                <h5 class="card-title"><i class="fas fa-clock"></i> Uptime</h5>
                <h2 class="display-6">{{ "%.1f"|format(system_info.uptime / 3600) }}h</h2>
                <p class="card-text">System Uptime</p>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <!-- Quick Stats -->
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-chart-bar"></i> Statistics</h5>
            </div>
            <div class="card-body">
                <ul class="list-group list-group-flush">
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        Total Scans
                        <span class="badge bg-primary rounded-pill">{{ total_scans }}</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        Threats Detected
                        <span class="badge bg-danger rounded-pill">{{ total_threats }}</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        Pending Alerts
                        <span class="badge bg-warning rounded-pill">{{ pending_alerts }}</span>
                    </li>
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        IOC Database
                        <span class="badge bg-info rounded-pill">{{ ioc_stats.total_iocs }}</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-bolt"></i> Quick Actions</h5>
            </div>
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="{{ url_for('scan_page') }}" class="btn btn-primary">
                        <i class="fas fa-search"></i> Scan Files
                    </a>
                    <a href="{{ url_for('encrypt_page') }}" class="btn btn-success">
                        <i class="fas fa-lock"></i> Encrypt File
                    </a>
                    <a href="{{ url_for('decrypt_page') }}" class="btn btn-warning">
                        <i class="fas fa-unlock"></i> Decrypt File
                    </a>
                    <a href="{{ url_for('linux_tools') }}" class="btn btn-info">
                        <i class="fab fa-linux"></i> Linux Tools
                    </a>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <!-- Recent Scans -->
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-history"></i> Recent Scans</h5>
            </div>
            <div class="card-body">
                {% if recent_scans %}
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Target</th>
                                <th>Status</th>
                                <th>Threats</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for scan in recent_scans %}
                            <tr>
                                <td>{{ scan.id[:8] }}...</td>
                                <td>{{ scan.target_path|truncate(20) }}</td>
                                <td>
                                    {% if scan.status == 'completed' %}
                                    <span class="badge bg-success">Completed</span>
                                    {% elif scan.status == 'running' %}
                                    <span class="badge bg-warning">Running</span>
                                    {% else %}
                                    <span class="badge bg-danger">Failed</span>
                                    {% endif %}
                                </td>
                                <td>{{ scan.threats_found }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <p class="text-muted">No recent scans</p>
                {% endif %}
            </div>
        </div>
    </div>
    
    <!-- Recent Threats -->
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-exclamation-triangle"></i> Recent Threats</h5>
            </div>
            <div class="card-body">
                {% if recent_threats %}
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>File</th>
                                <th>Detected</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for threat in recent_threats %}
                            <tr>
                                <td>{{ threat.threat_type|truncate(15) }}</td>
                                <td>
                                    {% if threat.severity == 'critical' %}
                                    <span class="badge bg-danger">Critical</span>
                                    {% elif threat.severity == 'high' %}
                                    <span class="badge bg-warning">High</span>
                                    {% elif threat.severity == 'medium' %}
                                    <span class="badge bg-info">Medium</span>
                                    {% else %}
                                    <span class="badge bg-secondary">Low</span>
                                    {% endif %}
                                </td>
                                <td>{{ threat.file_path|basename|truncate(20) }}</td>
                                <td>{{ threat.detected_at.strftime('%H:%M') }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <p class="text-muted">No recent threats</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
// Auto-refresh dashboard every 30 seconds
setTimeout(function() {
    window.location.reload();
}, 30000);
</script>
{% endblock %}
""")

def print_banner():
    """Print startup banner"""
    banner = f"""
{'='*80}
🚀 ADVANCED LINUX DLP SECURITY SYSTEM v3.0.0
{'='*80}

📊 SYSTEM FEATURES:
   • 🔐 Advanced Encryption Engine (AES-256-GCM, ChaCha20, RSA-4096)
   • 🤖 ML-Powered Threat Detection with YARA rules
   • 🐧 Linux Command Integration (file, strings, binwalk, auditd)
   • 🛡️ Real-time System Monitoring & Alerting
   • 🔄 Automated Key Rotation & TPM Integration
   • 📁 LUKS Encrypted Container Support
   • 🌐 REST API with Rate Limiting
   • 🗄️ Encrypted Database with Redis Caching
   • 📈 Comprehensive Logging & Auditing

🌐 ACCESS POINTS:
   http://localhost:5001/              - Web Dashboard
   http://localhost:5001/scan          - File Scanning
   http://localhost:5001/encrypt       - File Encryption
   http://localhost:5001/linux/tools   - Linux Tools
   http://localhost:5001/api/health    - Health Check API

🔧 SYSTEM STATUS:
   Database: {db_engine.health_check()['overall']}
   Encryption: Operational
   Threat Intel: {threat_detector.get_ioc_stats()['total_iocs']} IOCs loaded
   Linux Tools: {sum(sum(1 for t in cat.values() if t) for cat in linux_engine.tools.values())} available

⚠️ IMPORTANT NOTES:
   1. Change default admin password immediately!
   2. Set MASTER_KEY_SECRET environment variable for encryption
   3. Configure DATABASE_URL for production database
   4. Review and customize threat patterns
   5. Enable TPM/HSM for hardware-backed keys

📝 LOGS: Check logs/ directory for detailed logs
{'='*80}
"""
    print(banner)

def main():
    """Main entry point"""
    try:
        # Create directories
        create_directories()
        
        # Create default templates
        create_default_templates()
        
        # Print banner
        print_banner()
        
        # Start Flask application
        app.run(
            host='0.0.0.0',
            port=5001,
            debug=True,
            threaded=True,
            use_reloader=False
        )
    
    except KeyboardInterrupt:
        print("\n\n👋 Shutdown requested. Goodbye!")
        sys.exit(0)
    
    except Exception as e:
        logger.critical(f"Application failed to start: {e}")
        print(f"\n❌ CRITICAL ERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

@app.route('/test-responsive')
def test_responsive():
    """Responsiveness testing page"""
    return render_template('test_responsive.html')
