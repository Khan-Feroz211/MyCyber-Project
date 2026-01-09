# Advanced Linux DLP Security System - Complete Documentation

## 🎯 Project Overview
Enterprise-grade Data Loss Prevention (DLP) system built for Linux with advanced encryption, threat detection, and system monitoring capabilities.

## 🏗️ Architecture

### Core Components

#### 1. **Advanced Encryption Engine**
- **Algorithms**: AES-256-GCM, ChaCha20-Poly1305, RSA-4096, ECC-P521
- **Key Management**: Automated rotation, TPM/HSM integration, PBKDF2 key derivation
- **Features**:
  - Master key encryption with Fernet
  - Ephemeral keys for file encryption
  - Hardware acceleration support (AES-NI)
  - LUKS container creation
  - GPG/OpenSSL integration

#### 2. **Threat Detection System**
- **Pattern Matching**: Regex-based detection for PII, credentials, secrets
- **YARA Rules**: Malware signature detection
- **ML Models**: Anomaly detection with Isolation Forest
- **Threat Intelligence**: Real-time IOC updates from external feeds
- **Categories Detected**:
  - PII (SSN, credit cards, bank accounts)
  - Financial data (IBAN, credit cards)
  - Credentials (AWS keys, GitHub tokens, API keys)
  - Secrets (private keys, JWT, passwords)
  - Malware indicators
  - Code injection patterns

#### 3. **Linux Command Integration**
- **File Analysis**: file, strings, binwalk, exiftool
- **Security Tools**: clamscan, yara, nmap, auditd
- **System Monitoring**: lsof, strace, ltrace
- **Cryptography**: openssl, gpg, cryptsetup
- **Network Analysis**: tcpdump, ss, netstat, iftop

#### 4. **Web Application (Flask)**
- **Authentication**: Flask-Login with session management
- **Rate Limiting**: Flask-Limiter (1000/day, 200/hour, 50/min)
- **Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **API Endpoints**: RESTful API with JSON responses
- **Features**:
  - Dashboard with system stats
  - File scanning interface
  - Encryption/decryption tools
  - Threat management
  - Linux tools integration

#### 5. **Database Layer**
- **Primary**: SQLAlchemy with SQLite (production: PostgreSQL)
- **Caching**: Redis (optional)
- **Models**:
  - User (with encrypted profiles)
  - ScanJob (file scan tracking)
  - ThreatFinding (detected threats)
  - SecurityAlert (system alerts)
- **Features**:
  - Connection pooling
  - Encrypted data storage
  - Audit logging

## 📦 Technology Stack

### Backend
- **Python 3.12+**
- **Flask 3.0** - Web framework
- **SQLAlchemy 2.0** - ORM
- **Cryptography 41.0** - Encryption
- **scikit-learn** - ML models
- **psutil** - System monitoring

### Security
- **bcrypt** - Password hashing
- **PyNaCl** - Modern cryptography
- **YARA** - Malware detection
- **python-magic** - File type detection

### Linux Integration
- **systemd-python** - Systemd integration
- **pyinotify** - File system monitoring
- **scapy** - Network packet analysis
- **python-nmap** - Network scanning

### Data Processing
- **pandas** - Data analysis
- **numpy** - Numerical computing
- **reportlab** - PDF generation
- **pdfplumber** - PDF parsing

## 🔧 System Requirements

### Minimum
- **OS**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **CPU**: 4 cores
- **RAM**: 8GB
- **Disk**: 20GB free space
- **Python**: 3.8+

### Recommended
- **CPU**: 8+ cores
- **RAM**: 16GB
- **Disk**: 50GB SSD
- **Network**: 100Mbps+

## 🚀 Installation

### 1. Clone Repository
```bash
git clone https://github.com/Khan-Feroz211/MyCyber-Project.git
cd MyCyber-Project
```

### 2. Create Virtual Environment
```bash
python3 -m venv env
source env/bin/activate
```

### 3. Install Dependencies
```bash
pip install Flask flask-login flask-limiter flask-wtf WTForms
pip install cryptography bcrypt PyNaCl SQLAlchemy redis
pip install psutil scikit-learn joblib requests reportlab
pip install python-magic chardet pdfplumber python-docx openpyxl
pip install systemd-python pyinotify yara-python scapy python-nmap
pip install dnspython netifaces docker kubernetes gensim
pip install aiofiles aiohttp beautifulsoup4 whois
```

### 4. Set Environment Variables
```bash
export MASTER_KEY_SECRET="your-secret-key-here"
export ADMIN_PASSWORD="your-admin-password"
```

### 5. Run Application
```bash
python app.py
```

## 🎮 Usage

### Web Interface
Access at: `http://localhost:5001`

**Default Credentials:**
- Username: `admin`
- Password: Set via `ADMIN_PASSWORD` env variable

### Dashboard Features
1. **System Monitoring**: CPU, memory, disk, network stats
2. **Scan Management**: Create and track file scans
3. **Threat Analysis**: View and manage detected threats
4. **Encryption Tools**: Encrypt/decrypt files
5. **Linux Tools**: Access to system commands

### API Endpoints

#### Health Check
```bash
curl http://localhost:5001/api/health
```

#### Analyze File
```bash
curl -X POST http://localhost:5001/api/analyze/file \
  -H "Authorization: Bearer TOKEN" \
  -F "file=@/path/to/file"
```

#### Encrypt Data
```bash
curl -X POST http://localhost:5001/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "sensitive information"}'
```

#### System Status
```bash
curl http://localhost:5001/api/system/status
```

## 🔐 Security Features

### 1. Encryption
- **At Rest**: All sensitive data encrypted in database
- **In Transit**: HTTPS with TLS 1.3
- **Key Management**: Automated rotation, secure storage

### 2. Authentication
- **Password Hashing**: bcrypt with salt
- **Session Management**: Secure cookies, CSRF protection
- **Rate Limiting**: Prevents brute force attacks
- **Account Lockout**: After 5 failed attempts

### 3. Audit Logging
- All actions logged with timestamps
- User activity tracking
- Security event monitoring
- Encrypted audit logs

### 4. Linux Security Integration
- SELinux context checking
- File capabilities detection
- Setuid/setgid monitoring
- System audit integration

## 📊 Performance

### Benchmarks (CPU-only)
- **File Encryption**: ~50 MB/s (AES-256-GCM)
- **Pattern Matching**: ~1000 files/minute
- **YARA Scanning**: ~500 files/minute
- **Database Queries**: <10ms average

### Optimization Tips
1. Enable Redis caching
2. Use SSD for database
3. Increase worker threads
4. Enable parallel processing
5. Use file type filtering

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find process using port
lsof -i :5001
# Kill process
kill <PID>
```

### Missing Dependencies
```bash
# Install system packages
sudo apt-get install python3-dev libssl-dev
```

### Permission Errors
```bash
# Run with sudo for system commands
sudo python app.py
```

### Database Errors
```bash
# Reset database
rm -rf data/
python app.py
```

## 📈 Monitoring

### Log Files
- **Application**: `logs/advanced_dlp.log`
- **Security**: `logs/security.log`
- **Performance**: `logs/performance.log`
- **Encryption**: `logs/encryption_audit.log`

### Metrics
- System resource usage
- Scan statistics
- Threat detection rates
- API response times

## 🔄 Maintenance

### Daily
- Check logs for errors
- Review security alerts
- Monitor system resources

### Weekly
- Update threat intelligence feeds
- Review detected threats
- Backup encryption keys

### Monthly
- Rotate encryption keys
- Update dependencies
- Security audit
- Performance review

## 🤝 Contributing
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License
MIT License - See LICENSE file

## 👤 Author
**Feroz Khan**
- GitHub: [@Khan-Feroz211](https://github.com/Khan-Feroz211)

## 🙏 Acknowledgments
- Flask framework
- Cryptography library
- scikit-learn
- YARA project
- Linux security tools community

## 📞 Support
- Issues: GitHub Issues
- Email: Contact via GitHub profile
- Documentation: See docs/ folder

## 🗺️ Roadmap
- [ ] GPU acceleration support
- [ ] Distributed scanning
- [ ] Cloud storage integration
- [ ] Advanced ML models
- [ ] Mobile app
- [ ] Kubernetes deployment
- [ ] Multi-tenancy support