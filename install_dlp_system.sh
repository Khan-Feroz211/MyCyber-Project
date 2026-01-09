#!/bin/bash
# DLP Security System Installation Script
# Run with: bash install_dlp_system.sh

set -e

echo "🚀 DLP Security System Installation"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}Warning: Running as root is not recommended.${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check Python version
echo "🔍 Checking Python version..."
python3 --version || { echo -e "${RED}Python3 is required${NC}"; exit 1; }

# Check pip
echo "📦 Checking pip..."
python3 -m pip --version || { echo -e "${RED}pip is required${NC}"; exit 1; }

# Create virtual environment
echo "🏗️ Creating virtual environment..."
python3 -m venv venv || { echo -e "${RED}Failed to create virtual environment${NC}"; exit 1; }

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install required packages
echo "📥 Installing dependencies..."
pip install -r requirements.txt || {
    echo -e "${YELLOW}requirements.txt not found, installing default packages...${NC}"
    pip install flask flask-login flask-wtf werkzeug
    pip install psutil numpy scikit-learn pandas
    pip install cryptography requests beautifulsoup4
    pip install python-dateutil pyyaml
    pip install watchdog python-magic
}

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p {models,backups,quarantine,exports,uploads,logs}
mkdir -p static/{css,js,images}
mkdir -p templates/{linux,compliance,incidents}
mkdir -p data/{threat_intel,incidents,backups,logs}
mkdir -p scripts/{monitoring,backup,security}
mkdir -p config

# Linux system directories
echo "🐧 Setting up Linux integration..."
sudo mkdir -p /etc/dlp_system 2>/dev/null || true
sudo mkdir -p /var/log/dlp_system 2>/dev/null || true
sudo mkdir -p /var/lib/dlp_system 2>/dev/null || true

# Set permissions
echo "🔐 Setting permissions..."
sudo chown -R $(whoami):$(whoami) /var/log/dlp_system 2>/dev/null || true
sudo chmod 755 /var/log/dlp_system 2>/dev/null || true

# Create configuration file
echo "⚙️ Creating configuration..."
if [ ! -f config/settings.py ]; then
    cat > config/settings.py << 'CONFIG'
# DLP Configuration
SECRET_KEY = "$(openssl rand -hex 32)"
ENCRYPTION_KEY = "$(openssl rand -hex 32)"
CONFIG
fi

# Create systemd service
echo "⚙️ Creating systemd service..."
sudo tee /etc/systemd/system/dlp_system.service > /dev/null << 'SYSTEMD'
[Unit]
Description=DLP Security System
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/python app_linux_enhanced.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSTEMD

# Create default admin user
echo "👤 Creating default admin configuration..."
cat > config/admins.json << 'ADMINS'
[
    {
        "username": "admin",
        "email": "admin@localhost",
        "role": "admin",
        "password_hash": "$2b$12$YourHashedPasswordHere"
    }
]
ADMINS

# Create firewall setup script
echo "🔥 Creating firewall setup..."
cat > scripts/setup_firewall.sh << 'FIREWALL'
#!/bin/bash
# Simple firewall setup for DLP system
if command -v ufw >/dev/null; then
    sudo ufw allow 22/tcp
    sudo ufw allow 5000/tcp
    sudo ufw --force enable
    echo "UFW configured"
elif command -v firewall-cmd >/dev/null; then
    sudo firewall-cmd --permanent --add-port=5000/tcp
    sudo firewall-cmd --reload
    echo "Firewalld configured"
else
    echo "No supported firewall found"
fi
FIREWALL
chmod +x scripts/setup_firewall.sh

# Create backup script
echo "💾 Creating backup script..."
cat > scripts/backup_dlp.sh << 'BACKUP'
#!/bin/bash
# Backup DLP system
BACKUP_DIR="/var/lib/dlp_system/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/dlp_backup_$TIMESTAMP.tar.gz"

mkdir -p $BACKUP_DIR

# Backup important files
tar -czf $BACKUP_FILE \
    --exclude=venv \
    --exclude=__pycache__ \
    --exclude=*.log \
    .

echo "Backup created: $BACKUP_FILE"

# Clean old backups (keep last 30 days)
find $BACKUP_DIR -name "dlp_backup_*.tar.gz" -mtime +30 -delete
BACKUP
chmod +x scripts/backup_dlp.sh

# Create cron job for backups
echo "⏰ Setting up cron jobs..."
(crontab -l 2>/dev/null | grep -v "backup_dlp.sh"; echo "0 2 * * * $(pwd)/scripts/backup_dlp.sh") | crontab -

# Generate SSL certificates for HTTPS
echo "🔒 Generating SSL certificates..."
mkdir -p ssl
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem \
    -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null || \
    echo -e "${YELLOW}SSL certificate generation skipped${NC}"

# Create test files
echo "🧪 Creating test files..."
mkdir -p tests
cat > tests/test_basic.py << 'TEST'
#!/usr/bin/env python3
"""Basic system tests"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestDLPSystem(unittest.TestCase):
    def test_imports(self):
        """Test that required modules can be imported"""
        try:
            import flask
            import psutil
            import cryptography
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Import failed: {e}")
    
    def test_directories(self):
        """Test that required directories exist"""
        required_dirs = ['models', 'backups', 'logs', 'data']
        for dir_name in required_dirs:
            self.assertTrue(os.path.exists(dir_name), f"Directory {dir_name} missing")

if __name__ == '__main__':
    unittest.main()
TEST

# Final setup
echo "🎉 Installation complete!"
echo ""
echo "📋 NEXT STEPS:"
echo "   1. Review configuration: nano config/settings.py"
echo "   2. Start the system: ./start_dlp.sh"
echo "   3. Access web interface: https://localhost:5000"
echo "   4. Default login: admin / Admin@123"
echo ""
echo "🔧 Available scripts:"
echo "   ./scripts/setup_firewall.sh    - Configure firewall"
echo "   ./scripts/backup_dlp.sh        - Manual backup"
echo "   ./linux_system_monitor.py      - System monitoring"
echo ""
echo "📊 System information:"
echo "   Python: $(python3 --version | cut -d' ' -f2)"
echo "   Directory: $(pwd)"
echo "   Virtual env: $(pwd)/venv"
echo "   Logs: /var/log/dlp_system/"
echo ""
echo "🐧 For systemd service:"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl enable dlp_system"
echo "   sudo systemctl start dlp_system"
echo "   sudo systemctl status dlp_system"
