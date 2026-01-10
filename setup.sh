#!/bin/bash

# CyberShield DLP Security System - Setup Script
# This script helps set up the project for first-time use

echo "========================================="
echo "CyberShield DLP Security System Setup"
echo "========================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ -d "venv" ]; then
    echo "Virtual environment already exists. Skipping..."
else
    python3 -m venv venv
    echo "Virtual environment created successfully!"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "Creating project directories..."
mkdir -p data
mkdir -p logs
mkdir -p backups
mkdir -p uploads
mkdir -p static/css
mkdir -p static/js
mkdir -p static/images
mkdir -p templates
mkdir -p modules
mkdir -p tests
mkdir -p docs

# Create initial data files
echo ""
echo "Creating initial data files..."

# Create users.json
cat > data/users.json << 'EOF'
{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "password_hash": "pbkdf2:sha256:600000$...",
      "role": "admin",
      "email": "admin@cybershield.local",
      "created_at": "2025-01-01T00:00:00",
      "last_login": null,
      "active": true
    }
  ]
}
EOF

# Create policies.json
cat > data/policies.json << 'EOF'
{
  "policies": []
}
EOF

# Create incidents.json
cat > data/incidents.json << 'EOF'
{
  "incidents": []
}
EOF

# Create logs.json
cat > data/logs.json << 'EOF'
{
  "logs": []
}
EOF

# Create .env file
if [ ! -f ".env" ]; then
    echo ""
    echo "Creating .env configuration file..."
    cat > .env << 'EOF'
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=change-this-to-a-random-secret-key
PORT=5001

# Security Settings
SESSION_TIMEOUT=3600
MAX_LOGIN_ATTEMPTS=5
PASSWORD_MIN_LENGTH=8

# Paths
DATA_DIR=./data
LOG_DIR=./logs
BACKUP_DIR=./backups
UPLOAD_DIR=./uploads
EOF
    echo "⚠️  IMPORTANT: Edit .env and change the SECRET_KEY!"
fi

# Create example configuration
if [ ! -f "config.py" ]; then
    echo ""
    echo "Creating configuration file..."
    cat > config.py << 'EOF'
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    DEBUG = os.environ.get('FLASK_ENV') == 'development'
    
    # Server
    HOST = '0.0.0.0'
    PORT = int(os.environ.get('PORT', 5001))
    
    # Session
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('SESSION_TIMEOUT', 3600))
    
    # Security
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 8))
    
    # Paths
    DATA_DIR = os.environ.get('DATA_DIR', './data')
    LOG_DIR = os.environ.get('LOG_DIR', './logs')
    BACKUP_DIR = os.environ.get('BACKUP_DIR', './backups')
    UPLOAD_DIR = os.environ.get('UPLOAD_DIR', './uploads')
EOF
fi

echo ""
echo "========================================="
echo "Setup completed successfully! ✅"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Edit .env and change SECRET_KEY"
echo "2. Review config.py settings"
echo "3. Place your app.py in the project root"
echo "4. Run: python app.py"
echo ""
echo "Access the application at: http://localhost:5001"
echo ""
echo "Default credentials:"
echo "  Admin:   admin / admin123"
echo "  Manager: manager / manager123"
echo "  User:    user / user123"
echo ""
echo "⚠️  Remember to change default passwords after first login!"
echo ""
