#!/bin/bash
# DLP Security System Startup Script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🐧 DLP Security System - Linux Enterprise Edition${NC}"
echo -e "${BLUE}==================================================${NC}"

# Check if running in correct directory
if [ ! -f "app_linux_enhanced.py" ]; then
    echo -e "${RED}Error: app_linux_enhanced.py not found${NC}"
    echo "Please run this script from the DLP system directory"
    exit 1
fi

# Check virtual environment
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt 2>/dev/null || {
        echo "Installing default packages..."
        pip install flask flask-login psutil numpy scikit-learn cryptography
    }
else
    source venv/bin/activate
fi

# Check for required packages
echo -e "${BLUE}🔍 Checking dependencies...${NC}"
python3 -c "
import sys
required = ['flask', 'flask_login', 'psutil', 'cryptography', 'sklearn']
missing = []
for pkg in required:
    try:
        __import__(pkg.replace('-', '_'))
    except ImportError:
        missing.append(pkg)
if missing:
    print(f'Missing packages: {missing}')
    sys.exit(1)
else:
    print('All dependencies satisfied')
" || {
    echo -e "${YELLOW}Installing missing packages...${NC}"
    pip install flask flask-login psutil cryptography scikit-learn
}

# Start system monitor in background
echo -e "${BLUE}📊 Starting system monitor...${NC}"
if [ -f "linux_system_monitor.py" ]; then
    python3 linux_system_monitor.py &
    MONITOR_PID=$!
    echo "System monitor PID: $MONITOR_PID"
fi

# Start main application
echo -e "${BLUE}🚀 Starting DLP Security System...${NC}"
echo -e "${GREEN}🌐 Web interface: http://localhost:5000${NC}"
echo -e "${GREEN}   HTTPS: https://localhost:5000${NC}"
echo -e "${YELLOW}   Default login: admin / Admin@123${NC}"
echo -e "${BLUE}   Press Ctrl+C to stop${NC}"
echo ""

# Run the application
python3 app_linux_enhanced.py

# Cleanup on exit
if [ ! -z "$MONITOR_PID" ]; then
    echo -e "${BLUE}🛑 Stopping system monitor...${NC}"
    kill $MONITOR_PID 2>/dev/null
fi

echo -e "${GREEN}👋 DLP system stopped${NC}"
