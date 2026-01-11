#!/bin/bash

echo "🔍 DLP SYSTEM QUICK CHECK"
echo "══════════════════════════════════════"
echo ""

# 1. Files Check
echo "1️⃣ CRITICAL FILES:"
[ -f "app.py" ] && echo "✅ app.py" || echo "❌ app.py"
[ -f "templates/login.html" ] && echo "✅ login.html" || echo "❌ login.html"
[ -f "static/css/style.css" ] && echo "✅ style.css" || echo "❌ style.css"
[ -f "data/advanced_dlp.db" ] && echo "✅ database" || echo "❌ database"
echo ""

# 2. Database Check
echo "2️⃣ DATABASE:"
sqlite3 data/advanced_dlp.db "SELECT username, role FROM users;" 2>/dev/null || echo "❌ Can't read database"
echo ""

# 3. App Status
echo "3️⃣ APP STATUS:"
if pgrep -f "python.*app.py" > /dev/null; then
    echo "✅ App is RUNNING"
    PORT_CHECK=$(ss -tuln | grep ":5000" || netstat -tuln | grep ":5000")
    [ -n "$PORT_CHECK" ] && echo "✅ Port 5000 is LISTENING" || echo "❌ Port 5000 NOT listening"
else
    echo "❌ App is NOT running"
fi
echo ""

# 4. Password Test
echo "4️⃣ LOGIN TEST:"
python3 << 'PYEND'
import sqlite3
from werkzeug.security import check_password_hash
try:
    db = sqlite3.connect('data/advanced_dlp.db')
    c = db.cursor()
    c.execute('SELECT password_hash FROM users WHERE username="admin"')
    h = c.fetchone()
    if h and check_password_hash(h[0], 'admin123'):
        print('✅ admin/admin123 will work')
    elif h and check_password_hash(h[0], 'ChangeMe123!'):
        print('⚠️  Password is: ChangeMe123!')
    else:
        print('❌ Password unknown - Run fix script')
    db.close()
except Exception as e:
    print(f'❌ Error: {e}')
PYEND
echo ""

# 5. Errors Check
echo "5️⃣ RECENT ERRORS:"
if [ -d "logs" ]; then
    find logs -name "*.log" -exec grep "ERROR" {} \; 2>/dev/null | tail -3 | cut -c1-100
    [ $? -ne 0 ] && echo "✅ No errors found"
else
    echo "ℹ️  No logs directory"
fi
echo ""

# 6. Quick Stats
echo "6️⃣ QUICK STATS:"
echo "Routes: $(grep -c '@app.route' app.py)"
echo "Users: $(sqlite3 data/advanced_dlp.db 'SELECT COUNT(*) FROM users;' 2>/dev/null)"
echo "CSS lines: $(wc -l < static/css/style.css 2>/dev/null)"
echo "Templates: $(find templates -name '*.html' 2>/dev/null | wc -l)"
echo ""

echo "══════════════════════════════════════"
echo "🎯 NEXT STEPS:"
echo "1. Fix password: python3 fix_database_issue.py"
echo "2. Start app: python3 app.py"
echo "3. Test at: http://localhost:5000"
echo ""
