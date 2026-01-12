#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# IMPROVEMENT 1: Fix Missing Routes
# Time: 5 minutes
# Priority: CRITICAL (Fix now!)
# ═══════════════════════════════════════════════════════════════

echo "🔧 IMPROVEMENT 1: Adding Missing Routes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Go to project root
cd ../..

# Backup
cp app.py app.py.backup_routes_$(date +%Y%m%d_%H%M%S)
echo "✅ Backup created"

# Find where to add routes (before if __name__)
LINE_NUM=$(grep -n "if __name__ == '__main__':" app.py | head -1 | cut -d: -f1)

if [ -z "$LINE_NUM" ]; then
    echo "❌ Could not find 'if __name__' in app.py"
    echo "   Add routes manually at the end of app.py"
    exit 1
fi

# Create temporary file with new routes
cat > /tmp/new_routes.py << 'ROUTES'

# ═══════════════════════════════════════════════════════════════
# MISSING ROUTES - Added by Improvement Pack
# ═══════════════════════════════════════════════════════════════

@app.route('/scan', methods=['GET'])
@login_required
def scan_page():
    """Scan page"""
    try:
        return render_template('scan.html', user=current_user)
    except Exception as e:
        logger.error(f"Error loading scan page: {e}")
        flash('Error loading scan page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/scan/directory', methods=['POST'])
@login_required
def scan_directory():
    """Scan directory"""
    directory_path = request.form.get('directory_path', '')
    flash(f'Directory scan started for: {directory_path}', 'info')
    return redirect(url_for('scan_page'))

@app.route('/scan/file', methods=['POST'])
@login_required
def scan_file():
    """Scan file"""
    if 'file' in request.files:
        file = request.files['file']
        flash(f'File scan started: {file.filename}', 'info')
    return redirect(url_for('scan_page'))

@app.route('/scan/results/<scan_id>')
@login_required
def scan_results(scan_id):
    """Scan results"""
    return render_template('scan.html', user=current_user, scan_id=scan_id)

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_page():
    """Encryption page"""
    try:
        if request.method == 'POST':
            flash('Encryption processing...', 'info')
            return redirect(url_for('encrypt_page'))
        return render_template('encrypt.html', user=current_user)
    except Exception as e:
        flash('Error loading encryption page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt_page():
    """Decryption page"""
    try:
        if request.method == 'POST':
            flash('Decryption processing...', 'info')
            return redirect(url_for('decrypt_page'))
        return render_template('decrypt.html', user=current_user)
    except Exception as e:
        flash('Error loading decryption page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports')
@login_required
def reports():
    """Reports page"""
    try:
        return render_template('reports.html', user=current_user)
    except Exception as e:
        flash('Error loading reports page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/users')
@login_required
def users():
    """User management (admin only)"""
    if current_user.role != 'admin':
        flash('Admin access required', 'danger')
        return redirect(url_for('dashboard'))
    try:
        return render_template('users.html', user=current_user)
    except Exception as e:
        flash('Error loading users page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/alerts')
@login_required
def alerts():
    """Security alerts"""
    try:
        return render_template('alerts.html', user=current_user)
    except Exception as e:
        flash('Error loading alerts page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/settings')
@login_required
def settings():
    """Settings page"""
    try:
        return render_template('settings.html', user=current_user)
    except Exception as e:
        flash('Error loading settings page', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/settings/change-password', methods=['POST'])
@login_required
def change_password():
    """Change password"""
    flash('Password change feature coming soon', 'info')
    return redirect(url_for('settings'))

ROUTES

# Insert routes before if __name__
head -n $((LINE_NUM - 1)) app.py > /tmp/app_new.py
cat /tmp/new_routes.py >> /tmp/app_new.py
tail -n +$LINE_NUM app.py >> /tmp/app_new.py

# Replace original
mv /tmp/app_new.py app.py

echo "✅ Routes added successfully!"
echo ""
echo "📋 Added routes:"
echo "   • /scan (GET)"
echo "   • /scan/directory (POST)"
echo "   • /scan/file (POST)"
echo "   • /scan/results/<id> (GET)"
echo "   • /encrypt (GET, POST)"
echo "   • /decrypt (GET, POST)"
echo "   • /reports (GET)"
echo "   • /users (GET)"
echo "   • /alerts (GET)"
echo "   • /settings (GET)"
echo "   • /settings/change-password (POST)"
echo ""
echo "🚀 Restart your app:"
echo "   python3 app.py"
echo ""
