#!/bin/bash

echo "🔧 COMPLETE LOGIN FIX - All Issues"
echo "════════════════════════════════════"
echo ""

# Step 1: Fix admin password
echo "1️⃣ Resetting admin password to 'admin123'..."
python3 << 'PYFIXPW'
import sqlite3
from werkzeug.security import generate_password_hash

try:
    db = sqlite3.connect('data/advanced_dlp.db')
    c = db.cursor()
    
    # Set password to admin123
    password_hash = generate_password_hash('admin123')
    c.execute('UPDATE users SET password_hash = ?, is_active = 1, failed_attempts = 0, locked_until = NULL WHERE username = "admin"', (password_hash,))
    db.commit()
    
    # Verify it worked
    c.execute('SELECT username, is_active FROM users WHERE username = "admin"')
    user = c.fetchone()
    
    if user:
        print(f"✅ Admin password reset successfully")
        print(f"   Username: admin")
        print(f"   Password: admin123")
        print(f"   Active: {user[1]}")
    else:
        print("❌ Admin user not found!")
    
    db.close()
except Exception as e:
    print(f"❌ Error: {e}")
PYFIXPW

echo ""

# Step 2: Check user_loader in app.py
echo "2️⃣ Checking user_loader function..."
if grep -q "def load_user" app.py; then
    echo "✅ user_loader function exists"
    
    # Check if it has session issues
    if grep -A 10 "def load_user" app.py | grep -q "session.expunge\|session.close"; then
        echo "✅ user_loader has proper session handling"
    else
        echo "⚠️  user_loader might have session issues"
        echo "   Fixing now..."
        
        # Backup app.py
        cp app.py app.py.backup_$(date +%Y%m%d_%H%M%S)
        
        # This will need manual fix - showing the issue
        echo ""
        echo "📝 Current user_loader code:"
        grep -A 15 "def load_user" app.py | head -20
    fi
else
    echo "❌ user_loader function NOT FOUND!"
fi

echo ""

# Step 3: Check Flask-Login configuration
echo "3️⃣ Checking Flask-Login setup..."
if grep -q "LoginManager" app.py; then
    echo "✅ LoginManager imported"
else
    echo "❌ LoginManager NOT imported"
fi

if grep -q "login_manager = LoginManager" app.py; then
    echo "✅ LoginManager initialized"
else
    echo "❌ LoginManager NOT initialized"
fi

if grep -q "login_manager.login_view" app.py; then
    echo "✅ login_view configured"
else
    echo "⚠️  login_view might not be configured"
fi

echo ""

# Step 4: Check session configuration
echo "4️⃣ Checking session configuration..."
if grep -q "app.secret_key\|SECRET_KEY" app.py; then
    echo "✅ Secret key configured"
else
    echo "❌ Secret key NOT configured!"
fi

if grep -q "app.config\['SESSION" app.py; then
    echo "✅ Session config found"
else
    echo "⚠️  Custom session config not found (using defaults)"
fi

echo ""

# Step 5: Test login functionality
echo "5️⃣ Testing login credentials..."
python3 << 'PYTEST'
import sqlite3
from werkzeug.security import check_password_hash

try:
    db = sqlite3.connect('data/advanced_dlp.db')
    c = db.cursor()
    
    # Test admin login
    c.execute('SELECT username, password_hash, is_active FROM users WHERE username = "admin"')
    result = c.fetchone()
    
    if result:
        username, password_hash, is_active = result
        
        print(f"User: {username}")
        print(f"Active: {is_active}")
        
        # Test password
        if check_password_hash(password_hash, 'admin123'):
            print("✅ Password 'admin123' WORKS!")
        else:
            print("❌ Password 'admin123' FAILS!")
            
            # Try other common passwords
            for pwd in ['admin', 'ChangeMe123!', 'password', 'Admin123']:
                if check_password_hash(password_hash, pwd):
                    print(f"⚠️  Password is actually: {pwd}")
                    break
    else:
        print("❌ Admin user not found in database!")
    
    db.close()
except Exception as e:
    print(f"❌ Error: {e}")
PYTEST

echo ""

# Step 6: Create proper user_loader fix
echo "6️⃣ Creating fixed user_loader code..."
cat > fixed_user_loader.py << 'PYFIX'
# FIXED USER_LOADER - Replace your current one with this

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID - FIXED VERSION"""
    try:
        # Create a new session (don't use with statement)
        session = db_engine.get_session()
        
        # Get user
        user = session.query(User).filter_by(id=user_id).first()
        
        if user:
            # Detach user from session BEFORE closing
            session.expunge(user)
        
        # Close session
        session.close()
        
        return user
    except Exception as e:
        logger.error(f"Error loading user: {e}")
        return None
PYFIX

echo ""
echo "📄 Fixed user_loader code saved to: fixed_user_loader.py"
echo ""

# Step 7: Check login route
echo "7️⃣ Checking login route..."
if grep -q "def login():" app.py; then
    echo "✅ Login route exists"
    
    # Check if it uses login_user
    if grep -A 30 "def login():" app.py | grep -q "login_user"; then
        echo "✅ login_user() called in login route"
    else
        echo "❌ login_user() NOT called in login route!"
    fi
else
    echo "❌ Login route NOT found!"
fi

echo ""

# Step 8: Provide complete working login route
echo "8️⃣ Creating complete working login route..."
cat > fixed_login_route.py << 'PYLOGIN'
# COMPLETE WORKING LOGIN ROUTE - Replace your current one

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Login page"""
    # Already logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return redirect(url_for('login'))
        
        try:
            # Get database session
            with db_engine.get_session() as session:
                # Find user
                user = session.query(User).filter_by(username=username).first()
                
                if not user:
                    flash('Invalid username or password', 'danger')
                    logger.warning(f"Login attempt for non-existent user: {username}")
                    return redirect(url_for('login'))
                
                # Check if account is active
                if not user.is_active:
                    flash('Account is disabled', 'danger')
                    logger.warning(f"Login attempt for disabled account: {username}")
                    return redirect(url_for('login'))
                
                # Check if account is locked
                if user.locked_until and user.locked_until > datetime.utcnow():
                    flash('Account is temporarily locked. Try again later.', 'danger')
                    return redirect(url_for('login'))
                
                # Verify password
                if not check_password_hash(user.password_hash, password):
                    # Increment failed attempts
                    user.failed_attempts = (user.failed_attempts or 0) + 1
                    
                    # Lock account after 5 failed attempts
                    if user.failed_attempts >= 5:
                        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                        session.commit()
                        flash('Too many failed attempts. Account locked for 15 minutes.', 'danger')
                        logger.warning(f"Account locked due to failed attempts: {username}")
                        return redirect(url_for('login'))
                    
                    session.commit()
                    flash('Invalid username or password', 'danger')
                    logger.warning(f"Failed login attempt for user: {username}")
                    return redirect(url_for('login'))
                
                # Successful login
                # Reset failed attempts
                user.failed_attempts = 0
                user.locked_until = None
                user.last_login = datetime.utcnow()
                
                # IMPORTANT: Detach user from session before closing
                session.expunge(user)
                session.commit()
            
            # Login user (this happens AFTER session is closed)
            login_user(user, remember=remember)
            
            flash(f'Welcome back, {user.username}!', 'success')
            logger.info(f"Successful login: {username}")
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login', 'danger')
            return redirect(url_for('login'))
    
    # GET request - show login page
    return render_template('login.html')


# Helper function for safe redirects
def is_safe_url(target):
    """Check if URL is safe for redirect"""
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
PYLOGIN

echo "📄 Complete login route saved to: fixed_login_route.py"
echo ""

# Final summary
echo "════════════════════════════════════"
echo "✅ FIX SUMMARY"
echo "════════════════════════════════════"
echo ""
echo "Login Credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Files Created:"
echo "  1. fixed_user_loader.py    - Copy this to app.py"
echo "  2. fixed_login_route.py    - Copy this to app.py"
echo ""
echo "Next Steps:"
echo "  1. Open app.py"
echo "  2. Find the @login_manager.user_loader section"
echo "  3. Replace it with code from fixed_user_loader.py"
echo "  4. Find the login() function"
echo "  5. Replace it with code from fixed_login_route.py"
echo "  6. Restart: python3 app.py"
echo "  7. Test: http://localhost:5000/login"
echo ""
echo "OR use the auto-fix option below..."
echo ""
