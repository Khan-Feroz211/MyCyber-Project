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
