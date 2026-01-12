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
