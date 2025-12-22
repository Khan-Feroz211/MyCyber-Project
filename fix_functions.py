# Fix for the save_users, get_next_user_id, and save_new_user functions

def save_users(users):
    """Save users to JSON file - accepts either User objects or dictionaries"""
    try:
        # Ensure data directory exists
        DATA_DIR.mkdir(exist_ok=True)
        
        # Convert to dict format for saving
        users_dict = {}
        for user_id, user_data in users.items():
            if hasattr(user_data, 'to_dict'):
                # It's a User object - convert to dictionary
                users_dict[str(user_id)] = user_data.to_dict()
            else:
                # It's already a dictionary
                users_dict[str(user_id)] = user_data
        
        with open(USERS_FILE, 'w') as f:
            json.dump(users_dict, f, indent=2)
        
        # Set secure permissions
        set_file_permissions()
        print(f"✅ Users saved to {USERS_FILE}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving users: {e}")
        return False


def get_next_user_id():
    """Get the next available user ID"""
    users = load_users()
    if users:
        # Users are loaded as dictionaries with string keys
        # Convert to integers to find the max
        user_ids = [int(uid) for uid in users.keys() if uid.isdigit()]
        if user_ids:
            return max(user_ids) + 1
    return 1


def save_new_user(user):
    """Save a new user to the database"""
    try:
        users = load_users()
        
        # Convert User object to dictionary for saving
        user_dict = user.to_dict()
        user_id = str(user.id)
        
        # Add to users dictionary
        users[user_id] = user_dict
        
        # Save using save_users (which now accepts dictionaries)
        if save_users(users):
            print(f"✅ New user '{user.username}' saved with ID: {user_id}")
            return True
        else:
            print(f"❌ Failed to save user '{user.username}'")
            return False
            
    except Exception as e:
        print(f"❌ Error in save_new_user: {e}")
        import traceback
        traceback.print_exc()
        return False
