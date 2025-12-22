#!/usr/bin/env python3
"""
Apply the correct fix for save_new_user
"""
import re

with open('app.py', 'r') as f:
    content = f.read()

# Find the save_new_user function
pattern = r'(def save_new_user\(user\):\s*""".*?"""\s*users = load_users\(\)\s*users\[user\.id\] = user\s*)save_users\(users\)'

if re.search(pattern, content, re.DOTALL):
    print("Found the problematic save_new_user function")
    
    # Replace with fixed version
    replacement = r'''def save_new_user(user):
    """Save a new user to the database"""
    users = load_users()
    users[user.id] = user
    
    # Convert User objects to dictionaries for saving
    users_dict = {}
    for uid, user_obj in users.items():
        users_dict[uid] = {
            'id': user_obj.id,
            'username': user_obj.username,
            'email': user_obj.email,
            'role': user_obj.role,
            'password_hash': user_obj.password_hash
        }
    save_users(users_dict)  # Save dictionaries, not objects
'''
    
    # Use simpler replacement
    fixed_content = re.sub(
        r'def save_new_user\(user\):\s*""".*?"""\s*users = load_users\(\)\s*users\[user\.id\] = user\s*save_users\(users\)',
        replacement,
        content,
        flags=re.DOTALL
    )
    
    # Backup and save
    with open('app.py.backup_before_fix', 'w') as f:
        f.write(content)
    
    with open('app.py', 'w') as f:
        f.write(fixed_content)
    
    print("✅ Fixed save_new_user() function")
    print("📁 Backup saved as: app.py.backup_before_fix")
    
else:
    print("Pattern not found. Let me check the current function...")
    
    # Show current function
    match = re.search(r'def save_new_user\(user\):.*?def ', content, re.DOTALL)
    if match:
        print("Current save_new_user function:")
        print(match.group(0)[:500])
