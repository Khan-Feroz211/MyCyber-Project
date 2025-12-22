#!/usr/bin/env python3
"""
Test if registration works after fix
"""
import sys
import os
import json
sys.path.insert(0, '.')

print("=== TESTING FIXED REGISTRATION ===")

# Import
from app import load_users, save_new_user, User, get_next_user_id
from werkzeug.security import generate_password_hash

# 1. Initial state
print("1. Initial state:")
users_before = load_users()
print(f"   Users before: {len(users_before)}")

# 2. Create and save test user
print("\n2. Creating test user...")
try:
    next_id = get_next_user_id()
    test_user = User(
        id=next_id,
        username="test_fix_user",
        email="test_fix@example.com",
        role="user",
        password_hash=generate_password_hash("TestFix@123")
    )
    
    print(f"   User ID: {next_id}")
    print(f"   Username: test_fix_user")
    
    # Save
    save_new_user(test_user)
    print("   ✅ save_new_user() called")
    
    # 3. Verify
    print("\n3. Verification:")
    
    # Check file directly
    if os.path.exists('data/users.json'):
        with open('data/users.json', 'r') as f:
            file_data = json.load(f)
        
        print(f"   File has {len(file_data)} users")
        
        # Find our user
        user_found = False
        for uid, user_data in file_data.items():
            if isinstance(user_data, dict) and user_data.get('username') == 'test_fix_user':
                print(f"   ✅ Found in file: ID={uid}, username={user_data['username']}")
                user_found = True
                break
        
        if not user_found:
            print("   ❌ NOT found in file!")
            
            # Debug: show all users
            print("   File contents:")
            for uid, user_data in file_data.items():
                print(f"     {uid}: {type(user_data)} - {user_data}")
    
    # Check via load_users
    users_after = load_users()
    print(f"   load_users() returns: {len(users_after)} users")
    
    # Check if our user is in memory
    if next_id in users_after:
        print(f"   ✅ User in memory: {users_after[next_id].username}")
    else:
        print(f"   ❌ User NOT in memory")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n=== FIX SUMMARY ===")
print("Issue: save_new_user() was passing User objects to save_users()")
print("Fix: Convert User objects to dictionaries before saving")
print("This ensures proper JSON serialization")
