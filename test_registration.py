#!/usr/bin/env python3
"""
Test user registration and persistence
"""
import sys
import os
sys.path.insert(0, '.')

from app import load_users, save_users, users_db

print("=== Testing User Registration Issue ===")

# Load current users
users = load_users()
print(f"1. load_users() returns: {len(users)} users")
for uid, user in users.items():
    print(f"   - {user['username']} (id: {uid})")

print(f"\n2. Current users_db (in-memory): {len(users_db)} users")
for uid, user in users_db.items():
    print(f"   - {user.username} (id: {uid})")

# Check if they match
print(f"\n3. Match check: {'✅ MATCH' if len(users) == len(users_db) else '❌ MISMATCH'}")

# Test adding a new user
print("\n4. Testing if we can add a new user...")
try:
    from werkzeug.security import generate_password_hash
    from app import User, get_next_user_id, save_new_user
    
    new_id = get_next_user_id()
    print(f"   Next available ID: {new_id}")
    
    # This simulates what happens during registration
    new_user = User(
        id=new_id,
        username="test_user",
        email="test@example.com",
        role="user",
        password_hash=generate_password_hash("Test@123")
    )
    
    print(f"   Created user: {new_user.username}")
    
except Exception as e:
    print(f"   ❌ Error: {e}")
