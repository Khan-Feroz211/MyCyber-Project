# Read the original backup
with open('app.py.bak', 'r') as f:
    content = f.read()

# Split into lines
lines = content.split('\n')

# Find and replace save_users
new_lines = []
i = 0
while i < len(lines):
    if lines[i].strip() == 'def save_users(users):':
        # Replace with fixed version
        new_lines.append('def save_users(users):')
        new_lines.append('    """Save users to JSON file - accepts either User objects or dictionaries"""')
        new_lines.append('    try:')
        new_lines.append('        # Ensure data directory exists')
        new_lines.append('        DATA_DIR.mkdir(exist_ok=True)')
        new_lines.append('        ')
        new_lines.append('        # Convert to dict format for saving')
        new_lines.append('        users_dict = {}')
        new_lines.append('        for user_id, user_data in users.items():')
        new_lines.append('            if hasattr(user_data, "to_dict"):')
        new_lines.append('                # It\'s a User object - convert to dictionary')
        new_lines.append('                users_dict[str(user_id)] = user_data.to_dict()')
        new_lines.append('            else:')
        new_lines.append('                # It\'s already a dictionary')
        new_lines.append('                users_dict[str(user_id)] = user_data')
        new_lines.append('        ')
        new_lines.append('        with open(USERS_FILE, "w") as f:')
        new_lines.append('            json.dump(users_dict, f, indent=2)')
        new_lines.append('        ')
        new_lines.append('        # Set secure permissions')
        new_lines.append('        set_file_permissions()')
        new_lines.append('        print(f"✅ Users saved to {USERS_FILE}")')
        new_lines.append('        return True')
        new_lines.append('    except Exception as e:')
        new_lines.append('        print(f"❌ Error saving users: {e}")')
        new_lines.append('        return False')
        # Skip original function
        i += 1
        while i < len(lines) and (lines[i].startswith(' ') or lines[i].strip() == ''):
            i += 1
    elif lines[i].strip() == 'def get_next_user_id():':
        # Replace with fixed version
        new_lines.append('def get_next_user_id():')
        new_lines.append('    """Get the next available user ID"""')
        new_lines.append('    users = load_users()')
        new_lines.append('    if users:')
        new_lines.append('        # Users are loaded as dictionaries with string keys')
        new_lines.append('        # Convert to integers to find the max')
        new_lines.append('        user_ids = [int(uid) for uid in users.keys() if uid.isdigit()]')
        new_lines.append('        if user_ids:')
        new_lines.append('            return max(user_ids) + 1')
        new_lines.append('    return 1')
        # Skip original function
        i += 1
        while i < len(lines) and (lines[i].startswith(' ') or lines[i].strip() == ''):
            i += 1
    else:
        new_lines.append(lines[i])
        i += 1

# Write the fixed file
with open('app.py.clean', 'w') as f:
    f.write('\n'.join(new_lines))

print("Created app.py.clean")
