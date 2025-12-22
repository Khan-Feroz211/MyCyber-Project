# Read the file
with open('app.py', 'r') as f:
    lines = f.readlines()

# Find and fix the get_next_user_id function
for i in range(len(lines)):
    if 'def get_next_user_id():' in lines[i]:
        # Fix the line - remove any trailing spaces after :
        lines[i] = 'def get_next_user_id():\n'
        break

# Write back
with open('app.py', 'w') as f:
    f.writelines(lines)

print("Fixed get_next_user_id definition")
