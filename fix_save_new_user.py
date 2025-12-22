#!/usr/bin/env python3
"""
Fix save_new_user() to convert User objects to dictionaries
"""
import re

with open('app.py', 'r') as f:
    lines = f.readlines()

# Find save_new_user function
for i, line in enumerate(lines):
    if 'def save_new_user' in line:
        print(f"Found save_new_user at line {i+1}")
        
        # Look for the save_users(users) line
        for j in range(i, i+10):
            if 'save_users(users)' in lines[j]:
                print(f"Found save_users call at line {j+1}")
                
                # Check if we need to convert to dict
                # We need to see if users contains User objects or dicts
                
                # Read the current function
                func_start = i
                func_end = i + 1
                while func_end < len(lines) and not lines[func_end].startswith('def '):
                    func_end += 1
                
                func_lines = lines[func_start:func_end]
                func_text = ''.join(func_lines)
                
                # Check if we're passing User objects
                if 'User(' in func_text and not 'to_dict' in func_text:
                    print("⚠️  Issue found: Passing User objects to save_users()")
                    print("   Need to convert to dictionaries")
                    
                    # Create fixed version
                    fixed_func = []
                    for k, func_line in enumerate(func_lines):
                        if 'save_users(users)' in func_line:
                            # Insert conversion before save
                            fixed_func.append('    # Convert User objects to dictionaries for saving\n')
                            fixed_func.append('    users_dict = {}\n')
                            fixed_func.append('    for uid, user_obj in users.items():\n')
                            fixed_func.append('        users_dict[uid] = {\n')
                            fixed_func.append("            'id': user_obj.id,\n")
                            fixed_func.append("            'username': user_obj.username,\n")
                            fixed_func.append("            'email': user_obj.email,\n")
                            fixed_func.append("            'role': user_obj.role,\n")
                            fixed_func.append("            'password_hash': user_obj.password_hash\n")
                            fixed_func.append('        }\n')
                            fixed_func.append('    save_users(users_dict)  # Save dictionaries, not objects\n')
                        else:
                            fixed_func.append(func_line)
                    
                    # Replace the function
                    lines[func_start:func_end] = fixed_func
                    print("✅ Applied fix: Convert User objects to dictionaries")
                    break
                else:
                    print("✅ Already converts to dictionaries")
                break
        break

# Write fixed file
with open('app.py.fixed', 'w') as f:
    f.writelines(lines)

print("\n=== COMPARISON ===")
print("Original save_new_user() lines 316-321:")
print("".join(lines[315:322] if len(lines) > 322 else "Can't display"))

print("\nFixed version saved to: app.py.fixed")
print("To apply: mv app.py.fixed app.py")
