#!/usr/bin/env python3
"""
Find where User objects are accessed as dictionaries
"""
import re

with open('app.py', 'r') as f:
    lines = f.readlines()

print("Lines with potential dictionary access on user objects:")
print("=" * 60)

for i, line in enumerate(lines, 1):
    # Look for patterns like user['something'] or user.get('something')
    if re.search(r'user\[["\']|user\.get\(["\']', line):
        print(f"Line {i}: {line.rstrip()}")
        
        # Show context
        start = max(0, i-3)
        end = min(len(lines), i+2)
        print("Context:")
        for j in range(start, end):
            print(f"  {j}: {lines[j-1].rstrip()}")
        print("-" * 40)

print("\n" + "=" * 60)
print("These need to be changed from user['key'] to user.key")
