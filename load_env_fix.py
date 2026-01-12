import sys

print("🔧 Adding environment variable loading to app.py...")

with open('app.py', 'r') as f:
    content = f.read()

# Check if dotenv is already loaded
if 'load_dotenv' not in content:
    # Add at the top after imports
    env_code = '''
# Load environment variables
from dotenv import load_dotenv
load_dotenv()

'''
    
    # Find first import and add after it
    lines = content.split('\n')
    
    # Find the first import block
    import_end = 0
    for i, line in enumerate(lines):
        if line.startswith('import ') or line.startswith('from '):
            import_end = i
        elif import_end > 0 and not line.startswith('import ') and not line.startswith('from ') and line.strip():
            break
    
    # Insert env loading code
    lines.insert(import_end + 1, env_code)
    
    with open('app.py', 'w') as f:
        f.write('\n'.join(lines))
    
    print("✅ Environment loading added to app.py")
else:
    print("✅ Environment loading already configured")

print()
print("=" * 70)
print("Now run: python3 app.py")
print("=" * 70)

