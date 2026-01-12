import re
import shutil
from datetime import datetime

print("🔧 Fixing Content Security Policy...")

# Backup
backup = f'app.py.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
shutil.copy('app.py', backup)
print(f"✅ Backup: {backup}")

with open('app.py', 'r') as f:
    content = f.read()

# Find CSP configuration
if "Content-Security-Policy" in content:
    print("✅ Found CSP headers")
    
    # Replace strict CSP with permissive one
    old_csp = r"response\.headers\['Content-Security-Policy'\]\s*=\s*['\"].*?['\"]"
    new_csp = '''response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self'"
    )'''
    
    content = re.sub(old_csp, new_csp, content, flags=re.DOTALL)
    
    with open('app.py', 'w') as f:
        f.write(content)
    print("✅ CSP headers updated!")
else:
    print("⚠️  No CSP found - will add after_request handler")
    
    # Add CSP configuration
    after_request = '''
@app.after_request
def add_security_headers(response):
    """Add security headers"""
    # Permissive CSP for CDN resources
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Remove problematic Clear-Site-Data header
    response.headers.pop('Clear-Site-Data', None)
    
    return response

'''
    
    # Add before if __name__
    if "if __name__ == '__main__':" in content:
        content = content.replace("if __name__ == '__main__':", after_request + "\nif __name__ == '__main__':")
        with open('app.py', 'w') as f:
            f.write(content)
        print("✅ Security headers added!")

print()
print("=" * 70)
print("🎯 IMPORTANT: Clear browser cache!")
print("=" * 70)
print()
print("1. Press Ctrl+Shift+Delete in browser")
print("2. Select 'Cached images and files'")
print("3. Click 'Clear data'")
print()
print("OR use Incognito/Private mode:")
print("   Ctrl+Shift+N (Chrome)")
print("   Ctrl+Shift+P (Firefox)")
print()
print("Then:")
print("1. Restart app: python3 app.py")
print("2. Go to: http://localhost:5001/login")
print("3. Login: admin / admin123")
print()

