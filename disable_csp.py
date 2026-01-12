import re
print("🔧 Disabling strict CSP...")

with open('app.py', 'r') as f:
    content = f.read()

# Remove all CSP headers
content = re.sub(r"response\.headers\['Content-Security-Policy'\][^\n]*", 
                 "# CSP disabled for development", content)
content = re.sub(r"response\.headers\['Clear-Site-Data'\][^\n]*", 
                 "# Clear-Site-Data disabled", content)

# Add permissive CSP
if '@app.after_request' not in content:
    after_req = '''
@app.after_request
def set_headers(response):
    """Set permissive headers for development"""
    response.headers.pop('Content-Security-Policy', None)
    response.headers.pop('Clear-Site-Data', None)
    return response

'''
    content = content.replace("if __name__ == '__main__':", after_req + "if __name__ == '__main__':")
else:
    # Find after_request and modify it
    content = re.sub(
        r"(@app\.after_request\s+def\s+\w+\([^)]*\):.*?return response)",
        r"@app.after_request\ndef set_headers(response):\n    response.headers.pop('Content-Security-Policy', None)\n    response.headers.pop('Clear-Site-Data', None)\n    return response",
        content,
        flags=re.DOTALL
    )

with open('app.py', 'w') as f:
    f.write(content)

print("✅ CSP disabled!")
print()
print("Restart app now: python3 app.py")
