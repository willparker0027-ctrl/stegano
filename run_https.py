#!/usr/bin/env python3
"""
Run Stegano app with HTTPS support
"""
import os
import sys

def main():
    # Set port
    port = os.environ.get('PORT', '5050')
    
    # Check if certificates exist
    if not (os.path.exists('certs/cert.pem') and os.path.exists('certs/key.pem')):
        print("❌ SSL certificates not found!")
        print("🔧 Run: python generate_ssl.py")
        sys.exit(1)
    
    # Set environment variables
    os.environ['PORT'] = port
    
    # Import and run the app
    from app import app
    
    print("🚀 Starting Stegano with HTTPS...")
    print("=" * 50)
    print(f"🔒 HTTPS Server: https://localhost:{port}")
    print(f"🌐 Network: https://192.168.1.41:{port}")
    print("=" * 50)
    print("⚠️  Note: Browser will show security warning for self-signed certificate")
    print("   Click 'Advanced' → 'Proceed to localhost' to continue")
    print("=" * 50)
    
    # Run with SSL context
    ssl_context = ('certs/cert.pem', 'certs/key.pem')
    app.run(host='0.0.0.0', port=int(port), debug=True, ssl_context=ssl_context)

if __name__ == '__main__':
    main()


