#!/usr/bin/env python3
"""
Production-ready launcher for the Steganography Flask Application
Handles SSL certificates, port management, and provides clear instructions
"""
import os
import sys
import subprocess
import socket
import time
from pathlib import Path

def check_port_available(port):
    """Check if a port is available"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', port))
            return True
        except OSError:
            return False

def kill_existing_processes():
    """Kill any existing Flask processes"""
    try:
        subprocess.run(['pkill', '-f', 'python.*app.py'], check=False)
        time.sleep(1)  # Give processes time to terminate
    except Exception:
        pass

def setup_environment():
    """Set up virtual environment and install dependencies"""
    venv_path = Path('.venv')
    
    if not venv_path.exists():
        print("📦 Creating virtual environment...")
        subprocess.run([sys.executable, '-m', 'venv', '.venv'], check=True)
    
    # Determine the correct python executable in venv
    if os.name == 'nt':  # Windows
        python_exe = venv_path / 'Scripts' / 'python.exe'
        pip_exe = venv_path / 'Scripts' / 'pip.exe'
    else:  # Unix/Linux/macOS
        python_exe = venv_path / 'bin' / 'python'
        pip_exe = venv_path / 'bin' / 'pip'
    
    print("📦 Installing dependencies...")
    subprocess.run([str(pip_exe), 'install', '-r', 'requirements.txt'], check=True)
    
    return str(python_exe)

def generate_ssl_certificates():
    """Generate SSL certificates if they don't exist"""
    cert_dir = Path('certs')
    cert_file = cert_dir / 'cert.pem'
    key_file = cert_dir / 'key.pem'
    
    if not cert_file.exists() or not key_file.exists():
        print("🔒 Generating SSL certificates...")
        subprocess.run([sys.executable, 'generate_ssl.py'], check=True)
    else:
        print("✅ SSL certificates already exist")

def find_available_port():
    """Find an available port starting from 5000"""
    preferred_ports = [5000, 8000, 3000, 4000, 9000, 8888, 9999]
    
    for port in preferred_ports:
        if check_port_available(port):
            return port
    
    # If none of the preferred ports are available, find any available port
    for port in range(5001, 6000):
        if check_port_available(port):
            return port
    
    raise RuntimeError("No available ports found")

def main():
    """Main launcher function"""
    print("🚀 Starting Steganography Flask Application...")
    print("=" * 50)
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    try:
        # Step 1: Clean up any existing processes
        print("🧹 Cleaning up existing processes...")
        kill_existing_processes()
        
        # Step 2: Set up environment
        python_exe = setup_environment()
        
        # Step 3: Generate SSL certificates
        generate_ssl_certificates()
        
        # Step 4: Find available port
        port = find_available_port()
        print(f"🔍 Using port: {port}")
        
        # Step 5: Start the application
        print("🔒 Starting Flask application with HTTPS...")
        print("=" * 50)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        # Start the Flask app
        process = subprocess.run([python_exe, 'app.py'], env=env, check=False)
        
        if process.returncode != 0:
            print(f"❌ Application failed to start (exit code: {process.returncode})")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
