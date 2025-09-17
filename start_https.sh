#!/bin/bash

echo "🚀 Starting Stegano with HTTPS..."
echo "=================================="

# Kill any existing processes on port 5050
lsof -ti:5050 | xargs kill -9 2>/dev/null || true

# Start the app
source .venv/bin/activate
python run_https.py





