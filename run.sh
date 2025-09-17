#!/bin/bash

# Simple launcher script for the Steganography Flask Application
# This script handles everything: environment setup, dependencies, SSL, and launching

echo "🚀 Starting Steganography Flask Application..."
echo "=================================================="

# Make sure we're in the right directory
cd "$(dirname "$0")"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found. Please install Python 3."
    exit 1
fi

# Run the Python launcher
python3 start_app.py
