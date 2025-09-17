#!/bin/bash

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Generate SSL certificates
python generate_ssl.py

# Run the Flask app on port 8000
PORT=8000 python app.py
