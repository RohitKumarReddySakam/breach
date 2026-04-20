#!/bin/bash
set -e
echo "=== BREACH Setup ==="
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
mkdir -p reports instance
cp .env.example .env 2>/dev/null || true
echo "Setup complete. Start with: python app.py"
echo "WARNING: For authorized use only. Obtain written permission before scanning."
