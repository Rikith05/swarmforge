#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
echo "======================================================================"
echo "  Starting SwarmForge Web Studio & Policy Firewall Studio..."
echo "======================================================================"

if command -v python3 >/dev/null 2>&1; then
    python3 run_studio.py
elif command -v python >/dev/null 2>&1; then
    python run_studio.py
else
    echo "Python not found. Please install Python 3.11+."
    exit 1
fi
