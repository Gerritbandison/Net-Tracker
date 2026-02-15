#!/usr/bin/env bash
# NetMonDash — one-command setup
# Usage: ./setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$SCRIPT_DIR/netmondash"
VENV_DIR="$SCRIPT_DIR/venv"

echo "═══════════════════════════════════════════════"
echo "  NetMonDash Setup"
echo "═══════════════════════════════════════════════"

# Check Python version
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=$("$cmd" -c 'import sys; print(sys.version_info.major)')
        minor=$("$cmd" -c 'import sys; print(sys.version_info.minor)')
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.10+ is required."
    echo "Install it with: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi
echo "[1/4] Using $PYTHON ($ver)"

# Create venv
if [ ! -d "$VENV_DIR" ]; then
    echo "[2/4] Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
else
    echo "[2/4] Virtual environment already exists"
fi

# Activate and install
echo "[3/4] Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel -q
pip install -r "$APP_DIR/requirements.txt" -q

# Check nmap (optional)
echo "[4/4] Checking optional dependencies..."
if command -v nmap &>/dev/null; then
    echo "  nmap: found (deep scans enabled)"
else
    echo "  nmap: not found (install with: sudo apt install nmap)"
    echo "         ARP-based discovery will still work without it."
fi

echo ""
echo "═══════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Start the dashboard:"
echo "    ./run.sh"
echo ""
echo "  Or manually:"
echo "    source venv/bin/activate"
echo "    cd netmondash && python main.py"
echo ""
echo "  Dashboard URL: http://localhost:5000"
echo "═══════════════════════════════════════════════"
