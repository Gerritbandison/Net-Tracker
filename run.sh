#!/usr/bin/env bash
# NetMonDash — one-command launcher
# Usage: ./run.sh [options]
#   ./run.sh                  — start with defaults
#   ./run.sh -p 8080          — custom port
#   ./run.sh -i wlan0         — specific interface
#   ./run.sh --no-ai -v       — no AI, verbose logging
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$SCRIPT_DIR/netmondash"
VENV_DIR="$SCRIPT_DIR/venv"

# Auto-setup if venv doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "First run detected — running setup..."
    bash "$SCRIPT_DIR/setup.sh"
    echo ""
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Run from the app directory (so relative imports work)
cd "$APP_DIR"
exec python main.py "$@"
