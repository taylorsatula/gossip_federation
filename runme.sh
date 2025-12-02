#!/bin/bash
set -e

# Phase 1: Prerequisites
echo "Checking prerequisites..."

if [ "$EUID" -eq 0 ]; then
    echo "Error: Don't run as root"
    exit 1
fi

command -v python3 >/dev/null || { echo "Error: python3 not found"; exit 1; }
command -v git >/dev/null || { echo "Error: git not found"; exit 1; }
python3 -c "import venv" 2>/dev/null || { echo "Error: python3-venv not installed. Run: sudo apt install python3-venv"; exit 1; }

echo "Prerequisites OK"

# Phase 2: Get the Code
echo "Downloading Lattice..."

INSTALL_DIR="/opt/lattice"

if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/requirements.txt" ]; then
    echo "Lattice already exists at $INSTALL_DIR"
else
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami)" "$INSTALL_DIR"
    git clone --depth 1 https://github.com/taylorsatula/lattice.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
echo "Now in: $(pwd)"

# Phase 3: Python Environment
echo "Setting up Python environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

./venv/bin/pip install -q -r requirements.txt
echo "Dependencies installed"

# Phase 4: Configuration
echo ""
read -p "Enter your server URL (e.g., https://example.com): " APP_URL
if [ -z "$APP_URL" ]; then
    echo "Error: Server URL required"
    exit 1
fi

read -p "Bootstrap servers [https://lattice.miraos.org]: " BOOTSTRAP
BOOTSTRAP="${BOOTSTRAP:-https://lattice.miraos.org}"

sudo mkdir -p /etc/lattice
sudo chown -R "$(whoami)" /etc/lattice
cat > /etc/lattice/config.env <<EOF
APP_URL=$APP_URL
LATTICE_BOOTSTRAP_SERVERS=$BOOTSTRAP
EOF
chmod 600 /etc/lattice/config.env
echo "Config written to /etc/lattice/config.env"

# Phase 5: Identity
echo "Initializing Lattice identity..."

./venv/bin/python3 -c "
from lattice.init_lattice import ensure_lattice_identity
result = ensure_lattice_identity()
print(f\"Server ID: {result['server_id']}\")
print(f\"UUID: {result['server_uuid']}\")
"

# Phase 6: Systemd
echo "Setting up systemd service..."

sudo tee /etc/systemd/system/lattice.service > /dev/null <<EOF
[Unit]
Description=Lattice Discovery Daemon
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/uvicorn lattice.discovery_daemon:app --host 0.0.0.0 --port 1113
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable lattice
sudo systemctl start lattice

# Phase 7: Verify
echo "Waiting for service to start..."
sleep 3

if curl -s http://localhost:1113/status >/dev/null; then
    echo "SUCCESS: Lattice is running"
    curl -s http://localhost:1113/status
else
    echo "Warning: Service may not be running. Check: journalctl -u lattice -n 20"
fi

echo ""
echo "Done. Manage with: sudo systemctl {start|stop|status} lattice"
