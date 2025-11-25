# Federation Discovery Daemon systemd Service

This document describes how to set up the federation discovery daemon as a systemd service for production deployment.

## Service File

Create `/etc/systemd/system/mira-federation-discovery.service`:

```ini
[Unit]
Description=MIRA Federation Discovery Daemon
Documentation=https://github.com/yourorg/botwithmemory
After=network.target postgresql.service vault.service
Wants=postgresql.service

[Service]
Type=simple
User=mira
Group=mira
WorkingDirectory=/opt/mira

# Environment variables
Environment="PYTHONUNBUFFERED=1"
Environment="VAULT_ADDR=http://localhost:8200"
EnvironmentFile=/etc/mira/federation.env

# Start discovery daemon on port 8302
ExecStart=/opt/mira/venv/bin/python -m uvicorn \
    federation.discovery_daemon:app \
    --host 0.0.0.0 \
    --port 8302 \
    --log-level info

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/mira/data
ReadOnlyPaths=/opt/mira

# Resource limits
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

## Environment File

Create `/etc/mira/federation.env`:

```bash
# Vault configuration (AppRole authentication)
VAULT_ADDR=http://localhost:8200
VAULT_ROLE_ID=your-role-id-here
VAULT_SECRET_ID=your-secret-id-here

# Optional: Vault namespace (for Vault Enterprise)
# VAULT_NAMESPACE=mira
```

**Security Note:** This file contains sensitive credentials. Protect it:
```bash
sudo chown root:mira /etc/mira/federation.env
sudo chmod 640 /etc/mira/federation.env
```

## Installation Steps

### 1. Create Service User

```bash
# Create mira system user if it doesn't exist
sudo useradd --system --no-create-home --shell /bin/false mira

# Create necessary directories
sudo mkdir -p /opt/mira/data
sudo chown -R mira:mira /opt/mira/data
```

### 2. Install Service File

```bash
# Copy service file
sudo cp /path/to/mira-federation-discovery.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

### 3. Configure Environment

```bash
# Create config directory
sudo mkdir -p /etc/mira

# Create environment file with your credentials
sudo nano /etc/mira/federation.env

# Set permissions
sudo chown root:mira /etc/mira/federation.env
sudo chmod 640 /etc/mira/federation.env
```

### 4. Enable and Start Service

```bash
# Enable service to start on boot
sudo systemctl enable mira-federation-discovery

# Start service
sudo systemctl start mira-federation-discovery

# Check status
sudo systemctl status mira-federation-discovery
```

## Service Management

### View Logs

```bash
# Follow logs in real-time
sudo journalctl -u mira-federation-discovery -f

# View last 100 lines
sudo journalctl -u mira-federation-discovery -n 100

# View logs since boot
sudo journalctl -u mira-federation-discovery -b
```

### Control Service

```bash
# Start service
sudo systemctl start mira-federation-discovery

# Stop service
sudo systemctl stop mira-federation-discovery

# Restart service
sudo systemctl restart mira-federation-discovery

# Reload configuration (if supported)
sudo systemctl reload mira-federation-discovery

# Check status
sudo systemctl status mira-federation-discovery
```

### Troubleshooting

#### Service won't start

```bash
# Check service status for errors
sudo systemctl status mira-federation-discovery

# Check recent logs
sudo journalctl -u mira-federation-discovery -n 50

# Verify environment file
sudo cat /etc/mira/federation.env

# Test manually as mira user
sudo -u mira /opt/mira/venv/bin/python -m uvicorn federation.discovery_daemon:app --port 8302
```

#### Can't connect to Vault

```bash
# Verify Vault is running
sudo systemctl status vault

# Test Vault connection
vault status

# Check environment variables
sudo systemctl show mira-federation-discovery | grep Environment
```

#### Port 8302 already in use

```bash
# Check what's using the port
sudo lsof -i :8302

# Or use netstat
sudo netstat -tlnp | grep 8302
```

## Integration with Main MIRA

The main MIRA application (port 1993) schedules periodic HTTP calls to the discovery daemon:

- **Gossip rounds**: `POST http://localhost:8302/api/v1/announce` (every 10 minutes)
- **Neighbor updates**: `POST http://localhost:8302/api/v1/maintenance/update_neighbors` (every 6 hours)
- **Cleanup**: `POST http://localhost:8302/api/v1/maintenance/cleanup` (daily)

These are registered automatically when MIRA starts (see `federation/init_federation.py`).

## Monitoring

### Health Check

```bash
# Check if daemon is responding
curl http://localhost:8302/api/v1/peers

# Expected: JSON list of peer servers
```

### Service Metrics

```bash
# View service resource usage
systemctl status mira-federation-discovery

# Detailed resource stats
systemctl show mira-federation-discovery --property=MemoryCurrent,CPUUsage
```

## Security Best Practices

1. **Run as non-root user**: Service runs as `mira` user with limited permissions
2. **Protect credentials**: Environment file is only readable by `root` and `mira` group
3. **Filesystem restrictions**: Service has read-only access to application code
4. **Network binding**: Only binds to localhost (use reverse proxy for external access)
5. **Resource limits**: Memory and CPU limits prevent resource exhaustion
6. **Restart policy**: Automatic restart on failure with backoff

## Reverse Proxy Configuration (Nginx)

For external federation access, configure nginx:

```nginx
# Federation discovery daemon (port 8302)
location /discovery/ {
    proxy_pass http://localhost:8302/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Timeout settings for long-polling if needed
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

Then reload nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Upgrading

When deploying new versions:

```bash
# Stop service
sudo systemctl stop mira-federation-discovery

# Update code
cd /opt/mira
sudo -u mira git pull

# Restart service
sudo systemctl start mira-federation-discovery

# Verify
sudo systemctl status mira-federation-discovery
```

## Uninstallation

To remove the service:

```bash
# Stop and disable
sudo systemctl stop mira-federation-discovery
sudo systemctl disable mira-federation-discovery

# Remove service file
sudo rm /etc/systemd/system/mira-federation-discovery.service

# Reload systemd
sudo systemctl daemon-reload
```
