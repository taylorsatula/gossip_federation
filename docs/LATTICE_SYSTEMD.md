# Lattice Discovery Daemon systemd Service

This document describes how to set up the Lattice discovery daemon as a systemd service for production deployment.

## Quick Start

The easiest way to deploy is using the deploy script:

```bash
./deploy.sh
```

This handles secrets setup, identity generation, and systemd configuration automatically.

## Manual Setup

### Service File

The service file is at `deploy/lattice.service`. For manual installation:

```bash
sudo cp deploy/lattice.service /etc/systemd/system/lattice.service
sudo systemctl daemon-reload
```

### Secrets Configuration

Lattice uses file-based secrets at `/etc/lattice/`:

```bash
# Create secrets directory
sudo mkdir -p /etc/lattice
sudo chmod 700 /etc/lattice

# Create config file
sudo tee /etc/lattice/config.env > /dev/null <<EOF
APP_URL=https://your-server.com
LATTICE_BOOTSTRAP_SERVERS=https://lattice.miraos.org
EOF
sudo chmod 600 /etc/lattice/config.env
```

The private key is auto-generated on first run at `/etc/lattice/private_key.pem`.

### systemd Credentials (systemd 250+)

On modern systems, the deploy script automatically encrypts credentials:

```bash
# Manual encryption (optional)
sudo systemd-creds encrypt --name=private_key /etc/lattice/private_key.pem /etc/lattice/private_key.cred
sudo systemd-creds encrypt --name=config /etc/lattice/config.env /etc/lattice/config.cred
```

The service file uses `LoadCredentialEncrypted=` for encrypted credentials or `LoadCredential=` as fallback.

## Service Management

### Enable and Start

```bash
sudo systemctl enable lattice
sudo systemctl start lattice
```

### View Logs

```bash
# Follow logs in real-time
sudo journalctl -u lattice -f

# View last 100 lines
sudo journalctl -u lattice -n 100
```

### Control Service

```bash
sudo systemctl start lattice
sudo systemctl stop lattice
sudo systemctl restart lattice
sudo systemctl status lattice
```

## Troubleshooting

### Service won't start

```bash
# Check service status for errors
sudo systemctl status lattice

# Check recent logs
sudo journalctl -u lattice -n 50

# Test manually
python -m uvicorn lattice.discovery_daemon:app --port 1113
```

### Port 1113 already in use

```bash
sudo lsof -i :1113
```

### Credentials not loading

Verify files exist and have correct permissions:

```bash
ls -la /etc/lattice/
# Should show:
# -rw------- private_key.pem
# -rw------- config.env
```

## Integration with Main Application

The main application schedules periodic HTTP calls to the discovery daemon:

- **Gossip rounds**: `POST http://localhost:1113/api/v1/announce` (every 10 minutes)
- **Neighbor updates**: `POST http://localhost:1113/api/v1/maintenance/update_neighbors` (every 6 hours)
- **Cleanup**: `POST http://localhost:1113/api/v1/maintenance/cleanup` (daily)

These are registered automatically when the application starts (see `lattice/init_lattice.py`).

## Monitoring

### Health Check

```bash
curl http://localhost:1113/status
curl http://localhost:1113/health  # localhost only
```

### Service Metrics

```bash
systemctl status lattice
systemctl show lattice --property=MemoryCurrent,CPUUsage
```

## Security Best Practices

1. **Run as non-root user**: Service runs as dedicated `lattice` user
2. **Protect credentials**: Secret files have 600 permissions
3. **Use encrypted credentials**: On systemd 250+, credentials are encrypted at rest
4. **Filesystem restrictions**: Service has limited write access via `ProtectSystem=strict`
5. **Resource limits**: Memory and CPU limits prevent resource exhaustion

## Reverse Proxy Configuration (Nginx)

For external federation access:

```nginx
location /discovery/ {
    proxy_pass http://localhost:1113/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```
