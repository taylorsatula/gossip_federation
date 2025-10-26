# Gossip Federation

A decentralized federation protocol for cross-server messaging using gossip-based peer discovery.

## Overview

Gossip Federation enables servers to:
- Discover peers without central coordination
- Exchange messages across server boundaries
- Verify message authenticity with cryptographic signatures
- Handle network partitions gracefully

## Features

- **Decentralized Discovery**: No central servers or coordinators required
- **Cryptographic Security**: RSA-2048 signatures on all messages
- **Rate Limiting**: Built-in protection against message floods
- **Circuit Breakers**: Automatic failure detection and recovery
- **Production Ready**: Monitoring, health checks, and operational metrics

## Quick Start

### Installation

```bash
pip install gossip-federation
```

### Basic Usage

```python
from gossip_federation import FederationService

# Initialize service
service = FederationService(
    database_url="postgresql://user:pass@localhost/dbname",
    vault_url="https://vault.example.com",
    server_url="https://myserver.com"
)

# Start federation daemon
service.start()
```

### Sending Federated Messages

```python
from gossip_federation.client import FederationClient

client = FederationClient("http://localhost:8302")

# Send message to user on remote server
client.send_message(
    to_address="alice@remote-server.com",
    from_address="bob@myserver.com",
    content="Hello from another server!",
    content_type="text/plain"
)
```

## Architecture

The federation system consists of:

1. **Discovery Daemon**: HTTP service for gossip protocol and message routing
2. **Peer Manager**: Tracks known peers and connection health
3. **Gossip Protocol**: Exchanges peer information using epidemic algorithms
4. **Message Queue**: Reliable delivery with exponential backoff
5. **Domain Registry**: Optional custom domain registration

See [Architecture Documentation](docs/ARCHITECTURE.md) for details.

## Deployment

### Using Docker

```bash
docker run -d \
  -p 8302:8302 \
  -e DATABASE_URL=postgresql://... \
  -e VAULT_URL=https://... \
  gossip-federation:latest
```

### Using systemd

See [Systemd Setup](docs/FEDERATION_SYSTEMD.md) for production deployment.

## Configuration

Environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `VAULT_URL`: HashiCorp Vault server URL
- `VAULT_TOKEN`: Vault authentication token
- `FEDERATION_PORT`: Port for federation service (default: 8302)
- `GOSSIP_INTERVAL`: Seconds between gossip rounds (default: 3600)

## Security

- All messages are signed with RSA-2048 keys
- Private keys stored in HashiCorp Vault
- Automatic rate limiting per peer
- Prompt injection filtering on inbound content

See [Security Model](docs/SECURITY.md) for threat analysis.

## API Reference

### REST Endpoints

- `POST /api/v1/messages/send` - Queue outbound message
- `POST /api/v1/messages/receive` - Receive inbound message
- `GET /api/v1/peers` - List known peers
- `GET /api/v1/health` - Health status

### Python Client

See [API Documentation](docs/API.md) for complete reference.

## Development

```bash
# Clone repository
git clone https://github.com/taylorsatula/gossip-federation
cd gossip-federation

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Start development server
uvicorn gossip_federation.discovery_daemon:app --reload
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.