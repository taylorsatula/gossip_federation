# Lattice

A decentralized peer-to-peer protocol for cross-server messaging without a central coordinator.

Primarily developed to allow [taylorsatula/mira-OSS]([docs/ARCHITECTURE.md](https://github.com/taylorsatula/mira-OSS)) instances to communicate in airgapped systems and after the root servers at [miraos.org](https://miraos.org) are shut down someday in the far-future.

## Overview

Lattice allows servers to discover each other and exchange messages across server boundaries. Users can send messages to `user@remote-server` just like email, but for real-time messaging.

**Key Properties:**
- **Decentralized**: No central registry or coordinator
- **Cryptographically Secure**: All messages signed with RSA-2048
- **Resilient**: Gossip protocol ensures eventual consistency
- **Spam-Resistant**: Rate limiting, circuit breakers, trust levels

---

## Quick Start

### Installation

```bash
pip install -e .
```

### Start the Discovery Daemon

```bash
# Database schema is automatically created on first run
# Default SQLite database: lattice.db (configure with LATTICE_DB_PATH env var)

# Start daemon
uvicorn lattice.discovery_daemon:app --host 0.0.0.0 --port 1113
```


### REST Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/v1/identity` | Get server federation identity |
| `GET /api/v1/peers` | List known peers |
| `POST /api/v1/announce` | Trigger gossip round |
| `POST /api/v1/gossip/receive` | Receive announcements |
| `POST /api/v1/route/{domain}` | Resolve domain to endpoint |

### Integration with External Systems

External systems (like MIRA) must configure the username resolver before federated message delivery works:

```python
from lattice.username_resolver import set_username_resolver

def resolve_username(username: str) -> Optional[str]:
    # Query your user database for username -> user_id mapping
    result = your_db.query("SELECT user_id FROM users WHERE username = ?", username)
    return str(result.user_id) if result else None

# Call at application startup
set_username_resolver(resolve_username)
```

---

## Core Concepts

### Identity

Each Lattice server has a permanent identity:

```
server_id:   "acme-corp"              # Human-readable domain name
server_uuid: "550e8400-e29b-41d4..."  # Permanent UUID (survives renames)
public_key:  "-----BEGIN PUBLIC..."   # RSA-2048 public key
fingerprint: "A1B2C3D4E5F6..."        # SHA-256 of public key (first 32 hex chars)
```

The `server_uuid` is the true identity. If a server renames from `acme-corp` to `acme-global`, the UUID stays the same, and peers update their records accordingly.

### Peers vs Neighbors

**Peers**: All servers we know about (could be thousands)
**Neighbors**: Subset of peers we actively gossip with (max 8)

```
┌─────────────────────────────────────────┐
│              All Known Peers            │
│  ┌───────────────────────────────────┐  │
│  │         Active Neighbors          │  │
│  │  (max 8, randomly selected)       │  │
│  │                                   │  │
│  │   [peer-a] [peer-b] [peer-c]     │  │
│  │   [peer-d] [peer-e] [peer-f]     │  │
│  │                                   │  │
│  └───────────────────────────────────┘  │
│                                         │
│  [peer-g] [peer-h] [peer-i] [peer-j]   │
│  [peer-k] [peer-l] ... (inactive)      │
│                                         │
└─────────────────────────────────────────┘
```

Neighbors are selected randomly from peers seen within the last 7 days. This random selection provides network diversity and resilience against partitioning.

### Addresses

Users are addressed as `username@server_id`:

```
taylor@acme-corp        # User "taylor" on server "acme-corp"
alex@west-office        # User "alex" on server "west-office"
```

---

## Protocol Messages

### 1. Server Announcement

Servers periodically announce themselves to neighbors:

```json
{
  "version": "1.0",
  "server_id": "acme-corp",
  "server_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...",
  "capabilities": {
    "paging": true,
    "ai_messaging": false,
    "supported_versions": ["1.0"]
  },
  "endpoints": {
    "federation": "https://acme-corp.example.com/api/federation",
    "discovery": "https://acme-corp.example.com/api/discovery"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "signature": "base64-encoded-rsa-signature..."
}
```

**Validation Rules:**
- Timestamp must be within 1 hour (prevents replay attacks)
- Clock skew tolerance: +/-5 minutes
- Signature must verify against included public key
- If server_id already known with different UUID -> collision, reject

### 2. Federated Message

Cross-server pager message:

```json
{
  "version": "1.0",
  "message_id": "MSG-A1B2C3D4E5F6",
  "message_type": "pager",
  "from_address": "taylor@acme-corp",
  "to_address": "alex@west-office",
  "content": "Meeting in conference room 302 - please join ASAP",
  "priority": 2,
  "timestamp": "2024-01-15T10:35:00Z",
  "sender_fingerprint": "A1B2C3D4...",
  "signature": "base64-encoded-rsa-signature...",
  "metadata": {}
}
```

**Priority Levels:**
- `0`: Normal
- `1`: High
- `2`: Urgent

### 3. Domain Query

When a server doesn't know how to reach a domain:

```json
{
  "query_id": "QUERY-1705312500000",
  "domain": "west-office",
  "requester": "acme-corp",
  "max_hops": 10,
  "timestamp": "2024-01-15T10:35:00Z"
}
```

The query propagates through the network (up to `max_hops`) until someone knows the answer.

### 4. Domain Response

Answer to a domain query:

```json
{
  "query_id": "QUERY-1705312500000",
  "domain": "west-office",
  "found": true,
  "server_id": "west-office",
  "endpoint_url": "https://west-office.example.com/api/federation",
  "hop_count": 3,
  "confidence": 0.729,
  "timestamp": "2024-01-15T10:35:01Z"
}
```

**Confidence Decay:**
Each hop reduces confidence by 10% (multiplied by 0.9). A route discovered 3 hops away has confidence `0.9^3 = 0.729`.

---

## Message Flow Examples

### Example 1: Sending a Pager Message

Taylor on `acme-corp` sends a page to Alex on `west-office`:

```
┌──────────────────┐                              ┌──────────────────┐
│    acme-corp     │                              │   west-office    │
│                  │                              │                  │
│  Taylor's pager  │                              │   Alex's pager   │
│       tool       │                              │                  │
└────────┬─────────┘                              └────────▲─────────┘
         │                                                 │
         │ 1. send("alex@west-office", "Room 302 meeting") │
         ▼                                                 │
┌──────────────────┐                              ┌────────┴─────────┐
│ LatticeAdapter│                              │ LatticeAdapter│
│                  │                              │                  │
│ - Verify Taylor  │                              │ - Verify sig     │
│   owns address   │                              │ - Filter content │
│ - Sign message   │                              │ - Resolve "alex" │
│ - Queue for      │                              │ - Deliver locally│
│   delivery       │                              │                  │
└────────┬─────────┘                              └────────▲─────────┘
         │                                                 │
         │ 2. INSERT INTO lattice_messages              │
         ▼                                                 │
┌──────────────────┐                              ┌────────┴─────────┐
│ Discovery Daemon │  3. POST /federation/        │ Discovery Daemon │
│                  │     messages/receive         │                  │
│ - Resolve domain │ ─────────────────────────▶   │ - Rate limit chk │
│ - Check circuit  │                              │ - Accept message │
│   breaker        │  4. {"status": "accepted"}   │                  │
│ - HTTP POST      │ ◀─────────────────────────   │                  │
│ - Update status  │                              │                  │
└──────────────────┘                              └──────────────────┘
```

**Step-by-Step:**

1. Taylor's pager tool calls `LatticeAdapter.send_federated_message()`
2. Adapter verifies Taylor owns `taylor@acme-corp`, signs message, queues it
3. Discovery daemon (every 1 min) picks up pending messages
4. Resolves `west-office` -> looks up in `lattice_peers` table
5. Checks circuit breaker (is `west-office` responsive?)
6. POSTs signed message to `west-office`'s federation endpoint
7. Remote server verifies signature, checks rate limits, delivers to Alex
8. Returns `{"status": "accepted"}`
9. Local daemon marks message as delivered

### Example 2: Gossip Round

Every 10 minutes, servers announce themselves to neighbors:

```
                    ┌─────────────┐
                    │   peer-a    │
                    └──────▲──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        │         1. Select 3 random          │
        │            neighbors                │
        │                  │                  │
┌───────▼───────┐  ┌───────┴───────┐  ┌───────▼───────┐
│    peer-b     │  │  OUR SERVER   │  │    peer-c     │
└───────────────┘  │               │  └───────────────┘
                   │ 2. Create     │
                   │    signed     │
                   │    announce-  │
                   │    ment       │
                   │               │
                   │ 3. POST to    │
                   │    each       │
                   └───────────────┘

Each recipient:
- Validates timestamp (< 1h old)
- Verifies signature
- Updates peer record (last_seen_at, endpoints, etc.)
- May forward to their neighbors (epidemic spread)
```

**Epidemic Spread:**
If `peer-a` doesn't know about us, they add us to their peer list. Next gossip round, they might tell `peer-d` about us. Information spreads exponentially.

### Example 3: Domain Resolution

`acme-corp` wants to reach `unknown-server` but doesn't know the route:

```
┌─────────────────┐     Query: "unknown-server"       ┌─────────────────┐
│    acme-corp    │ ─────────────────────────────────▶│    peer-a       │
│                 │                                    │                 │
│  "I don't know  │                                    │  "I don't know  │
│   this domain"  │                                    │   either, let   │
│                 │                                    │   me forward"   │
└─────────────────┘                                    └────────┬────────┘
                                                                │
                                                                │ Forward
                                                                ▼
                                                       ┌─────────────────┐
                                                       │    peer-b       │
                                                       │                 │
                                                       │  "I know them!  │
                                                       │   Here's the    │
                                                       │   endpoint"     │
                                                       └────────┬────────┘
                                                                │
        Response: {found: true, endpoint: "https://..."}        │
┌─────────────────┐◀────────────────────────────────────────────┘
│    acme-corp    │
│                 │
│  "Got it!       │
│   Caching for   │
│   24 hours"     │
└─────────────────┘
```

**Query Deduplication:**
Each query has a unique `query_id`. If a server sees the same query twice (circular topology), it ignores the duplicate.

### Example 4: New Server Joining

A new server `new-branch` wants to join the federation:

```
1. BOOTSTRAP
   ┌─────────────────┐                    ┌─────────────────┐
   │   new-branch    │  GET /api/v1/      │ bootstrap-server│
   │                 │  announcement      │  (configured    │
   │  "I'm new here" │ ──────────────────▶│   in Vault)     │
   │                 │                    │                 │
   │                 │ ◀────────────────  │  "Here's my     │
   │                 │  ServerAnnouncement│   identity"     │
   └─────────────────┘                    └─────────────────┘

2. DOMAIN REGISTRATION
   ┌─────────────────┐
   │   new-branch    │
   │                 │
   │  "Is 'new-      │──▶ Query all neighbors with max_hops=20
   │   branch'       │
   │   available?"   │◀── Responses: not found (confidence 0.85)
   │                 │
   │  "Registering   │──▶ INSERT INTO lattice_identity
   │   domain..."    │
   └─────────────────┘

3. ANNOUNCE TO NETWORK
   ┌─────────────────┐
   │   new-branch    │
   │                 │──▶ POST announcement to bootstrap server
   │  "Hello world!" │
   │                 │──▶ Bootstrap forwards to their neighbors
   └─────────────────┘    (epidemic spread begins)
```

**Domain Collision Protection:**
- Before registration, query network with high hop count (20)
- Calculate confidence based on network visibility
- If confidence < 0.8, block registration (unless manual override)
- UUID prevents hijacking: same domain + different UUID = rejected

---

## Network Topology Confidence

The system uses a **network visibility saturation model** to determine when it has a strong view of the federation topology. This prevents domain collisions and ensures reliable routing.

- Queries propagate through the network, tracking how many new peers are discovered
- Few new peers = high confidence (we've seen most of the network)
- Many new peers = low confidence (unexplored regions exist)
- Domain registration requires ≥ 0.8 confidence to prevent collisions

**Strong topology** is detected when:
1. **Confidence ≥ 0.8** - Few or no new peers discovered during queries
2. **High query coverage** - Most neighbors responded to verification
3. **Multiple hops completed** - Query propagated through multiple network layers

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for confidence calculation details and thresholds.

---

## Security Model

| Component | Details |
|-----------|---------|
| **Cryptography** | RSA-2048 keypairs, RSA-PSS with SHA-256 signatures |
| **Key Storage** | HashiCorp Vault |
| **Message Signing** | All protocol messages cryptographically signed |
| **Rate Limiting** | Per-peer limits prevent spam and abuse |
| **Circuit Breaker** | Automatic backoff from unresponsive peers |
| **Collision Detection** | UUID-based domain ownership prevents hijacking |

### Trust Levels

| Level | Description |
|-------|-------------|
| `trusted` | Manually verified peer |
| `unknown` | Default for new peers |
| `untrusted` | Suspicious behavior |
| `blocked` | Banned from federation |

All federated content is treated as untrusted and should be filtered for prompt injection attacks before delivery.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for implementation details.

---

## Development

```bash
# Clone repository
git clone https://github.com/taylorsatula/lattice
cd lattice

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Start development server
uvicorn lattice.discovery_daemon:app --reload --port 1113
```

---

## Deployment

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for database schema, scheduled tasks, and internals.
See [docs/LATTICE_SYSTEMD.md](docs/LATTICE_SYSTEMD.md) for systemd service setup.
See [docs/LATTICE_VAULT_SETUP.md](docs/LATTICE_VAULT_SETUP.md) for Vault configuration.

---

## Glossary

| Term | Definition |
|------|------------|
| **Gossip** | Epidemic protocol where servers randomly share info with neighbors |
| **Neighbor** | A peer we actively communicate with (max 8) |
| **Peer** | Any server we know about |
| **Announcement** | Signed message declaring a server's identity and endpoints |
| **Circuit Breaker** | Pattern that stops trying unresponsive peers temporarily |
| **Hop** | One step in query forwarding; `hop_count` limits propagation depth |
| **Fingerprint** | Short hash of public key for identification |
| **Confidence** | 0.0-1.0 score indicating route reliability (decays 10% per hop) or network visibility (based on new peer discovery during queries) |
| **Network Visibility** | How much of the federation topology is known; high visibility (few new peers discovered) yields high confidence |

---

## License

MIT
