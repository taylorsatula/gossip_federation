# MIRA Federation Protocol

A decentralized protocol for cross-server pager messaging without a central coordinator.

## Overview

Federation allows MIRA servers to discover each other and exchange pager messages across server boundaries. Users can send messages to `user@remote-server` just like email, but for real-time paging.

**Key Properties:**
- **Decentralized**: No central registry or coordinator
- **Cryptographically Secure**: All messages signed with RSA-2048
- **Resilient**: Gossip protocol ensures eventual consistency
- **Spam-Resistant**: Rate limiting, reputation scoring, circuit breakers

---

## Quick Start

### Installation

```bash
pip install -e .
```

### Start the Discovery Daemon

```bash
# Apply database schema first
psql -U mira_admin -d mira_service -f deploy/federation_schema.sql

# Start daemon
uvicorn federation.discovery_daemon:app --host 0.0.0.0 --port 8302
```

### Using Docker

```bash
docker run -d \
  -p 8302:8302 \
  -e DATABASE_URL=postgresql://... \
  -e VAULT_ADDR=https://... \
  gossip-federation:latest
```

### REST Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /api/v1/peers` | List known peers |
| `POST /api/v1/announce` | Trigger gossip round |
| `POST /api/v1/gossip/receive` | Receive announcements |
| `POST /api/v1/route/{domain}` | Resolve domain to endpoint |

---

## Core Concepts

### Identity

Each MIRA server has a permanent identity:

```
server_id:   "acme-medical"          # Human-readable domain name
server_uuid: "550e8400-e29b-41d4..."  # Permanent UUID (survives renames)
public_key:  "-----BEGIN PUBLIC..."   # RSA-2048 public key
fingerprint: "A1B2C3D4E5F6..."        # SHA-256 of public key (first 32 hex chars)
```

The `server_uuid` is the true identity. If a server renames from `acme-medical` to `acme-health`, the UUID stays the same, and peers update their records accordingly.

### Peers vs Neighbors

**Peers**: All servers we know about (could be thousands)
**Neighbors**: Subset of peers we actively gossip with (max 8)

```
┌─────────────────────────────────────────┐
│              All Known Peers            │
│  ┌───────────────────────────────────┐  │
│  │         Active Neighbors          │  │
│  │  (max 8, selected by score)       │  │
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

Neighbors are selected based on:
- **Reputation score** (70% weight): Track record of successful interactions
- **Recency** (30% weight): How recently we've heard from them

### Addresses

Users are addressed as `username@server_id`:

```
taylor@acme-medical     # User "taylor" on server "acme-medical"
alex@city-hospital      # User "alex" on server "city-hospital"
```

---

## Protocol Messages

### 1. Server Announcement

Servers periodically announce themselves to neighbors:

```json
{
  "version": "1.0",
  "server_id": "acme-medical",
  "server_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...",
  "capabilities": {
    "paging": true,
    "ai_messaging": false,
    "supported_versions": ["1.0"]
  },
  "endpoints": {
    "federation": "https://acme-medical.example.com/api/federation",
    "discovery": "https://acme-medical.example.com/api/discovery"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "signature": "base64-encoded-rsa-signature..."
}
```

**Validation Rules:**
- Timestamp must be within 24 hours (prevents replay attacks)
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
  "from_address": "taylor@acme-medical",
  "to_address": "alex@city-hospital",
  "content": "Patient in room 302 needs immediate attention",
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
  "domain": "city-hospital",
  "requester": "acme-medical",
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
  "domain": "city-hospital",
  "found": true,
  "server_id": "city-hospital",
  "endpoint_url": "https://city-hospital.example.com/api/federation",
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

Taylor on `acme-medical` sends a page to Alex on `city-hospital`:

```
┌──────────────────┐                              ┌──────────────────┐
│   acme-medical   │                              │  city-hospital   │
│                  │                              │                  │
│  Taylor's pager  │                              │   Alex's pager   │
│       tool       │                              │                  │
└────────┬─────────┘                              └────────▲─────────┘
         │                                                 │
         │ 1. send("alex@city-hospital", "Patient 302")   │
         ▼                                                 │
┌──────────────────┐                              ┌────────┴─────────┐
│ FederationAdapter│                              │ FederationAdapter│
│                  │                              │                  │
│ - Verify Taylor  │                              │ - Verify sig     │
│   owns address   │                              │ - Filter content │
│ - Sign message   │                              │ - Resolve "alex" │
│ - Queue for      │                              │ - Deliver locally│
│   delivery       │                              │                  │
└────────┬─────────┘                              └────────▲─────────┘
         │                                                 │
         │ 2. INSERT INTO federation_messages              │
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

1. Taylor's pager tool calls `FederationAdapter.send_federated_message()`
2. Adapter verifies Taylor owns `taylor@acme-medical`, signs message, queues it
3. Discovery daemon (every 1 min) picks up pending messages
4. Resolves `city-hospital` -> looks up in `federation_peers` table
5. Checks circuit breaker (is `city-hospital` responsive?)
6. POSTs signed message to `city-hospital`'s federation endpoint
7. Remote server verifies signature, checks rate limits, delivers to Alex
8. Returns `{"status": "accepted"}`
9. Local daemon marks message as delivered, updates reputation

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
- Validates timestamp (< 24h old)
- Verifies signature
- Updates peer record (last_seen_at, endpoints, etc.)
- May forward to their neighbors (epidemic spread)
```

**Epidemic Spread:**
If `peer-a` doesn't know about us, they add us to their peer list. Next gossip round, they might tell `peer-d` about us. Information spreads exponentially.

### Example 3: Domain Resolution

`acme-medical` wants to reach `unknown-hospital` but doesn't know the route:

```
┌─────────────────┐     Query: "unknown-hospital"     ┌─────────────────┐
│  acme-medical   │ ─────────────────────────────────▶│    peer-a       │
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
│  acme-medical   │
│                 │
│  "Got it!       │
│   Caching for   │
│   24 hours"     │
└─────────────────┘
```

**Query Deduplication:**
Each query has a unique `query_id`. If a server sees the same query twice (circular topology), it ignores the duplicate.

### Example 4: New Server Joining

A new server `new-clinic` wants to join the federation:

```
1. BOOTSTRAP
   ┌─────────────────┐                    ┌─────────────────┐
   │   new-clinic    │  GET /api/v1/      │ bootstrap-server│
   │                 │  announcement      │  (configured    │
   │  "I'm new here" │ ──────────────────▶│   in Vault)     │
   │                 │                    │                 │
   │                 │ ◀────────────────  │  "Here's my     │
   │                 │  ServerAnnouncement│   identity"     │
   └─────────────────┘                    └─────────────────┘

2. DOMAIN REGISTRATION
   ┌─────────────────┐
   │   new-clinic    │
   │                 │
   │  "Is 'new-      │──▶ Query all neighbors with max_hops=20
   │   clinic'       │
   │   available?"   │◀── Responses: not found (confidence 0.85)
   │                 │
   │  "Registering   │──▶ INSERT INTO federation_identity
   │   domain..."    │
   └─────────────────┘

3. ANNOUNCE TO NETWORK
   ┌─────────────────┐
   │   new-clinic    │
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

## Security Model

### Cryptography

| Component | Algorithm |
|-----------|-----------|
| Keypair | RSA-2048 |
| Signing | RSA-PSS with SHA-256 |
| Key Storage | HashiCorp Vault |
| Fingerprint | SHA-256 (first 32 hex chars) |

### Message Signing

All protocol messages are signed:

```python
# Signing
canonical_json = json.dumps(message_dict, sort_keys=True)
signature = private_key.sign(canonical_json, PSS_SHA256)

# Verification
canonical_json = json.dumps(message_dict, sort_keys=True)
public_key.verify(signature, canonical_json, PSS_SHA256)
```

**Why sorted keys?** JSON object key order isn't guaranteed. Sorting ensures identical bytes for signing and verification.

### Trust Levels

| Level | Description | Content Filtering |
|-------|-------------|-------------------|
| `trusted` | Manually verified peer | Minimal |
| `unknown` | Default for new peers | Standard |
| `untrusted` | Suspicious behavior | Aggressive |
| `blocked` | Banned from federation | Rejected |

**Prompt Injection Defense:**
All federated content is treated as `UNTRUSTED` and filtered for prompt injection attacks before delivery to users.

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| Federated messages | 100/peer | 1 minute |
| Gossip messages | 100/peer | 1 minute |

Rate limits use atomic database operations to prevent race conditions.

### Circuit Breaker

Protects against unresponsive peers:

```
Failures: 0 -> 1 -> 2 -> 3 -> 4 -> 5
                              │
                              ▼
                    CIRCUIT OPEN (15 min)
                              │
                    (timeout expires)
                              │
                              ▼
                    CIRCUIT CLOSED (retry)
```

After 5 consecutive failures, the circuit opens for 15 minutes. All messages to that peer are skipped until the timeout expires.

### Collision Detection

Prevents domain hijacking:

```
Existing peer:  server_id="acme"  server_uuid="UUID-A"

Attacker tries: server_id="acme"  server_uuid="UUID-B"
                                        │
                                        ▼
                              REJECTED (UUID mismatch)
```

The first server to claim a domain owns it permanently (tied to UUID).

---

## Database Tables

| Table | Purpose |
|-------|---------|
| `federation_identity` | Our server's identity (singleton) |
| `federation_peers` | Known peer servers |
| `federation_routes` | Cached domain -> endpoint mappings |
| `federation_messages` | Outbound message queue |
| `federation_received_messages` | Idempotency tracking (7-day TTL) |
| `federation_blocklist` | Manual ban list |
| `global_usernames` | Local username -> user_id mapping |

---

## Scheduled Tasks

| Task | Frequency | Endpoint |
|------|-----------|----------|
| Gossip round | 10 minutes | `POST /api/v1/announce` |
| Message delivery | 1 minute | `POST /api/v1/maintenance/process_messages` |
| Neighbor selection | 6 hours | `POST /api/v1/maintenance/update_neighbors` |
| Cleanup | Daily | `POST /api/v1/maintenance/cleanup` |

The main MIRA application's scheduler calls these endpoints on the discovery daemon (port 8302).

---

## Retry Logic

Failed message delivery uses exponential backoff:

```
Attempt 1: immediate
Attempt 2: +2 minutes
Attempt 3: +4 minutes
Attempt 4: +8 minutes
Attempt 5: +16 minutes
Attempt 6: +32 minutes
Attempt 7+: +60 minutes (capped)
```

Messages expire after 1 hour by default. After max attempts (default 3), the message is marked `failed`.

---

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
uvicorn federation.discovery_daemon:app --reload --port 8302
```

---

## Deployment

See [docs/FEDERATION_SYSTEMD.md](docs/FEDERATION_SYSTEMD.md) for systemd service setup.
See [docs/FEDERATION_VAULT_SETUP.md](docs/FEDERATION_VAULT_SETUP.md) for Vault configuration.

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
| **Confidence** | 0.0-1.0 score indicating route reliability (decays per hop) |

---

## License

MIT
