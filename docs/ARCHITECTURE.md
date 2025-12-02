# Lattice Architecture

## Overview

Lattice enables decentralized cross-server messaging using a gossip-based peer discovery protocol. No central servers required.

## Architectural Decision: Async vs Sync

### Business Logic (Synchronous)

**Modules:** `gossip_protocol.py`, `peer_manager.py`, `lattice_adapter.py`, `domain_registration.py`

- All core business logic is **synchronous** (no `async`/`await`)
- Follows the "Synchronous Over Async" principle
- Easier to test, debug, and reason about
- No async overhead for non-I/O operations

**Rationale:** Cryptographic operations (signing/verification), database queries, and peer selection algorithms are CPU-bound or use connection pooling. Async adds complexity without benefit.

### I/O Layer (Async)

**Module:** `discovery_daemon.py` - FastAPI endpoints

- FastAPI endpoints use `async def` for efficient HTTP I/O
- Allows concurrent request handling without blocking
- Internal method calls (gossip, delivery) remain synchronous
- Main scheduler calls daemon via synchronous `httpx.Client`

**Rationale:** FastAPI async endpoints don't block the event loop during network I/O (incoming gossip messages, domain queries). This is a framework-level optimization, not a business logic concern.

### HTTP Calls

**Outbound:** Always synchronous using `httpx.Client` (not `AsyncClient`)
- Gossip rounds: `_send_gossip_to_neighbor()` uses `httpx.Client`
- Message delivery: `_send_to_remote_server()` uses `httpx.Client`
- Scheduler calls: `init_lattice.py` uses `httpx.Client`

**Why synchronous HTTP?**
1. These operations happen in background tasks where blocking is acceptable
2. Simpler error handling and timeout management
3. No need to propagate `async`/`await` through call chains

## Key Principle

> **Async at the edges (HTTP I/O), sync in the core (business logic).**

This gives us FastAPI's concurrency benefits without infecting the entire codebase with async complexity.

---

## Database Client Lifecycle

All Lattice modules create `SQLiteClient()` in `__init__`:

```python
def __init__(self):
    self.db = SQLiteClient()
```

**Lifecycle:**
- Client created once per service instance (e.g., one per `GossipProtocol` object)
- SQLite database file created automatically on first access
- Default path: `lattice.db` (configurable via `LATTICE_DB_PATH` env var)
- Schema auto-initialized from `lattice/schema.sql`

**Why SQLite:**
- Lattice is a single-daemon service - no need for external database server
- Simpler deployment and operational overhead
- Sufficient performance for peer discovery and message queuing
- File-level locking handles concurrency

---

## Message Flow

### Local → Local (Same Server)
1. User sends to recipient using username only (e.g., "alice" not "alice@server")
2. PagerTool uses external username resolver (configured via `set_username_resolver()`)
3. If found locally, resolves username → user_id
4. Message delivered directly via PagerTool's normal delivery mechanism
5. **No federation involved** - stays entirely within local server

### Local → Remote (Cross-Server)
1. User sends to federated address (e.g., "bob@other-server.com")
2. PagerTool detects '@' in recipient, calls `LatticeAdapter.send_federated_message()`
3. Message queued to `lattice_messages` table with status='pending'
4. Scheduler calls discovery daemon every 1 minute
5. Discovery daemon's `process_message_queue()` reads pending messages
6. Circuit breaker check - skip if peer has too many failures
7. `_deliver_single_message()` sends HTTP POST to remote server's federation endpoint
8. Status updated to 'delivered' or retried with exponential backoff (2, 4, 8 minutes)
9. After 5 consecutive failures, circuit breaker opens for 15 minutes

### Remote → Local (Inbound)
1. Remote server POSTs to `/api/federation/v1/messages/receive`
2. **Rate limiting check** - 100 messages/minute per peer (sliding window)
3. Extract sender domain from `from_address`
4. Look up sender's peer record from `lattice_peers` table
5. **Signature verification** - verify RSA signature using sender's public key
6. **Prompt injection filtering** - all content treated as UNTRUSTED
7. Username resolution via external resolver (configured via `set_username_resolver()`)
8. Create PagerTool instance for recipient user
9. `PagerTool.deliver_federated_message()` writes message to user's local pager (write-only)
10. Return 200 OK with acceptance status

---

## Security

- **All federated content treated as UNTRUSTED** - filtered for prompt injection
- **Signature verification** - RSA-2048 signatures on all messages
- **Rate limiting** - 100 messages/minute per peer (sliding window)
- **Circuit breaker** - 5 failures → 15 minute timeout per peer
- **Write-only delivery** - Federation can't read user data, only write messages
- **Secure credential storage** - Private keys via systemd credentials (encrypted) or file-based with 600 permissions

---

## Performance

- **Message delivery**: Every 1 minute (configurable via scheduler)
- **Gossip rounds**: Every 10 minutes
- **Neighbor updates**: Every 6 hours
- **Cleanup**: Daily
- **Crash recovery**: On daemon startup, all 'sending' → 'pending'

---

## Production Deployment

See `LATTICE_SYSTEMD.md` for systemd setup instructions.

**Required:**
1. Database schema auto-created on startup (SQLite)
2. Configure secrets in `/etc/lattice/` (APP_URL in config.env, private key)
3. Run discovery daemon (systemd service: `deploy/lattice.service`)
4. Configure username resolver for message delivery to local users
5. Main scheduler automatically handles periodic tasks

**Monitoring:**
- Discovery daemon health: `http://localhost:1113/api/v1/health`
- Peer list: `http://localhost:1113/api/v1/peers`
- Message queue status: Query `lattice_messages` table in SQLite
- Circuit breaker state: Logged when failures occur

---

## Database Tables

| Table | Purpose |
|-------|---------|
| `lattice_identity` | Our server's identity (singleton) |
| `lattice_peers` | Known peer servers |
| `lattice_routes` | Cached domain → endpoint mappings |
| `lattice_messages` | Outbound message queue |
| `lattice_received_messages` | Idempotency tracking (7-day TTL) |
| `lattice_blocklist` | Manual ban list |
| `global_usernames` | Local username → user_id mapping |

---

## Scheduled Tasks

| Task | Frequency | Endpoint |
|------|-----------|----------|
| Gossip round | 10 minutes | `POST /api/v1/announce` |
| Message delivery | 1 minute | `POST /api/v1/maintenance/process_messages` |
| Neighbor selection | 6 hours | `POST /api/v1/maintenance/update_neighbors` |
| Cleanup | Daily | `POST /api/v1/maintenance/cleanup` |

The main application's scheduler calls these endpoints on the discovery daemon (port 1113).

---

## Network Topology Confidence

The system uses a **network visibility saturation model** to determine when it has a strong view of the federation topology.

### Confidence Calculation

During domain verification queries, the system tracks how many **new peers** are discovered:

```
New Peers Discovered → Base Confidence
─────────────────────────────────────
0 peers              → 0.95 (full visibility)
1-2 peers            → 0.80 (good visibility)
3-5 peers            → 0.60 (moderate visibility)
6+ peers             → 0.40 (limited visibility)
```

**Intuition:** If a query traverses the network and discovers no new peers, the system has likely seen the entire reachable topology. Discovering many new peers indicates unexplored network regions.

Final confidence is adjusted by query coverage:
```
confidence = base_confidence × (servers_queried / total_neighbors)
```

### Query Termination

Queries terminate when any of these conditions are met:

| Condition | Description |
|-----------|-------------|
| **Domain found** | Immediate return with endpoint info |
| **Max hops reached** | Query exhausted its hop budget |
| **Duplicate query** | Same query_id seen before (loop prevention) |

**Hop limits vary by use case:**

| Operation | Max Hops | Rationale |
|-----------|----------|-----------|
| Domain verification (registration) | 20 | Thorough federation-wide search |
| Route resolution (messaging) | 10 | Balance between coverage and latency |
| Default query | 5 | Quick lookups for known domains |

### Strong Topology Detection

The system considers itself to have a **strong topology view** when:

1. **Confidence ≥ 0.8** - Few or no new peers discovered during queries
2. **Query coverage is high** - Most neighbors responded to verification
3. **Multiple hops completed** - Query propagated through multiple network layers

```
                    Query with max_hops=20
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
       neighbor-1       neighbor-2       neighbor-3
           │                │                │
     (no new peers)   (1 new peer)    (no new peers)
           │                │                │
           └────────────────┼────────────────┘
                            ▼
                  Confidence = 0.95 × (3/3) = 0.95
                            │
                            ▼
                  "Strong topology - safe to register"
```

### Query Deduplication

Prevents infinite loops in circular topologies:

- Each query has a unique `query_id`
- Servers cache seen query IDs for 5 minutes
- Duplicate queries are ignored (return "not found")
- Cache uses LRU eviction (max 1000 entries)

### Confidence Thresholds

| Threshold | Action |
|-----------|--------|
| ≥ 0.8 | Domain registration allowed |
| 0.6 - 0.79 | Registration blocked (insufficient visibility) |
| < 0.6 | Registration blocked, recommend more bootstrap servers |

**Manual Override:** Low-confidence registration can be forced with `allow_low_confidence=True`, but this risks domain collisions if the network has unseen partitions.

---

## Security Implementation Details

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

### Prompt Injection Filtering

The Lattice adapter can call content filtering before delivering inbound messages. Implement your own content filtering using tools such as:
- LlamaGuard
- GPT-OSS-20B
- Custom regex/heuristic filters

Without filtering, federated message content should be treated as untrusted user input.
