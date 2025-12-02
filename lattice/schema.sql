-- Lattice Schema (SQLite)
-- Database schema for gossip-based peer discovery and cross-server messaging

-- =====================================================================
-- FEDERATION PEER MANAGEMENT
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_peers (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL UNIQUE,
    server_uuid TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '{}',
    endpoints TEXT NOT NULL DEFAULT '{}',

    -- Discovery tracking
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_announcement TEXT,

    -- Neighbor management
    is_neighbor INTEGER NOT NULL DEFAULT 0,

    -- Trust status (manual designation)
    trust_status TEXT NOT NULL DEFAULT 'unknown' CHECK (trust_status IN ('unknown', 'trusted', 'untrusted', 'blocked', 'revoked')),

    -- Rate limiting
    query_count INTEGER DEFAULT 0,
    message_count INTEGER DEFAULT 0,
    rate_limit_reset_at TEXT,

    -- Circuit breaker
    circuit_failures INTEGER DEFAULT 0,
    circuit_open_until TEXT,

    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_lattice_peers_serverid ON lattice_peers(server_id);
CREATE INDEX IF NOT EXISTS idx_lattice_peers_uuid ON lattice_peers(server_uuid);
CREATE INDEX IF NOT EXISTS idx_lattice_peers_neighbors ON lattice_peers(is_neighbor);
CREATE INDEX IF NOT EXISTS idx_lattice_peers_trust ON lattice_peers(trust_status);

-- =====================================================================
-- FEDERATION ROUTING CACHE
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_routes (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    server_id TEXT NOT NULL REFERENCES lattice_peers(server_id) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL,

    -- Routing metadata
    hop_count INTEGER NOT NULL DEFAULT 1,
    discovered_via TEXT,
    confidence REAL DEFAULT 0.9 CHECK (confidence >= 0 AND confidence <= 1),

    -- Cache management
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    query_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_lattice_routes_domain ON lattice_routes(domain);
CREATE INDEX IF NOT EXISTS idx_lattice_routes_expires ON lattice_routes(expires_at);

-- =====================================================================
-- FEDERATION MESSAGE QUEUE (for retries and acknowledgments)
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_messages (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE,

    -- Message routing
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    to_domain TEXT NOT NULL,
    to_server_id TEXT,

    -- Message content
    message_type TEXT NOT NULL DEFAULT 'pager',
    content TEXT NOT NULL,
    priority INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}',

    -- Cryptographic
    signature TEXT NOT NULL,
    sender_fingerprint TEXT NOT NULL,

    -- Delivery tracking
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'delivered', 'failed', 'expired')),
    attempt_count INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    next_attempt_at TEXT,
    last_status_change_at TEXT DEFAULT (datetime('now')),

    -- Acknowledgment
    ack_received INTEGER DEFAULT 0,
    ack_received_at TEXT,
    ack_data TEXT,

    -- Timestamps
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    sent_at TEXT,
    delivered_at TEXT,
    expires_at TEXT NOT NULL,

    -- Error tracking
    last_error TEXT,
    error_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_lattice_messages_status ON lattice_messages(status);
CREATE INDEX IF NOT EXISTS idx_lattice_messages_next_attempt ON lattice_messages(next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_lattice_messages_delivery_queue ON lattice_messages(to_domain, status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_lattice_messages_expires ON lattice_messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_lattice_messages_priority_queue ON lattice_messages(status, next_attempt_at, priority, created_at);

-- =====================================================================
-- RECEIVED MESSAGE TRACKING (for idempotency)
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_received_messages (
    message_id TEXT PRIMARY KEY,
    from_address TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_received_messages_cleanup ON lattice_received_messages(received_at);

-- =====================================================================
-- FEDERATION BLOCKLIST (manual spam control)
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_blocklist (
    id TEXT PRIMARY KEY,
    blocked_identifier TEXT NOT NULL UNIQUE,
    block_type TEXT NOT NULL CHECK (block_type IN ('domain', 'server', 'ip', 'fingerprint')),
    reason TEXT,

    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT,
    expires_at TEXT,

    -- Stats
    block_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_lattice_blocklist_identifier ON lattice_blocklist(blocked_identifier);
CREATE INDEX IF NOT EXISTS idx_lattice_blocklist_type ON lattice_blocklist(block_type);

-- =====================================================================
-- KEY ROTATION HISTORY
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_key_rotations (
    id TEXT PRIMARY KEY,
    server_uuid TEXT NOT NULL,
    old_key_fingerprint TEXT NOT NULL,
    new_key_fingerprint TEXT NOT NULL,
    reason TEXT NOT NULL,
    rotated_at TEXT NOT NULL DEFAULT (datetime('now')),
    received_from TEXT
);

CREATE INDEX IF NOT EXISTS idx_key_rotations_uuid ON lattice_key_rotations(server_uuid);

-- =====================================================================
-- IDENTITY REVOCATIONS (cyanide pill)
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_revocations (
    id TEXT PRIMARY KEY,
    server_uuid TEXT NOT NULL UNIQUE,
    server_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT (datetime('now')),
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_uuid ON lattice_revocations(server_uuid);

-- =====================================================================
-- SERVER IDENTITY (our own server's federation identity)
-- =====================================================================

CREATE TABLE IF NOT EXISTS lattice_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    server_id TEXT NOT NULL,
    server_uuid TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    public_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,

    -- Bootstrap configuration
    bootstrap_servers TEXT DEFAULT '[]',
    peer_exchange_sources TEXT DEFAULT '[]',

    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_at TEXT
);

-- =====================================================================
-- TRIGGERS
-- =====================================================================

-- Update trigger for lattice_peers.updated_at
CREATE TRIGGER IF NOT EXISTS update_lattice_peers_updated_at
AFTER UPDATE ON lattice_peers
FOR EACH ROW
BEGIN
    UPDATE lattice_peers SET updated_at = datetime('now') WHERE id = NEW.id;
END;
