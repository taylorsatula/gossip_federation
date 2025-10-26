-- MIRA Federation Schema Extension
-- Adds support for gossip-based federation and cross-server pager messaging
-- Run this after mira_service_schema.sql is applied
--
-- psql -U mira_admin -h localhost -d mira_service -f deploy/federation_schema.sql

\c mira_service

-- =====================================================================
-- GLOBAL USERNAME REGISTRY (for local routing)
-- =====================================================================

CREATE TABLE IF NOT EXISTS global_usernames (
    username VARCHAR(50) PRIMARY KEY CHECK (username ~ '^[a-zA-Z0-9]{3,20}$'),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT TRUE
);

COMMENT ON TABLE global_usernames IS 'Server-wide username registry for pager routing (one username per user)';
COMMENT ON COLUMN global_usernames.username IS 'Unique username for pager addressing (alphanumeric, 3-20 chars, enforced by CHECK constraint)';
COMMENT ON COLUMN global_usernames.user_id IS 'User who owns this username';

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_global_usernames_lookup ON global_usernames(username);
CREATE INDEX IF NOT EXISTS idx_global_usernames_userid ON global_usernames(user_id);

-- =====================================================================
-- FEDERATION PEER MANAGEMENT
-- =====================================================================

CREATE TABLE IF NOT EXISTS federation_peers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id VARCHAR(255) NOT NULL UNIQUE,  -- e.g., "mirah" or "otherserver"
    server_uuid UUID NOT NULL UNIQUE,  -- Permanent UUID for collision detection
    public_key TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
    endpoints JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Discovery tracking
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_announcement JSONB,

    -- Neighbor management
    is_neighbor BOOLEAN NOT NULL DEFAULT FALSE,
    neighbor_score NUMERIC(5,3) DEFAULT 0.5,  -- 0.0-1.0 score for neighbor selection

    -- Trust and reputation
    trust_status VARCHAR(50) NOT NULL DEFAULT 'unknown' CHECK (trust_status IN ('unknown', 'trusted', 'untrusted', 'blocked')),
    reputation_score NUMERIC(5,3) DEFAULT 0.5 CHECK (reputation_score >= 0 AND reputation_score <= 1),

    -- Rate limiting
    query_count INTEGER DEFAULT 0,
    message_count INTEGER DEFAULT 0,
    rate_limit_reset_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE federation_peers IS 'Known peer servers in the federation network';
COMMENT ON COLUMN federation_peers.server_id IS 'Unique domain identifier for the peer server';
COMMENT ON COLUMN federation_peers.capabilities IS 'Feature capabilities advertised by peer (paging, ai_messaging, etc)';
COMMENT ON COLUMN federation_peers.endpoints IS 'Service endpoints (federation, discovery URLs)';
COMMENT ON COLUMN federation_peers.is_neighbor IS 'Whether this peer is an active gossip neighbor';
COMMENT ON COLUMN federation_peers.trust_status IS 'Manual trust designation for this peer';

CREATE INDEX IF NOT EXISTS idx_federation_peers_serverid ON federation_peers(server_id);
CREATE INDEX IF NOT EXISTS idx_federation_peers_uuid ON federation_peers(server_uuid);
CREATE INDEX IF NOT EXISTS idx_federation_peers_neighbors ON federation_peers(is_neighbor) WHERE is_neighbor = TRUE;
CREATE INDEX IF NOT EXISTS idx_federation_peers_neighbor_selection ON federation_peers(is_neighbor, neighbor_score DESC) WHERE is_neighbor = TRUE;
CREATE INDEX IF NOT EXISTS idx_federation_peers_trust ON federation_peers(trust_status);

-- =====================================================================
-- FEDERATION ROUTING CACHE
-- =====================================================================

CREATE TABLE IF NOT EXISTS federation_routes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain VARCHAR(255) NOT NULL UNIQUE,  -- Target domain to route to
    server_id VARCHAR(255) NOT NULL REFERENCES federation_peers(server_id) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL,

    -- Routing metadata
    hop_count INTEGER NOT NULL DEFAULT 1,
    discovered_via VARCHAR(255),  -- Which peer told us about this route
    confidence NUMERIC(3,2) DEFAULT 0.9 CHECK (confidence >= 0 AND confidence <= 1),

    -- Cache management
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    query_count INTEGER DEFAULT 0
);

COMMENT ON TABLE federation_routes IS 'Cached routing information for domain resolution';
COMMENT ON COLUMN federation_routes.domain IS 'Domain name that maps to this server';
COMMENT ON COLUMN federation_routes.hop_count IS 'Number of hops in discovery chain';
COMMENT ON COLUMN federation_routes.confidence IS 'Confidence level in this route (0.0-1.0)';

CREATE INDEX IF NOT EXISTS idx_federation_routes_domain ON federation_routes(domain);
CREATE INDEX IF NOT EXISTS idx_federation_routes_expires ON federation_routes(expires_at);

-- =====================================================================
-- FEDERATION MESSAGE QUEUE (for retries and acknowledgments)
-- =====================================================================

CREATE TABLE IF NOT EXISTS federation_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id VARCHAR(100) NOT NULL UNIQUE,  -- e.g., "MSG-12345678"

    -- Message routing
    from_address VARCHAR(255) NOT NULL,  -- e.g., "taylor@mirah.example.com"
    to_address VARCHAR(255) NOT NULL,    -- e.g., "alex@other-server.com"
    to_domain VARCHAR(255) NOT NULL,     -- Extracted domain for routing
    to_server_id VARCHAR(255),           -- Resolved server (may be NULL if unresolved)

    -- Message content
    message_type VARCHAR(50) NOT NULL DEFAULT 'pager',
    content TEXT NOT NULL,
    priority INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,

    -- Cryptographic
    signature TEXT NOT NULL,
    sender_fingerprint VARCHAR(64) NOT NULL,

    -- Delivery tracking
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'delivered', 'failed', 'expired')),
    attempt_count INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    next_attempt_at TIMESTAMP WITH TIME ZONE,
    last_status_change_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Acknowledgment
    ack_received BOOLEAN DEFAULT FALSE,
    ack_received_at TIMESTAMP WITH TIME ZONE,
    ack_data JSONB,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() + INTERVAL '1 hour',

    -- Error tracking
    last_error TEXT,
    error_count INTEGER DEFAULT 0
);

COMMENT ON TABLE federation_messages IS 'Outbound message queue for federation with retry management';
COMMENT ON COLUMN federation_messages.message_id IS 'Unique message identifier for tracking';
COMMENT ON COLUMN federation_messages.status IS 'Current delivery status of the message';
COMMENT ON COLUMN federation_messages.attempt_count IS 'Number of delivery attempts made';

CREATE INDEX IF NOT EXISTS idx_federation_messages_status ON federation_messages(status) WHERE status IN ('pending', 'sending');
CREATE INDEX IF NOT EXISTS idx_federation_messages_next_attempt ON federation_messages(next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_federation_messages_delivery_queue ON federation_messages(to_domain, status, next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_federation_messages_expires ON federation_messages(expires_at);
CREATE INDEX IF NOT EXISTS idx_federation_messages_priority_queue ON federation_messages(status, next_attempt_at, priority DESC, created_at ASC) WHERE status = 'pending';

-- Data integrity constraints
ALTER TABLE federation_messages
ADD CONSTRAINT IF NOT EXISTS chk_delivered_timestamp
CHECK (status != 'delivered' OR delivered_at IS NOT NULL);

ALTER TABLE federation_messages
ADD CONSTRAINT IF NOT EXISTS chk_failed_error
CHECK (status != 'failed' OR last_error IS NOT NULL);

-- =====================================================================
-- RECEIVED MESSAGE TRACKING (for idempotency)
-- =====================================================================

CREATE TABLE IF NOT EXISTS federation_received_messages (
    message_id VARCHAR(100) PRIMARY KEY,
    from_address VARCHAR(255) NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE federation_received_messages IS 'Tracks received message IDs to prevent duplicate deliveries (7-day retention for idempotency)';
COMMENT ON COLUMN federation_received_messages.message_id IS 'Message ID from remote server (ensures idempotent delivery)';

CREATE INDEX IF NOT EXISTS idx_received_messages_cleanup ON federation_received_messages(received_at);

-- =====================================================================
-- FEDERATION BLOCKLIST (manual spam control)
-- =====================================================================

CREATE TABLE IF NOT EXISTS federation_blocklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    blocked_identifier VARCHAR(255) NOT NULL UNIQUE,  -- Can be domain, server_id, or IP
    block_type VARCHAR(50) NOT NULL CHECK (block_type IN ('domain', 'server', 'ip', 'fingerprint')),
    reason TEXT,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),  -- Admin identifier
    expires_at TIMESTAMP WITH TIME ZONE,  -- NULL for permanent blocks

    -- Stats
    block_count INTEGER DEFAULT 0  -- Times this block was enforced
);

COMMENT ON TABLE federation_blocklist IS 'Manual blocklist for bad actors in the federation';
COMMENT ON COLUMN federation_blocklist.blocked_identifier IS 'The identifier to block (domain/server/IP)';
COMMENT ON COLUMN federation_blocklist.block_type IS 'Type of identifier being blocked';

CREATE INDEX IF NOT EXISTS idx_federation_blocklist_identifier ON federation_blocklist(blocked_identifier);
CREATE INDEX IF NOT EXISTS idx_federation_blocklist_type ON federation_blocklist(block_type);

-- =====================================================================
-- SERVER IDENTITY (our own server's federation identity)
-- =====================================================================

CREATE TABLE IF NOT EXISTS federation_identity (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- Singleton table
    server_id VARCHAR(255) NOT NULL,  -- Domain name (e.g., "mirah")
    server_uuid UUID NOT NULL,  -- Permanent UUID for collision detection (set explicitly, not via DEFAULT)
    private_key_vault_path TEXT NOT NULL,  -- Path to private key in Vault
    public_key TEXT NOT NULL,   -- RSA public key
    fingerprint VARCHAR(64) NOT NULL,

    -- Bootstrap configuration
    bootstrap_servers JSONB DEFAULT '[]'::jsonb,
    peer_exchange_sources JSONB DEFAULT '[]'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE federation_identity IS 'This server''s federation identity (singleton)';
COMMENT ON COLUMN federation_identity.server_id IS 'Our server''s unique identifier in the federation';
COMMENT ON COLUMN federation_identity.server_uuid IS 'Permanent UUID for detecting domain name collisions';
COMMENT ON COLUMN federation_identity.private_key_vault_path IS 'Path to private key in HashiCorp Vault';
COMMENT ON COLUMN federation_identity.bootstrap_servers IS 'List of bootstrap server URLs';

-- =====================================================================
-- TRIGGERS
-- =====================================================================

-- Update trigger for federation tables
DROP TRIGGER IF EXISTS update_federation_peers_updated_at ON federation_peers;
CREATE TRIGGER update_federation_peers_updated_at
BEFORE UPDATE ON federation_peers
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================================
-- PERMISSIONS
-- =====================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mira_dbuser') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            global_usernames, federation_peers, federation_routes,
            federation_messages, federation_received_messages,
            federation_blocklist, federation_identity
        TO mira_dbuser;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mira_dbuser;
    END IF;
END
$$;

-- Note: These federation tables do NOT have Row Level Security
-- They are system-level tables accessed by the federation daemon
-- User isolation is handled at the application level