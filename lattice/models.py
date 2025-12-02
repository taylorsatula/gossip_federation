"""
Lattice protocol models.

Defines the protocol for gossip-based server discovery and message federation.
All messages are cryptographically signed for authenticity.
"""

import ipaddress
import socket
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Literal, Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


# =====================================================================
# URL VALIDATION HELPERS (SSRF Protection)
# =====================================================================

def _is_internal_address(hostname: str) -> bool:
    """
    Check if hostname is an internal/link-local address.

    Blocks:
    - Loopback (127.x.x.x, ::1)
    - Private networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    - Link-local (169.254.x.x, fe80::)
    - Reserved/unspecified addresses
    - Known localhost hostnames
    - Hostnames that resolve to internal IPs (DNS rebinding protection)
    """
    # Check for localhost hostnames
    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return True

    def _is_internal_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_unspecified
        )

    try:
        ip = ipaddress.ip_address(hostname)
        return _is_internal_ip(ip)
    except ValueError:
        # Not an IP address - resolve DNS and check all IPs
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _, _, _, sockaddr in results:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                # Handle IPv4-mapped IPv6
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
                if _is_internal_ip(ip):
                    return True
            return False
        except socket.gaierror:
            # DNS resolution failed - reject as suspicious
            return True


def _validate_endpoint_url(url: str) -> str:
    """
    Validate an endpoint URL for SSRF protection.

    Raises ValueError if URL points to internal/link-local address.
    """
    if not url:
        raise ValueError("Endpoint URL cannot be empty")

    parsed = urlparse(url)

    if not parsed.scheme:
        raise ValueError(f"Endpoint URL must include scheme (http/https): {url}")

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Endpoint URL must use http or https scheme: {url}")

    if not parsed.netloc:
        raise ValueError(f"Endpoint URL must include host: {url}")

    # Extract hostname (remove port if present)
    hostname = parsed.netloc.split(':')[0]

    if _is_internal_address(hostname):
        raise ValueError(
            f"Endpoint URL cannot point to internal/link-local address: {url}"
        )

    return url


# =====================================================================
# SERVER ANNOUNCEMENT (Gossip Protocol)
# =====================================================================

class ServerCapabilities(BaseModel):
    """Capabilities advertised by a federation server."""
    paging: bool = Field(default=True, description="Server supports pager messaging")
    ai_messaging: bool = Field(default=False, description="Server supports AI-to-AI messaging")
    supported_versions: List[str] = Field(default_factory=lambda: ["1.0"])


class ServerEndpoints(BaseModel):
    """Service endpoints for federation communication."""
    federation: str = Field(description="Federation message endpoint URL")
    discovery: str = Field(description="Discovery/gossip endpoint URL")

    @field_validator('federation', 'discovery')
    @classmethod
    def validate_endpoint_not_internal(cls, v):
        """Validate endpoint URLs don't point to internal addresses (SSRF protection)."""
        return _validate_endpoint_url(v)


class ServerAnnouncement(BaseModel):
    """Server announcement message for gossip protocol."""
    version: str = Field(default="1.0", description="Protocol version")
    server_id: str = Field(description="Unique server identifier (domain name)")
    server_uuid: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Permanent UUID for collision detection")
    public_key: str = Field(description="RSA public key in PEM format")
    capabilities: ServerCapabilities = Field(default_factory=ServerCapabilities)
    endpoints: ServerEndpoints = Field(description="Service endpoint URLs")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    signature: str = Field(description="Base64 signature of message content")

    @field_validator('server_id')
    @classmethod
    def validate_server_id(cls, v):
        """Ensure server_id is a valid domain format."""
        if not v or '://' in v or ' ' in v:
            raise ValueError("server_id must be a valid domain name")
        return v.lower()


# =====================================================================
# FEDERATED MESSAGE FORMAT
# =====================================================================

class FederatedMessage(BaseModel):
    """Message format for cross-server pager communication."""
    version: str = Field(default="1.0")
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique message ID (UUID)")
    message_type: Literal["pager", "location", "ai_to_ai"] = Field(default="pager")
    from_address: str = Field(description="Sender address (e.g., taylor@local.ourserver.com)")
    to_address: str = Field(description="Recipient address (e.g., alex@remote.otherserver.com)")
    content: str = Field(max_length=10000, description="Message content (max 10KB)")
    priority: int = Field(default=0, ge=0, le=2, description="0=normal, 1=high, 2=urgent")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sender_fingerprint: str = Field(description="Sender's device fingerprint")
    signature: str = Field(description="Base64 signature of message")

    # Optional fields
    location: Optional[Dict[str, Any]] = Field(default=None, description="Location data if applicable")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    @field_validator('from_address', 'to_address')
    @classmethod
    def validate_address_format(cls, v):
        """Ensure addresses are in user@domain format."""
        if '@' not in v:
            raise ValueError(f"Address must be in user@domain format, got: {v}")
        user, domain = v.split('@', 1)
        if not user or not domain:
            raise ValueError(f"Invalid address format: {v}")
        return v.lower()


# =====================================================================
# MESSAGE ACKNOWLEDGMENT
# =====================================================================

class MessageAcknowledgment(BaseModel):
    """Acknowledgment for successful message delivery."""
    version: str = Field(default="1.0")
    ack_type: Literal["message_received", "message_failed", "unknown"] = Field(default="unknown")
    message_id: str = Field(description="ID of the message being acknowledged")
    status: Literal["delivered", "failed", "rejected"] = Field(description="Delivery status")
    recipient_server: str = Field(description="Server that received the message")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    signature: str = Field(description="Base64 signature")

    # Optional error info
    error_message: Optional[str] = Field(default=None, description="Error details if failed")
    error_code: Optional[str] = Field(default=None, description="Error code if applicable")


# =====================================================================
# DOMAIN RESOLUTION
# =====================================================================

class DomainQuery(BaseModel):
    """Query to resolve a domain to a server endpoint."""
    query_id: str = Field(description="Unique query identifier")
    domain: str = Field(description="Domain to resolve (e.g., other-server.com)")
    requester: str = Field(description="Server making the query")
    max_hops: int = Field(default=5, ge=1, le=10, description="Maximum hops for query (limited to prevent amplification)")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        """Ensure domain is valid format."""
        if not v or '://' in v or '@' in v:
            raise ValueError("Invalid domain format")
        return v.lower()


class DomainResponse(BaseModel):
    """Response to domain resolution query."""
    query_id: str = Field(description="ID of the original query")
    domain: str = Field(description="Domain that was queried")
    found: bool = Field(description="Whether domain was resolved")
    server_id: Optional[str] = Field(default=None, description="Resolved server ID")
    endpoint_url: Optional[str] = Field(default=None, description="Federation endpoint URL")
    hop_count: int = Field(description="Number of hops to find result")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# =====================================================================
# GOSSIP PROTOCOL MESSAGES
# =====================================================================

class PeerExchange(BaseModel):
    """Exchange of known peers between servers."""
    version: str = Field(default="1.0")
    from_server: str = Field(description="Server sending the peer list")
    peers: List[str] = Field(description="List of known peer server IDs")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    signature: str = Field(description="Signature of peer list")


class KeyRotation(BaseModel):
    """Request to rotate a server's public key (signed with OLD key)."""
    version: str = Field(default="1.0")
    server_uuid: str = Field(description="Permanent server UUID")
    old_public_key: str = Field(description="Current public key being rotated out")
    new_public_key: str = Field(description="New public key to use")
    reason: Literal["scheduled", "compromise_suspected", "upgrade"] = Field(default="scheduled")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    signature: str = Field(description="Signature using OLD private key")


class IdentityRevocation(BaseModel):
    """Permanently revoke a server identity (cyanide pill)."""
    version: str = Field(default="1.0")
    server_uuid: str = Field(description="UUID being permanently revoked")
    server_id: str = Field(description="Current server_id for logging")
    reason: str = Field(description="Revocation reason")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    signature: str = Field(description="Signature using server's private key")


class GossipMessage(BaseModel):
    """Wrapper for gossip protocol messages."""
    message_type: Literal["announcement", "peer_exchange", "domain_query", "domain_response", "key_rotation", "identity_revocation"]
    payload: Dict[str, Any] = Field(description="Message payload")
    from_server: str = Field(description="Server sending the gossip")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# =====================================================================
# PEER EXCHANGE FILE FORMAT
# =====================================================================

class PeerInfo(BaseModel):
    """Information about a peer in exchange files."""
    server_id: str
    endpoints: ServerEndpoints
    last_seen: str = Field(description="ISO timestamp of last contact")
    trust_level: Optional[Literal["trusted", "neutral", "untrusted"]] = "neutral"


class PeerExchangeFile(BaseModel):
    """Format for peer exchange files shared out-of-band."""
    version: str = Field(default="1.0")
    peers: List[PeerInfo]
    compiled_by: str = Field(description="Entity that compiled this list")
    compiled_date: str = Field(description="When this list was compiled")
    expires_at: Optional[str] = Field(default=None, description="When this list expires")

    # Optional metadata
    description: Optional[str] = Field(default=None)
    contact: Optional[str] = Field(default=None, description="Contact for list maintainer")


# =====================================================================
# INTERNAL QUEUE MESSAGES
# =====================================================================

class QueuedMessage(BaseModel):
    """Internal representation of queued outbound messages."""
    id: str = Field(description="Internal queue ID")
    message: FederatedMessage
    destination_server: Optional[str] = Field(default=None)
    attempt_count: int = Field(default=0)
    next_attempt_at: Optional[datetime] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    last_error: Optional[str] = Field(default=None)