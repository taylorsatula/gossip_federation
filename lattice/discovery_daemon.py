"""
Lattice Discovery Daemon.

Standalone FastAPI service that handles peer discovery via gossip protocol.
Provides REST API for local tools to query routes.
"""

import asyncio
import ipaddress
import logging
import os
import random
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from pydantic import BaseModel, Field

from .sqlite_client import SQLiteClient
from .models import (
    ServerAnnouncement,
    DomainQuery,
    DomainResponse,
    GossipMessage,
    PeerExchangeFile,
    FederatedMessage,
    MessageAcknowledgment
)
from .username_resolver import resolve_username, has_username_resolver
from .peer_manager import PeerManager
from .gossip_protocol import GossipProtocol
from .domain_registration import (
    DomainRegistrationService,
    DomainRegistrationRequest,
    DomainRegistrationResult
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =====================================================================
# API Models
# =====================================================================

class AnnouncementRequest(BaseModel):
    """Request to announce server to network."""
    force: bool = Field(default=False, description="Force announcement even if recently sent")


class RouteQueryRequest(BaseModel):
    """Request to resolve a domain to server endpoint."""
    domain: str = Field(description="Domain to resolve (e.g., 'other-server.com')")


class RouteQueryResponse(BaseModel):
    """Response with routing information."""
    found: bool
    domain: str
    server_id: Optional[str] = None
    endpoint_url: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    from_cache: bool = Field(default=False, description="Whether result came from cache")


class PeerStatus(BaseModel):
    """Status information about a peer."""
    server_id: str
    is_neighbor: bool
    trust_status: str
    last_seen: str
    endpoints: Dict[str, str]


class InboundMessageResponse(BaseModel):
    """Response for inbound federated message."""
    status: str = Field(description="accepted, rejected, or failed")
    message_id: str = Field(description="ID of the processed message")
    ack: Optional[Dict[str, Any]] = Field(default=None, description="Signed acknowledgment")


class SendMessageRequest(BaseModel):
    """Request to send a federated message."""
    to_address: str = Field(description="Recipient address (e.g., alex@remote.otherserver.com)")
    from_address: str = Field(description="Sender address (e.g., taylor@local.ourserver.com)")
    content: str = Field(max_length=10000, description="Message content (max 10KB)")
    message_type: str = Field(default="pager", description="Message type: pager, location, ai_to_ai")
    priority: int = Field(default=0, ge=0, le=2, description="0=normal, 1=high, 2=urgent")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class SendMessageResponse(BaseModel):
    """Response from send message endpoint."""
    status: str = Field(description="queued, failed")
    message_id: str = Field(description="ID of the queued message")
    immediate_delivery: bool = Field(default=True, description="Whether immediate delivery was attempted")


# =====================================================================
# Access Control
# =====================================================================

async def localhost_only(request: Request):
    """
    FastAPI dependency that restricts endpoint access to localhost only.

    Use this for admin/maintenance endpoints that should not be exposed
    to the network (health checks, peer listings, maintenance tasks).

    Handles IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) by normalizing
    them to their IPv4 equivalent before checking.
    """
    client_host = request.client.host if request.client else None
    if not client_host:
        raise HTTPException(
            status_code=403,
            detail="This endpoint is restricted to localhost only"
        )

    try:
        ip = ipaddress.ip_address(client_host)
        # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        if not ip.is_loopback:
            raise HTTPException(
                status_code=403,
                detail="This endpoint is restricted to localhost only"
            )
    except ValueError:
        # Not a valid IP address
        raise HTTPException(
            status_code=403,
            detail="This endpoint is restricted to localhost only"
        )

    return client_host


# =====================================================================
# Service State
# =====================================================================

class DiscoveryService:
    """Core discovery service logic."""

    def __init__(self):
        self.peer_manager = PeerManager()
        self.gossip_protocol = GossipProtocol()
        self.domain_registration = DomainRegistrationService()
        self.db = SQLiteClient()
        self.last_gossip_time = None
        self.bootstrap_servers: List[str] = []

        # Status tracking for /status and /health endpoints
        self.start_time = datetime.now(timezone.utc)
        self.maintenance_mode = False
        self.cached_saturation: float = 0.0

        # Circuit breaker settings (state persisted in lattice_peers table)
        self._circuit_breaker_threshold = 5  # failures
        self._circuit_breaker_timeout = timedelta(minutes=15)

        # Query deduplication: Prevent query loops in circular topologies
        # Use OrderedDict with bounded size to prevent memory exhaustion
        self._processed_queries: OrderedDict[str, Any] = OrderedDict()  # query_id -> timestamp
        self._max_query_cache_size = 1000  # Maximum entries before LRU eviction

    async def initialize(self):
        """Initialize the discovery service."""
        # Load bootstrap servers from database
        identity = self.db.execute_single(
            "SELECT bootstrap_servers FROM lattice_identity WHERE id = 1"
        )
        if identity and identity['bootstrap_servers']:
            self.bootstrap_servers = identity['bootstrap_servers']
            logger.info(f"Loaded {len(self.bootstrap_servers)} bootstrap servers")

        # Reset any stuck messages from previous crash
        stuck_count = self._reset_stuck_messages()
        if stuck_count > 0:
            logger.info(f"Crash recovery: reset {stuck_count} stuck messages to pending")

        # Register gossip job with scheduler
        # Connect to bootstrap servers
        if self.bootstrap_servers:
            await self._connect_to_bootstrap_servers()

        logger.info("Discovery service initialized")

    async def _connect_to_bootstrap_servers(self):
        """Connect to bootstrap servers on startup (parallel for speed)."""
        import httpx

        async def _fetch_bootstrap(client, url):
            """Fetch single bootstrap server announcement."""
            try:
                logger.info(f"Connecting to bootstrap server: {url}")
                response = await client.get(f"{url}/api/v1/announcement")

                if response.status_code == 200:
                    announcement_data = response.json()
                    from .models import ServerAnnouncement
                    announcement = ServerAnnouncement(**announcement_data)

                    # Add bootstrap server to peer list
                    self.peer_manager.add_or_update_peer(announcement)
                    logger.info(f"Added bootstrap server: {announcement.server_id}")
                else:
                    logger.warning(f"Bootstrap server {url} returned {response.status_code}")

            except Exception as e:
                logger.error(f"Failed to connect to bootstrap {url}: {e}")

        # Connect to all bootstrap servers in parallel (faster startup)
        async with httpx.AsyncClient(timeout=10.0) as client:
            await asyncio.gather(
                *[_fetch_bootstrap(client, url) for url in self.bootstrap_servers],
                return_exceptions=True  # Don't fail if one bootstrap fails
            )

    def _perform_gossip_round(self):
        """Execute a gossip protocol round."""
        try:
            # Get active neighbors
            neighbors = self.peer_manager.get_active_neighbors()
            if not neighbors:
                logger.debug("No active neighbors for gossip")
                return

            # Create our announcement
            announcement = self.gossip_protocol.create_server_announcement()
            if not announcement:
                logger.error("Failed to create server announcement")
                return

            # Gossip to random subset of neighbors
            gossip_count = min(3, len(neighbors))
            selected = random.sample(neighbors, gossip_count)

            for neighbor in selected:
                try:
                    self._send_gossip_to_neighbor(neighbor, announcement)
                except Exception as e:
                    logger.error(f"Failed to gossip to {neighbor['server_id']}: {e}")

            self.last_gossip_time = datetime.now(timezone.utc)
            logger.info(f"Completed gossip round to {gossip_count} neighbors")

            # Update saturation metric after gossip
            self._update_saturation()

        except Exception as e:
            logger.error(f"Error in gossip round: {e}")

    def _send_gossip_to_neighbor(self, neighbor: Dict[str, Any], announcement: ServerAnnouncement):
        """Send announcement to a specific neighbor."""
        import httpx

        endpoint = neighbor['endpoints'].get('discovery')
        if not endpoint:
            logger.warning(f"No discovery endpoint for {neighbor['server_id']}")
            return

        try:
            # Create gossip message
            from .models import GossipMessage
            gossip = GossipMessage(
                message_type="announcement",
                payload=announcement.model_dump(),
                from_server=self.gossip_protocol.get_server_id() or "unknown"
            )

            # Send synchronously (gossip timing isn't critical)
            with httpx.Client(timeout=5.0) as client:
                response = client.post(
                    f"{endpoint}/api/v1/gossip/receive",
                    json=gossip.model_dump()
                )

                if response.status_code == 200:
                    logger.debug(f"Sent announcement to {neighbor['server_id']}")
                else:
                    logger.warning(
                        f"Gossip to {neighbor['server_id']} returned {response.status_code}"
                    )

        except Exception as e:
            logger.error(f"Failed to gossip to {neighbor['server_id']}: {e}")

    def _update_neighbors(self):
        """Update neighbor selection."""
        self.peer_manager.select_new_neighbors()

    def _update_saturation(self):
        """
        Calculate and cache network saturation metric.

        Saturation represents network visibility - how much of the reachable
        network this server has discovered. Based on peer discovery patterns:
        - 1.0 = Full visibility (no new peers being discovered)
        - 0.0 = Just started (still discovering the network)

        Called after gossip rounds to update the cached value.
        """
        try:
            # Get current peer counts
            peer_stats = self.db.execute_single(
                """
                SELECT
                    COUNT(*) as total_peers,
                    COUNT(CASE WHEN is_neighbor = 1 THEN 1 END) as neighbors,
                    COUNT(CASE WHEN last_seen_at > datetime('now', '-1 hour') THEN 1 END) as recently_active
                FROM lattice_peers
                WHERE trust_status != 'blocked'
                """
            )

            total_peers = peer_stats['total_peers'] if peer_stats else 0
            neighbors = peer_stats['neighbors'] if peer_stats else 0
            recently_active = peer_stats['recently_active'] if peer_stats else 0

            if total_peers == 0:
                # No peers yet - just starting
                self.cached_saturation = 0.0
                return

            # Saturation based on network stability:
            # - High neighbor ratio = well-connected
            # - High activity ratio = healthy network
            # Use a heuristic combining these factors

            # Target: ~10 neighbors is considered "saturated" for small networks
            # Scale up for larger networks
            target_neighbors = max(10, total_peers // 5)
            neighbor_saturation = min(1.0, neighbors / target_neighbors)

            # Activity ratio: what fraction of known peers are recently active
            activity_ratio = recently_active / total_peers if total_peers > 0 else 0.0

            # Combined saturation: weighted average
            # Neighbor connectivity matters more than activity
            self.cached_saturation = (0.7 * neighbor_saturation) + (0.3 * activity_ratio)

            logger.debug(
                f"Saturation updated: {self.cached_saturation:.2f} "
                f"(peers={total_peers}, neighbors={neighbors}, active={recently_active})"
            )

        except Exception as e:
            logger.error(f"Error calculating saturation: {e}")
            # Keep previous value on error

    def _cleanup_stale_data(self):
        """Clean up old data."""
        # Clean up stale peers
        peer_count = self.peer_manager.cleanup_stale_peers(days=30)

        # Clean up expired routes
        self.db.execute_delete(
            "DELETE FROM lattice_routes WHERE expires_at < datetime('now')"
        )

        # Clean up old messages
        self.db.execute_delete(
            "DELETE FROM lattice_messages WHERE expires_at < datetime('now') AND status IN ('delivered', 'failed', 'expired')"
        )

        # Clean up received message tracking (keep 7 days for debugging)
        self.db.execute_delete(
            "DELETE FROM lattice_received_messages WHERE received_at < datetime('now', '-7 days')"
        )

        # Reset stuck messages
        stuck_count = self._reset_stuck_messages()

        # Clean up query deduplication cache
        query_count = self._cleanup_query_cache()

        logger.info(f"Cleanup completed - removed {peer_count} stale peers, {query_count} old query IDs")

    def _reset_stuck_messages(self) -> int:
        """
        Reset messages stuck in 'sending' status for too long.

        Messages remain in 'sending' for 5+ minutes only if the daemon crashed
        or encountered a severe error during delivery. Reset these to 'pending'
        so delivery can be retried.

        Returns:
            Number of messages reset
        """
        try:
            result = self.db.execute_returning(
                """
                UPDATE lattice_messages
                SET status = 'pending',
                    next_attempt_at = datetime('now'),
                    last_status_change_at = datetime('now')
                WHERE status = 'sending'
                  AND last_status_change_at < datetime('now', '-5 minutes')
                RETURNING message_id
                """
            )

            count = len(result) if result else 0
            if count > 0:
                logger.warning(f"Reset {count} stuck messages from 'sending' to 'pending' (stuck > 5 min)")

            return count

        except Exception as e:
            logger.error(f"Error resetting stuck messages: {e}")
            return 0

    def _cleanup_query_cache(self) -> int:
        """
        Remove query IDs older than 5 minutes from deduplication cache.

        Query deduplication prevents infinite loops in circular network topologies.
        We only need to remember recently-seen queries, not all historical queries.

        Returns:
            Number of stale query IDs removed
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            before_count = len(self._processed_queries)

            self._processed_queries = OrderedDict(
                (qid, timestamp)
                for qid, timestamp in self._processed_queries.items()
                if timestamp > cutoff
            )

            removed = before_count - len(self._processed_queries)
            if removed > 0:
                logger.debug(f"Cleaned up {removed} stale query IDs from deduplication cache")

            return removed

        except Exception as e:
            logger.error(f"Error cleaning query cache: {e}")
            return 0

    # =====================================================================
    # Message Delivery (Synchronous)
    # =====================================================================

    def process_message_queue(self, max_messages: int = 10) -> Dict[str, Any]:
        """
        Process pending messages from the lattice_messages queue.

        Args:
            max_messages: Maximum number of messages to process in one batch

        Returns:
            Statistics about processing
        """
        try:
            # Get pending messages ready for delivery
            messages = self.db.execute_query(
                """
                SELECT *
                FROM lattice_messages
                WHERE status = 'pending'
                  AND next_attempt_at <= datetime('now')
                  AND expires_at > datetime('now')
                ORDER BY priority DESC, created_at ASC
                LIMIT %s
                """,
                (max_messages,)
            )

            if not messages:
                return {"processed": 0, "delivered": 0, "failed": 0, "message": "No pending messages"}

            delivered = 0
            failed = 0

            for msg in messages:
                try:
                    self._deliver_single_message(msg)
                    delivered += 1
                except Exception as e:
                    logger.error(f"Failed to deliver message {msg['message_id']}: {e}")
                    # Circuit breaker is recorded in _deliver_single_message
                    self._handle_delivery_failure(msg, str(e))
                    failed += 1

            logger.info(f"Processed {len(messages)} messages: {delivered} delivered, {failed} failed")

            return {
                "processed": len(messages),
                "delivered": delivered,
                "failed": failed,
                "message": f"Processed {len(messages)} messages"
            }

        except Exception as e:
            logger.error(f"Error processing message queue: {e}", exc_info=True)
            return {"error": str(e)}

    def _check_circuit_breaker(self, server_id: str) -> bool:
        """
        Check if circuit breaker is open for a peer (from database).

        Args:
            server_id: Peer server ID

        Returns:
            True if circuit is closed (can send), False if open (should skip)
        """
        peer = self.db.execute_single(
            "SELECT circuit_open_until FROM lattice_peers WHERE server_id = %s",
            (server_id,)
        )

        if not peer or not peer['circuit_open_until']:
            return True

        if peer['circuit_open_until'] <= datetime.now(timezone.utc):
            # Timeout expired - reset circuit
            self.db.execute_update(
                "UPDATE lattice_peers SET circuit_failures = 0, circuit_open_until = NULL WHERE server_id = %s",
                (server_id,)
            )
            logger.info(f"Circuit breaker timeout expired for {server_id} - closing circuit")
            return True

        logger.warning(f"Circuit breaker OPEN for {server_id} - skipping delivery until {peer['circuit_open_until']}")
        return False

    def _record_delivery_success(self, server_id: str) -> None:
        """Record successful delivery - resets circuit breaker (in database)."""
        self.db.execute_update(
            "UPDATE lattice_peers SET circuit_failures = 0, circuit_open_until = NULL WHERE server_id = %s",
            (server_id,)
        )

    def _record_delivery_failure(self, server_id: str) -> None:
        """Record delivery failure - may open circuit breaker (in database)."""
        result = self.db.execute_returning(
            """
            UPDATE lattice_peers
            SET circuit_failures = circuit_failures + 1
            WHERE server_id = %s
            RETURNING circuit_failures
            """,
            (server_id,)
        )

        if result and result[0]['circuit_failures'] >= self._circuit_breaker_threshold:
            open_until = datetime.now(timezone.utc) + self._circuit_breaker_timeout
            self.db.execute_update(
                "UPDATE lattice_peers SET circuit_open_until = %s WHERE server_id = %s",
                (open_until, server_id)
            )
            logger.error(
                f"Circuit breaker OPENED for {server_id} after {result[0]['circuit_failures']} "
                f"consecutive failures - blocking until {open_until}"
            )

    def _deliver_single_message(self, msg: Dict[str, Any]) -> None:
        """
        Deliver a single message to its destination.

        Args:
            msg: Message record from lattice_messages table

        Raises:
            Exception: If delivery fails
        """
        message_id = msg['message_id']
        to_domain = msg['to_domain']

        # Resolve recipient domain first to get server_id
        peer = self.peer_manager.get_peer_by_domain(to_domain)

        if not peer:
            raise ValueError(f"No route to domain: {to_domain}")

        # Use server_id for consistent circuit breaker tracking
        server_id = peer['server_id']

        # Check circuit breaker using resolved server_id
        if not self._check_circuit_breaker(server_id):
            raise ValueError(f"Circuit breaker open for {server_id}")

        if peer['trust_status'] == 'blocked':
            self._fail_message_permanently(message_id, "Recipient server is blocked")
            return

        # Update status to sending
        self.db.execute_update(
            "UPDATE lattice_messages SET status = 'sending', last_status_change_at = datetime('now') WHERE message_id = %s",
            (message_id,)
        )

        # Get federation endpoint
        endpoints = peer.get('endpoints', {})
        federation_url = endpoints.get('federation')

        if not federation_url:
            raise ValueError(f"No federation endpoint for {server_id}")

        # Construct federated message
        from .models import FederatedMessage
        # created_at is already a string in SQLite
        timestamp = msg['created_at'] if isinstance(msg['created_at'], str) else msg['created_at'].isoformat()
        message = FederatedMessage(
            message_id=msg['message_id'],
            message_type=msg['message_type'],
            from_address=msg['from_address'],
            to_address=msg['to_address'],
            content=msg['content'],
            priority=msg['priority'],
            timestamp=timestamp,
            sender_fingerprint=msg['sender_fingerprint'],
            signature=msg['signature'],
            metadata=msg.get('metadata', {})
        )

        # Send to remote server
        response = self._send_to_remote_server(
            federation_url + "/messages/receive",
            message.model_dump()
        )

        if response and response.get('status') == 'accepted':
            # Verify signed acknowledgment if present
            ack = response.get('ack')
            if ack:
                from .models import MessageAcknowledgment
                ack_obj = MessageAcknowledgment(**ack)
                ack_dict = ack_obj.model_dump(exclude={'signature'})
                recipient_public_key = peer.get('public_key')
                if recipient_public_key:
                    if not self.gossip_protocol.verify_signature(ack_dict, ack_obj.signature, recipient_public_key):
                        logger.warning(f"Invalid ack signature from {server_id} - possible MITM")
                        self._record_delivery_failure(server_id)
                        raise ValueError("Acknowledgment signature verification failed")
            # Mark as delivered and reset circuit breaker
            self._record_delivery_success(server_id)
            self._complete_message(message_id)
            logger.info(f"Message {message_id} delivered to {server_id}")
        else:
            self._record_delivery_failure(server_id)
            raise ValueError(f"Remote server rejected message: {response}")

    def _send_to_remote_server(self, url: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send message to remote federation server (synchronous).

        Args:
            url: Remote server federation endpoint
            data: Message data to send

        Returns:
            Response from remote server or None if failed
        """
        import httpx

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(url, json=data)

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(f"Remote server returned {response.status_code}: {response.text}")
                    return None

        except httpx.TimeoutException:
            logger.error(f"Timeout sending to {url}")
            return None
        except Exception as e:
            logger.error(f"Error sending to {url}: {e}")
            return None

    def _handle_delivery_failure(self, msg: Dict[str, Any], error: str) -> None:
        """
        Handle a delivery failure with retry logic.

        Args:
            msg: Message record
            error: Error message
        """
        message_id = msg['message_id']
        attempt_count = msg['attempt_count'] + 1
        max_attempts = msg['max_attempts']

        if attempt_count >= max_attempts:
            # Permanently fail the message
            self._fail_message_permanently(message_id, f"Max retries exceeded: {error}")
        else:
            # Schedule retry with exponential backoff (capped at 60 minutes)
            backoff_minutes = min(2 ** attempt_count, 60)  # 2, 4, 8, 16, 32, 60 minutes max
            next_attempt = datetime.now(timezone.utc) + timedelta(minutes=backoff_minutes)

            self.db.execute_update(
                """
                UPDATE lattice_messages
                SET status = 'pending',
                    attempt_count = %s,
                    next_attempt_at = %s,
                    last_error = %s,
                    error_count = error_count + 1,
                    last_status_change_at = datetime('now')
                WHERE message_id = %s
                """,
                (attempt_count, next_attempt.isoformat(), error, message_id)
            )

            logger.info(f"Message {message_id} retry scheduled for {next_attempt} (attempt {attempt_count}/{max_attempts})")

    def _complete_message(self, message_id: str) -> None:
        """Mark message as successfully delivered."""
        self.db.execute_update(
            """
            UPDATE lattice_messages
            SET status = 'delivered',
                delivered_at = datetime('now'),
                last_status_change_at = datetime('now')
            WHERE message_id = %s
            """,
            (message_id,)
        )

    def _fail_message_permanently(self, message_id: str, error: str) -> None:
        """Mark message as permanently failed."""
        self.db.execute_update(
            """
            UPDATE lattice_messages
            SET status = 'failed',
                last_error = %s,
                last_status_change_at = datetime('now')
            WHERE message_id = %s
            """,
            (error, message_id)
        )

        logger.error(f"Message {message_id} permanently failed: {error}")

    # =====================================================================
    # Outbound Message Queueing
    # =====================================================================

    def queue_outbound_message(
        self,
        to_address: str,
        from_address: str,
        content: str,
        message_type: str = "pager",
        priority: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Sign and queue a message for delivery.

        Args:
            to_address: Recipient address (user@domain)
            from_address: Sender address (user@domain)
            content: Message content
            message_type: Type of message (pager, location, ai_to_ai)
            priority: Message priority (0=normal, 1=high, 2=urgent)
            metadata: Optional metadata dict

        Returns:
            message_id of the queued message

        Raises:
            ValueError: If addresses are invalid or signing fails
        """
        import uuid

        # Validate address formats
        if '@' not in to_address:
            raise ValueError(f"Invalid to_address format: {to_address}")
        if '@' not in from_address:
            raise ValueError(f"Invalid from_address format: {from_address}")

        # Extract destination domain
        _, to_domain = to_address.split('@', 1)

        # Generate message ID
        message_id = str(uuid.uuid4())

        # Get sender fingerprint from our identity
        identity = self.db.execute_single(
            "SELECT fingerprint FROM lattice_identity WHERE id = 1"
        )
        if not identity:
            raise ValueError("No federation identity configured")

        sender_fingerprint = identity['fingerprint']

        # Create message dict for signing (excluding signature field)
        timestamp = datetime.now(timezone.utc).isoformat()
        message_dict = {
            "version": "1.0",
            "message_id": message_id,
            "message_type": message_type,
            "from_address": from_address.lower(),
            "to_address": to_address.lower(),
            "content": content,
            "priority": priority,
            "timestamp": timestamp,
            "sender_fingerprint": sender_fingerprint,
            "location": None,
            "metadata": metadata or {}
        }

        # Sign the message
        signature = self.gossip_protocol.sign_message(message_dict)

        # Calculate expiry (24 hours)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        # Insert into queue
        import json
        self.db.execute_insert(
            """
            INSERT INTO lattice_messages (
                id, message_id, from_address, to_address, to_domain,
                message_type, content, priority, metadata,
                signature, sender_fingerprint,
                status, attempt_count, max_attempts, next_attempt_at,
                created_at, expires_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                'pending', 0, 5, datetime('now'),
                datetime('now'), %s
            )
            """,
            (
                str(uuid.uuid4()),  # id (row ID)
                message_id,
                from_address.lower(),
                to_address.lower(),
                to_domain.lower(),
                message_type,
                content,
                priority,
                json.dumps(metadata or {}),
                signature,
                sender_fingerprint,
                expires_at
            )
        )

        logger.info(f"Queued message {message_id} to {to_address}")
        return message_id

    async def deliver_message_async(self, message_id: str) -> None:
        """
        Deliver a single message immediately (runs in background).

        This method fetches the message from the queue and attempts delivery.
        On failure, it schedules retry with exponential backoff.

        Args:
            message_id: ID of the message to deliver
        """
        try:
            # Fetch message from queue
            msg = self.db.execute_single(
                "SELECT * FROM lattice_messages WHERE message_id = %s",
                (message_id,)
            )

            if not msg:
                logger.warning(f"Message {message_id} not found for immediate delivery")
                return

            if msg['status'] != 'pending':
                logger.debug(f"Message {message_id} already in status {msg['status']}, skipping")
                return

            # Attempt delivery using existing synchronous method
            try:
                self._deliver_single_message(msg)
                logger.info(f"Immediate delivery succeeded for message {message_id}")
            except Exception as e:
                logger.warning(f"Immediate delivery failed for {message_id}: {e}")
                self._handle_delivery_failure(msg, str(e))

        except Exception as e:
            logger.error(f"Error in deliver_message_async for {message_id}: {e}", exc_info=True)


# =====================================================================
# FastAPI Application
# =====================================================================

discovery_service = DiscoveryService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    # Startup
    logger.info("Starting Discovery Daemon...")
    await discovery_service.initialize()
    yield
    # Shutdown
    logger.info("Shutting down Discovery Daemon...")


app = FastAPI(
    title="Lattice Discovery Daemon",
    description="Decentralized peer discovery service",
    version="1.0.0",
    lifespan=lifespan
)



# =====================================================================
# API Endpoints
# =====================================================================

@app.get("/status")
async def public_status():
    """
    Public status endpoint for external network participants.

    Returns lightweight information useful for deciding whether to interact
    with this server. No authentication required.
    """
    try:
        # Get peer count
        peer_count_result = discovery_service.db.execute_single(
            "SELECT COUNT(*) as count FROM lattice_peers WHERE trust_status != 'blocked'"
        )
        peer_count = peer_count_result['count'] if peer_count_result else 0

        return {
            "alive": True,
            "accepting_messages": not discovery_service.maintenance_mode,
            "peer_count": peer_count,
            "saturation": round(discovery_service.cached_saturation, 2),
            "version": "1.0.0"
        }

    except Exception as e:
        logger.error(f"Error in status endpoint: {e}")
        # Even on error, return basic alive status
        return {
            "alive": True,
            "accepting_messages": not discovery_service.maintenance_mode,
            "peer_count": 0,
            "saturation": 0.0,
            "version": "1.0.0"
        }


@app.get("/health")
async def health_check(_: str = Depends(localhost_only)):
    """
    Detailed health check endpoint (localhost only).

    Returns granular operational details for internal monitoring,
    admin tools, and the main application checking on the daemon.
    """
    try:
        # Get queue statistics
        queue_stats = discovery_service.db.execute_single(
            """
            SELECT
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
                COUNT(CASE WHEN status = 'sending' THEN 1 END) as sending,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
            FROM lattice_messages
            WHERE expires_at > datetime('now')
            """
        )

        # Get circuit breaker statistics
        circuit_stats = discovery_service.db.execute_single(
            """
            SELECT
                COUNT(*) as total_peers,
                COUNT(CASE WHEN circuit_open_until > datetime('now') THEN 1 END) as open_circuits
            FROM lattice_peers
            WHERE trust_status != 'blocked'
            """
        )

        # Calculate uptime
        uptime_seconds = int((datetime.now(timezone.utc) - discovery_service.start_time).total_seconds())

        return {
            "status": "healthy",
            "service": "discovery_daemon",
            "server_id": discovery_service.gossip_protocol.get_server_id(),
            "last_gossip": discovery_service.last_gossip_time.isoformat() if discovery_service.last_gossip_time else None,
            "maintenance_mode": discovery_service.maintenance_mode,
            "queues": {
                "pending": queue_stats['pending'] if queue_stats else 0,
                "sending": queue_stats['sending'] if queue_stats else 0,
                "failed": queue_stats['failed'] if queue_stats else 0
            },
            "circuit_breakers": {
                "open": circuit_stats['open_circuits'] if circuit_stats else 0,
                "total_peers": circuit_stats['total_peers'] if circuit_stats else 0
            },
            "saturation": round(discovery_service.cached_saturation, 2),
            "uptime_seconds": uptime_seconds
        }

    except Exception as e:
        logger.error(f"Error in health endpoint: {e}")
        return {
            "status": "degraded",
            "service": "discovery_daemon",
            "error": str(e)
        }


@app.get("/api/v1/identity")
async def get_server_identity():
    """Get this server's federation identity."""
    try:
        identity = discovery_service.db.execute_single(
            "SELECT server_id, server_uuid, fingerprint, created_at FROM lattice_identity WHERE id = 1"
        )

        if not identity:
            raise HTTPException(
                status_code=404,
                detail="Federation identity not configured"
            )

        return {
            "server_id": identity['server_id'],
            "server_uuid": identity['server_uuid'],
            "fingerprint": identity['fingerprint'],
            "created_at": identity['created_at']
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting identity: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/announcement")
async def get_server_announcement():
    """Get this server's announcement for bootstrap discovery."""
    try:
        announcement = discovery_service.gossip_protocol.create_server_announcement()

        if not announcement:
            raise HTTPException(
                status_code=500,
                detail="Failed to create server announcement"
            )

        return announcement.model_dump()

    except Exception as e:
        logger.error(f"Error creating announcement: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/announce")
async def announce_server(request: AnnouncementRequest, background_tasks: BackgroundTasks):
    """Announce local server to the network."""
    try:
        # Check if we recently announced
        if not request.force and discovery_service.last_gossip_time:
            time_since = (datetime.now(timezone.utc) - discovery_service.last_gossip_time).total_seconds()
            if time_since < 60:
                return {
                    "status": "rate_limited",
                    "message": f"Recently announced {int(time_since)} seconds ago",
                    "next_allowed": int(60 - time_since)
                }

        # Trigger gossip round in background
        background_tasks.add_task(discovery_service._perform_gossip_round)

        return {
            "status": "scheduled",
            "message": "Server announcement scheduled"
        }

    except Exception as e:
        logger.error(f"Error in announce endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/peers")
async def list_peers(
    _: str = Depends(localhost_only),
    active_only: bool = True,
    include_blocked: bool = False
) -> List[PeerStatus]:
    """Get list of known peer servers (localhost only)."""
    try:
        query = """
            SELECT server_id, is_neighbor, trust_status,
                   last_seen_at, endpoints
            FROM lattice_peers
            WHERE 1=1
        """
        params = []

        if active_only:
            query += " AND last_seen_at > %s"
            params.append(datetime.now(timezone.utc) - timedelta(days=7))

        if not include_blocked:
            query += " AND trust_status != 'blocked'"

        query += " ORDER BY is_neighbor DESC, last_seen_at DESC"

        peers = discovery_service.db.execute_query(query, tuple(params))

        return [
            PeerStatus(
                server_id=p['server_id'],
                is_neighbor=p['is_neighbor'],
                trust_status=p['trust_status'],
                last_seen=p['last_seen_at'].isoformat(),
                endpoints=p['endpoints']
            )
            for p in peers
        ]

    except Exception as e:
        logger.error(f"Error listing peers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/domain/query")
async def handle_domain_query(query: DomainQuery) -> DomainResponse:
    """Handle incoming domain query from another server (for forwarding)."""
    try:
        # Check for duplicate query (prevents loops in circular topologies)
        if query.query_id in discovery_service._processed_queries:
            logger.debug(f"Ignoring duplicate query {query.query_id} for domain {query.domain}")
            return DomainResponse(
                query_id=query.query_id,
                domain=query.domain,
                found=False,
                hop_count=0
            )

        # Mark query as processed with LRU eviction
        if len(discovery_service._processed_queries) >= discovery_service._max_query_cache_size:
            # Evict oldest entry (FIFO, which approximates LRU for this use case)
            discovery_service._processed_queries.popitem(last=False)
        discovery_service._processed_queries[query.query_id] = datetime.now(timezone.utc)

        # Process the query using gossip protocol
        response = discovery_service.gossip_protocol._handle_domain_query(
            query,
            from_server=query.requester
        )

        if response:
            # We have an answer (either found or not found after max hops)
            return response

        # No answer and hops remaining - forward to subset of neighbors (limit amplification)
        query.max_hops -= 1
        neighbors = discovery_service.peer_manager.get_active_neighbors()

        # Limit fan-out to 3 neighbors to prevent query amplification attacks
        import httpx
        sampled_neighbors = random.sample(neighbors, min(3, len(neighbors))) if neighbors else []
        with httpx.Client(timeout=3.0) as client:
            for neighbor in sampled_neighbors:
                try:
                    endpoint = neighbor['endpoints'].get('discovery')
                    if not endpoint:
                        continue

                    # Skip the server that sent us the query
                    if neighbor['server_id'] == query.requester:
                        continue

                    # Forward query to neighbor
                    forward_response = client.post(
                        f"{endpoint}/api/v1/domain/query",
                        json=query.model_dump()
                    )

                    if forward_response.status_code == 200:
                        result = DomainResponse(**forward_response.json())
                        if result.found:
                            # Cache the result before returning
                            discovery_service.gossip_protocol._handle_domain_response(result)
                            return result

                except Exception as e:
                    logger.debug(f"Forward to {neighbor['server_id']} failed: {e}")
                    continue

        # Nobody found it
        return DomainResponse(
            query_id=query.query_id,
            domain=query.domain,
            found=False,
            hop_count=query.max_hops
        )

    except Exception as e:
        logger.error(f"Error handling domain query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/route/{domain}")
async def resolve_route(domain: str) -> RouteQueryResponse:
    """Resolve a domain to a server endpoint."""
    try:
        # Check blocklist first
        if discovery_service.peer_manager.is_blocked(domain):
            return RouteQueryResponse(
                found=False,
                domain=domain,
                confidence=0.0
            )

        # Check cache
        peer = discovery_service.peer_manager.get_peer_by_domain(domain)
        if peer:
            endpoints = peer.get('endpoints', {})
            return RouteQueryResponse(
                found=True,
                domain=domain,
                server_id=peer['server_id'],
                endpoint_url=endpoints.get('federation'),
                confidence=0.9,
                from_cache=True
            )

        # Not in cache - initiate discovery query to neighbors
        query_id = f"QUERY-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
        query = DomainQuery(
            query_id=query_id,
            domain=domain,
            requester=discovery_service.gossip_protocol.get_server_id() or "unknown",
            max_hops=10  # High hop count for thorough domain resolution
        )

        # Process query locally first (checks our cache)
        local_response = discovery_service.gossip_protocol._handle_domain_query(
            query,
            from_server="local"
        )

        if local_response and local_response.found:
            # We found it in our cache
            return RouteQueryResponse(
                found=True,
                domain=domain,
                server_id=local_response.server_id,
                endpoint_url=local_response.endpoint_url,
                confidence=local_response.confidence,
                from_cache=True
            )

        # Not in cache - query neighbors with forwarding
        neighbors = discovery_service.peer_manager.get_active_neighbors()
        if not neighbors:
            logger.warning(f"No neighbors available to query for domain {domain}")
            return RouteQueryResponse(
                found=False,
                domain=domain,
                confidence=0.0
            )

        # Decrement hops for forwarding
        query.max_hops -= 1

        # Query subset of neighbors to limit amplification
        import httpx
        sampled_neighbors = random.sample(neighbors, min(3, len(neighbors)))
        with httpx.Client(timeout=5.0) as client:
            for neighbor in sampled_neighbors:
                try:
                    endpoint = neighbor['endpoints'].get('discovery')
                    if not endpoint:
                        continue

                    response = client.post(
                        f"{endpoint}/api/v1/domain/query",
                        json=query.model_dump(),
                        timeout=10.0  # Longer timeout for forwarding
                    )

                    if response.status_code == 200:
                        result = DomainResponse(**response.json())
                        if result.found:
                            # Cache the result
                            discovery_service.gossip_protocol._handle_domain_response(result)

                            return RouteQueryResponse(
                                found=True,
                                domain=domain,
                                server_id=result.server_id,
                                endpoint_url=result.endpoint_url,
                                confidence=result.confidence,
                                from_cache=False
                            )

                except Exception as e:
                    logger.debug(f"Query to {neighbor['server_id']} failed: {e}")
                    continue

        # No neighbors found the domain
        return RouteQueryResponse(
            found=False,
            domain=domain,
            confidence=0.0
        )

    except Exception as e:
        logger.error(f"Error resolving route for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/gossip/receive")
async def receive_gossip(message: GossipMessage):
    """Receive gossip message from another server."""
    try:
        # FASTPATH: Single atomic query for known peers - rate limit + peer info
        # Unknown peers (bootstrap announcements) handled separately below
        try:
            sender = discovery_service.db.execute_single(
                """
                UPDATE lattice_peers
                SET query_count = CASE
                        WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < datetime('now')
                        THEN 1
                        ELSE query_count + 1
                    END,
                    rate_limit_reset_at = CASE
                        WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < datetime('now')
                        THEN datetime('now', '+1 minute')
                        ELSE rate_limit_reset_at
                    END
                WHERE server_id = %s
                RETURNING public_key, server_uuid, query_count
                """,
                (message.from_server,)
            )
        except Exception as e:
            # FAIL CLOSED: Database error rejects the request
            logger.error(f"Rate limit check failed for gossip from {message.from_server}: {e}")
            raise HTTPException(status_code=503, detail="Rate limit check unavailable")

        # FASTPATH EXIT: Check rate limit immediately for known peers
        if sender and sender['query_count'] > 100:
            logger.warning(f"Rate limit exceeded for gossip from {message.from_server} (count: {sender['query_count']})")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        # For announcements, verify public key authenticity
        if message.message_type == "announcement":
            from .models import ServerAnnouncement
            announcement = ServerAnnouncement(**message.payload)

            # If we already know this server, verify the public key hasn't changed
            if sender:
                if sender['public_key'] != announcement.public_key:
                    logger.error(
                        f"Public key mismatch for {message.from_server}: "
                        f"stored key differs from announced key. Possible MITM attack!"
                    )
                    raise HTTPException(status_code=403, detail="Public key verification failed")
                sender_public_key = sender['public_key']  # Use known public key
            else:
                # Unknown server - only accept if from bootstrap servers
                # NOTE: Bootstrap servers (configured in LATTICE_BOOTSTRAP_SERVERS) are trusted on
                # first contact - their public keys are accepted without out-of-band verification.
                # This is a config-time trust decision: only configure bootstrap servers you control
                # or have verified. If a bootstrap server is compromised at first contact, an
                # attacker could inject arbitrary identities. Future enhancement: add key pinning
                # (fingerprint alongside URL in config). Contributions welcome.
                bootstrap_domains = [urlparse(url).hostname for url in discovery_service.bootstrap_servers if urlparse(url).hostname]
                if message.from_server not in bootstrap_domains:
                    logger.warning(
                        f"Rejecting announcement from unknown server '{message.from_server}'. "
                        f"New servers must be introduced by bootstrap or trusted peers."
                    )
                    raise HTTPException(
                        status_code=403,
                        detail="Unknown sender - new servers must be introduced via trusted path"
                    )
                sender_public_key = announcement.public_key  # First contact from bootstrap
        elif message.message_type == "key_rotation":
            from .models import KeyRotation
            rotation = KeyRotation(**message.payload)
            # Key rotation: verify with OLD key in message (peer_manager validates it matches stored)
            sender_public_key = rotation.old_public_key

        elif message.message_type == "identity_revocation":
            from .models import IdentityRevocation
            revocation = IdentityRevocation(**message.payload)
            # Revocation must come from known sender with matching UUID
            if not sender:
                raise HTTPException(status_code=403, detail="Unknown sender cannot revoke")
            if str(sender['server_uuid']) != revocation.server_uuid:
                raise HTTPException(status_code=403, detail="UUID mismatch in revocation")
            sender_public_key = sender['public_key']

        else:
            # For other messages, sender must be known
            if not sender:
                logger.warning(f"Received non-announcement gossip from unknown server: {message.from_server}")
                raise HTTPException(status_code=403, detail="Unknown sender")

            sender_public_key = sender['public_key']

        # Process the gossip message with verified public key
        success = discovery_service.gossip_protocol.process_gossip_message(
            message,
            sender_public_key
        )

        if not success:
            raise HTTPException(status_code=400, detail="Failed to process gossip")

        return {"status": "accepted"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error receiving gossip: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/federation/messages/receive")
async def receive_federated_message(message: FederatedMessage) -> InboundMessageResponse:
    """
    Receive an inbound federated message from a remote Lattice node.

    This endpoint:
    1. Verifies the message signature using the sender's public key
    2. Checks rate limits for the sending server
    3. Checks for duplicate message_id (idempotency)
    4. Resolves the recipient username to a user_id via the username_resolver hook
    5. Delivers the message via webhook to the configured LATTICE_DELIVERY_WEBHOOK
    6. Returns a signed acknowledgment to the sender
    """
    import httpx

    try:
        # Extract sender domain from from_address
        if '@' not in message.from_address:
            raise HTTPException(status_code=400, detail="Invalid from_address format")

        _, sender_domain = message.from_address.split('@', 1)

        # FASTPATH: Single atomic query that:
        # 1. Updates rate limit counter
        # 2. Returns peer info + current count
        # 3. Fails closed on any error
        try:
            sender = discovery_service.db.execute_single(
                """
                UPDATE lattice_peers
                SET query_count = CASE
                        WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < datetime('now')
                        THEN 1
                        ELSE query_count + 1
                    END,
                    rate_limit_reset_at = CASE
                        WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < datetime('now')
                        THEN datetime('now', '+1 minute')
                        ELSE rate_limit_reset_at
                    END
                WHERE server_id = %s
                RETURNING server_id, public_key, trust_status, query_count
                """,
                (sender_domain,)
            )
        except Exception as e:
            # FAIL CLOSED: Any database error rejects the request
            logger.error(f"Rate limit check failed for {sender_domain}: {e}")
            raise HTTPException(status_code=503, detail="Rate limit check unavailable")

        # FAIL CLOSED: No result means unknown peer OR database issue
        if not sender:
            logger.warning(f"Received message from unknown server: {sender_domain}")
            raise HTTPException(status_code=403, detail=f"Unknown sender server: {sender_domain}")

        # FASTPATH EXIT: Check rate limit immediately after atomic update
        if sender['query_count'] > 100:
            logger.warning(f"Rate limit exceeded for messages from {sender_domain} (count: {sender['query_count']})")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        # Now safe to do more expensive checks
        if sender['trust_status'] == 'blocked':
            logger.warning(f"Rejecting message from blocked server: {sender_domain}")
            raise HTTPException(status_code=403, detail="Sender server is blocked")

        # Verify message signature
        message_dict = message.model_dump(exclude={'signature'})
        if not discovery_service.gossip_protocol.verify_signature(
            message_dict,
            message.signature,
            sender['public_key']
        ):
            logger.error(f"Invalid signature on message {message.message_id} from {sender_domain}")
            raise HTTPException(status_code=403, detail="Message signature verification failed")

        # Check for duplicate message (idempotency)
        existing = discovery_service.db.execute_single(
            "SELECT message_id FROM lattice_received_messages WHERE message_id = %s",
            (message.message_id,)
        )

        if existing:
            logger.info(f"Duplicate message {message.message_id} - already processed")
            # Return success for idempotency (don't re-process, but acknowledge)
            return InboundMessageResponse(
                status="accepted",
                message_id=message.message_id,
                ack=None  # No new ack for duplicates
            )

        # Record the message as received
        discovery_service.db.execute_insert(
            """
            INSERT INTO lattice_received_messages (message_id, from_address, received_at)
            VALUES (%s, %s, datetime('now'))
            """,
            (message.message_id, message.from_address)
        )

        # Extract recipient username and resolve to user_id
        if '@' not in message.to_address:
            raise HTTPException(status_code=400, detail="Invalid to_address format")

        recipient_username, _ = message.to_address.split('@', 1)

        # Check if username resolver is configured
        if not has_username_resolver():
            logger.error("No username resolver configured - cannot deliver federated messages")
            raise HTTPException(
                status_code=503,
                detail="Server not configured to receive federated messages"
            )

        # Resolve username to user_id
        user_id = resolve_username(recipient_username)
        if not user_id:
            logger.warning(f"Unknown recipient username: {recipient_username}")
            return InboundMessageResponse(
                status="rejected",
                message_id=message.message_id,
                ack=_create_rejection_ack(message.message_id, f"Unknown recipient: {recipient_username}")
            )

        # Deliver via webhook
        delivery_webhook = os.getenv("LATTICE_DELIVERY_WEBHOOK")
        if not delivery_webhook:
            logger.error("LATTICE_DELIVERY_WEBHOOK not configured")
            raise HTTPException(
                status_code=503,
                detail="Delivery webhook not configured"
            )

        webhook_payload = {
            "from_address": message.from_address,
            "to_user_id": user_id,
            "content": message.content,
            "priority": message.priority,
            "message_id": message.message_id,
            "metadata": message.metadata,
            "sender_verified": True,
            "sender_server_id": sender_domain
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(delivery_webhook, json=webhook_payload)

                if response.status_code == 200:
                    logger.info(f"Message {message.message_id} delivered via webhook")

                    # Create signed acknowledgment
                    ack = _create_success_ack(message.message_id)

                    return InboundMessageResponse(
                        status="accepted",
                        message_id=message.message_id,
                        ack=ack
                    )
                elif 400 <= response.status_code < 500:
                    # 4xx: Permanent rejection - bad message, don't retry
                    logger.warning(f"Webhook rejected message {message.message_id}: {response.status_code} - {response.text}")
                    return InboundMessageResponse(
                        status="rejected",
                        message_id=message.message_id,
                        ack=_create_rejection_ack(message.message_id, f"Delivery rejected: {response.status_code}")
                    )
                else:
                    # 5xx: Temporary failure - sender should retry
                    logger.error(f"Webhook server error for {message.message_id}: {response.status_code} - {response.text}")
                    raise HTTPException(status_code=502, detail=f"Delivery backend error: {response.status_code}")

        except httpx.TimeoutException:
            logger.error(f"Webhook timeout for message {message.message_id}")
            raise HTTPException(status_code=504, detail="Delivery webhook timeout")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error receiving federated message: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def _create_success_ack(message_id: str) -> Dict[str, Any]:
    """Create a signed acknowledgment for successful delivery."""
    server_id = discovery_service.gossip_protocol.get_server_id() or "unknown"

    ack = MessageAcknowledgment(
        ack_type="message_received",
        message_id=message_id,
        status="delivered",
        recipient_server=server_id,
        signature=""  # Placeholder
    )

    # Sign the acknowledgment
    ack_dict = ack.model_dump(exclude={'signature'})
    signature = discovery_service.gossip_protocol.sign_message(ack_dict)

    ack_dict['signature'] = signature
    return ack_dict


def _create_rejection_ack(message_id: str, reason: str) -> Dict[str, Any]:
    """Create a signed acknowledgment for rejected/failed delivery."""
    server_id = discovery_service.gossip_protocol.get_server_id() or "unknown"

    ack = MessageAcknowledgment(
        ack_type="message_failed",
        message_id=message_id,
        status="rejected",
        recipient_server=server_id,
        error_message=reason,
        signature=""  # Placeholder
    )

    # Sign the acknowledgment
    ack_dict = ack.model_dump(exclude={'signature'})
    signature = discovery_service.gossip_protocol.sign_message(ack_dict)

    ack_dict['signature'] = signature
    return ack_dict


@app.post("/api/v1/messages/send")
async def send_federated_message(
    request: SendMessageRequest,
    background_tasks: BackgroundTasks,
    _: str = Depends(localhost_only)
) -> SendMessageResponse:
    """
    Queue and immediately attempt delivery of a federated message.

    This endpoint is localhost-only, intended to be called by local applications
    that want to send messages to users on remote Lattice servers.

    The message is:
    1. Signed with this server's private key
    2. Inserted into the message queue
    3. Immediately attempted for delivery in the background

    If immediate delivery fails, the scheduled message processor will retry
    with exponential backoff.
    """
    try:
        # Queue the message (signs and inserts into database)
        message_id = discovery_service.queue_outbound_message(
            to_address=request.to_address,
            from_address=request.from_address,
            content=request.content,
            message_type=request.message_type,
            priority=request.priority,
            metadata=request.metadata
        )

        # Trigger immediate delivery in background
        background_tasks.add_task(discovery_service.deliver_message_async, message_id)

        return SendMessageResponse(
            status="queued",
            message_id=message_id,
            immediate_delivery=True
        )

    except ValueError as e:
        logger.warning(f"Invalid send request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error queueing federated message: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/domain/verify")
async def verify_domain_availability(domain: str, server_uuid: str) -> DomainRegistrationResult:
    """
    Verify if a domain name is available for registration.

    Queries the federation network with high hop count to ensure uniqueness.
    """
    try:
        result = discovery_service.domain_registration.verify_domain_availability(
            desired_domain=domain,
            requester_uuid=server_uuid,
            max_hops=20  # High hop count for thorough verification
        )

        return result

    except Exception as e:
        logger.error(f"Error verifying domain availability: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/domain/register")
async def register_domain(request: DomainRegistrationRequest):
    """
    Register a domain name for this server.

    Verifies uniqueness across the federation before registration.
    """
    try:
        result = discovery_service.domain_registration.register_domain(
            domain=request.desired_domain,
            server_uuid=request.server_uuid,
            public_key=request.public_key,
            skip_verification=False
        )

        if not result['success']:
            raise HTTPException(
                status_code=409,
                detail=result.get('reason', 'Domain registration failed')
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering domain: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =====================================================================
# PEER IMPORT ENDPOINT - REMOVED (Future Enhancement)
# =====================================================================
#
# ORIGINAL VISION:
# Allow importing a curated "peer exchange file" (JSON) to bootstrap into
# an existing federation network quickly. Similar to Bitcoin seed nodes or
# DNS root servers - a trusted list of entry points.
#
# USE CASE:
# - New server wants to join large existing network
# - Bootstrap servers are offline or unavailable
# - Admin has trusted peer list from another source
#
# WHY REMOVED:
# The implementation was incomplete - it created peer announcements with
# empty public_key and signature fields, which fail signature verification.
# Proper implementation requires:
#   1. Fetch each peer's public key from their server (GET /api/v1/announcement)
#   2. Verify peer is reachable and responds correctly
#   3. Handle network errors, timeouts, malicious responses
#   4. Create valid announcements with proper signatures
#
# CURRENT ALTERNATIVES:
# - Bootstrap servers (configured in /etc/lattice/config.env: LATTICE_BOOTSTRAP_SERVERS)
# - Gossip protocol (peers share neighbor lists automatically)
#
# TO RE-IMPLEMENT:
# See PeerExchangeFile model in models.py and add proper key fetching/verification
# =====================================================================


@app.post("/api/v1/maintenance/update_neighbors")
async def trigger_neighbor_update(
    _: str = Depends(localhost_only),
    background_tasks: BackgroundTasks = None
):
    """
    Trigger neighbor selection update (called by scheduler, localhost only).

    This endpoint is designed to be called by the main application's
    scheduler service rather than having the discovery daemon manage its own scheduling.
    """
    try:
        background_tasks.add_task(discovery_service._update_neighbors)
        return {
            "status": "scheduled",
            "message": "Neighbor update scheduled"
        }
    except Exception as e:
        logger.error(f"Error scheduling neighbor update: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/maintenance/process_messages")
async def process_message_queue(_: str = Depends(localhost_only)):
    """
    Process pending federated messages for delivery (called by scheduler, localhost only).

    This endpoint processes messages queued in the lattice_messages table
    and attempts to deliver them to remote servers.
    """
    try:
        result = discovery_service.process_message_queue(max_messages=20)
        return {
            "status": "completed",
            **result
        }
    except Exception as e:
        logger.error(f"Error processing message queue: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/maintenance/cleanup")
async def trigger_cleanup(_: str = Depends(localhost_only)):
    """
    Trigger cleanup of stale data (called by scheduler, localhost only).

    This endpoint is designed to be called by the main application's
    scheduler service rather than having the discovery daemon manage its own scheduling.
    """
    try:
        discovery_service._cleanup_stale_data()
        return {
            "status": "completed",
            "message": "Cleanup completed"
        }
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    # Port 1113 for Lattice (all deployments)
    uvicorn.run(app, host="0.0.0.0", port=1113, log_level="info")