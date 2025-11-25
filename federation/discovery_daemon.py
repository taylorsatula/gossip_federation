"""
Discovery Daemon for MIRA Federation.

Standalone FastAPI service that handles federation discovery via gossip protocol.
Provides REST API for local tools to query federation routes.
"""

import asyncio
import logging
import random
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from clients.postgres_client import PostgresClient
from utils.timezone_utils import utc_now
from .models import (
    ServerAnnouncement,
    DomainQuery,
    DomainResponse,
    GossipMessage,
    PeerExchangeFile
)
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


class ReputationReportRequest(BaseModel):
    """Report server reputation (good/bad behavior)."""
    server_id: str
    report_type: str = Field(description="Type of report: 'success', 'failure', 'spam'")
    details: Optional[str] = None


class PeerStatus(BaseModel):
    """Status information about a peer."""
    server_id: str
    is_neighbor: bool
    trust_status: str
    reputation_score: float
    last_seen: str
    endpoints: Dict[str, str]


# =====================================================================
# Service State
# =====================================================================

class DiscoveryService:
    """Core discovery service logic."""

    def __init__(self):
        self.peer_manager = PeerManager()
        self.gossip_protocol = GossipProtocol()
        self.domain_registration = DomainRegistrationService()
        self.db = PostgresClient("mira_service")
        self.last_gossip_time = None
        self.bootstrap_servers: List[str] = []

        # Circuit breaker: Track consecutive failures per peer
        self._circuit_breaker: Dict[str, Dict[str, Any]] = {}
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
            "SELECT bootstrap_servers FROM federation_identity WHERE id = 1"
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

        logger.info("Discovery service initialized (scheduling handled by main MIRA)")

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

            self.last_gossip_time = utc_now()
            logger.info(f"Completed gossip round to {gossip_count} neighbors")

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

    def _cleanup_stale_data(self):
        """Clean up old data."""
        # Clean up stale peers
        peer_count = self.peer_manager.cleanup_stale_peers(days=30)

        # Clean up expired routes
        self.db.execute_delete(
            "DELETE FROM federation_routes WHERE expires_at < NOW()"
        )

        # Clean up old messages
        self.db.execute_delete(
            "DELETE FROM federation_messages WHERE expires_at < NOW() AND status IN ('delivered', 'failed', 'expired')"
        )

        # Clean up received message tracking (keep 7 days for debugging)
        self.db.execute_delete(
            "DELETE FROM federation_received_messages WHERE received_at < NOW() - INTERVAL '7 days'"
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
                UPDATE federation_messages
                SET status = 'pending',
                    next_attempt_at = NOW(),
                    last_status_change_at = NOW()
                WHERE status = 'sending'
                  AND last_status_change_at < NOW() - INTERVAL '5 minutes'
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
            cutoff = utc_now() - timedelta(minutes=5)
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
        Process pending messages from the federation_messages queue.

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
                FROM federation_messages
                WHERE status = 'pending'
                  AND next_attempt_at <= NOW()
                  AND expires_at > NOW()
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
        Check if circuit breaker is open for a peer.

        Args:
            server_id: Peer server ID

        Returns:
            True if circuit is closed (can send), False if open (should skip)
        """
        if server_id not in self._circuit_breaker:
            return True

        breaker = self._circuit_breaker[server_id]

        # Check if timeout expired - close circuit
        if breaker['open_until'] <= utc_now():
            logger.info(f"Circuit breaker timeout expired for {server_id} - closing circuit")
            del self._circuit_breaker[server_id]
            return True

        logger.warning(f"Circuit breaker OPEN for {server_id} - skipping delivery until {breaker['open_until']}")
        return False

    def _record_delivery_success(self, server_id: str) -> None:
        """Record successful delivery - resets circuit breaker."""
        if server_id in self._circuit_breaker:
            logger.info(f"Delivery succeeded to {server_id} - closing circuit breaker")
            del self._circuit_breaker[server_id]

    def _record_delivery_failure(self, server_id: str) -> None:
        """Record delivery failure - may open circuit breaker."""
        if server_id not in self._circuit_breaker:
            self._circuit_breaker[server_id] = {
                'failures': 1,
                'open_until': None
            }
        else:
            self._circuit_breaker[server_id]['failures'] += 1

        breaker = self._circuit_breaker[server_id]

        if breaker['failures'] >= self._circuit_breaker_threshold:
            breaker['open_until'] = utc_now() + self._circuit_breaker_timeout
            logger.error(
                f"Circuit breaker OPENED for {server_id} after {breaker['failures']} "
                f"consecutive failures - blocking until {breaker['open_until']}"
            )

    def _deliver_single_message(self, msg: Dict[str, Any]) -> None:
        """
        Deliver a single message to its destination.

        Args:
            msg: Message record from federation_messages table

        Raises:
            Exception: If delivery fails
        """
        message_id = msg['message_id']
        to_domain = msg['to_domain']

        # Resolve recipient domain first to get server_id
        peer = self.peer_manager.get_peer_by_domain(to_domain)

        if not peer:
            raise ValueError(f"No route to domain: {to_domain}")

        # Use server_id for consistent circuit breaker and reputation tracking
        server_id = peer['server_id']

        # Check circuit breaker using resolved server_id
        if not self._check_circuit_breaker(server_id):
            raise ValueError(f"Circuit breaker open for {server_id}")

        if peer['trust_status'] == 'blocked':
            self._fail_message_permanently(message_id, "Recipient server is blocked")
            return

        # Update status to sending
        self.db.execute_update(
            "UPDATE federation_messages SET status = 'sending', last_status_change_at = NOW() WHERE message_id = %s",
            (message_id,)
        )

        # Get federation endpoint
        endpoints = peer.get('endpoints', {})
        federation_url = endpoints.get('federation')

        if not federation_url:
            raise ValueError(f"No federation endpoint for {server_id}")

        # Construct federated message
        from .models import FederatedMessage
        message = FederatedMessage(
            message_id=msg['message_id'],
            message_type=msg['message_type'],
            from_address=msg['from_address'],
            to_address=msg['to_address'],
            content=msg['content'],
            priority=msg['priority'],
            timestamp=msg['created_at'].isoformat(),
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
            # Mark as delivered and reset circuit breaker
            self._record_delivery_success(server_id)
            # Update peer reputation positively
            self.peer_manager.update_peer_reputation(server_id, delta=0.05)
            self._complete_message(message_id)
            logger.info(f"Message {message_id} delivered to {server_id}")
        else:
            self._record_delivery_failure(server_id)
            # Update peer reputation negatively
            self.peer_manager.update_peer_reputation(server_id, delta=-0.1)
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
            next_attempt = utc_now() + timedelta(minutes=backoff_minutes)

            self.db.execute_update(
                """
                UPDATE federation_messages
                SET status = 'pending',
                    attempt_count = %s,
                    next_attempt_at = %s,
                    last_error = %s,
                    error_count = error_count + 1,
                    last_status_change_at = NOW()
                WHERE message_id = %s
                """,
                (attempt_count, next_attempt, error, message_id)
            )

            logger.info(f"Message {message_id} retry scheduled for {next_attempt} (attempt {attempt_count}/{max_attempts})")

    def _complete_message(self, message_id: str) -> None:
        """Mark message as successfully delivered."""
        self.db.execute_update(
            """
            UPDATE federation_messages
            SET status = 'delivered',
                delivered_at = NOW(),
                last_status_change_at = NOW()
            WHERE message_id = %s
            """,
            (message_id,)
        )

    def _fail_message_permanently(self, message_id: str, error: str) -> None:
        """Mark message as permanently failed."""
        self.db.execute_update(
            """
            UPDATE federation_messages
            SET status = 'failed',
                last_error = %s,
                last_status_change_at = NOW()
            WHERE message_id = %s
            """,
            (error, message_id)
        )

        logger.error(f"Message {message_id} permanently failed: {error}")


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
    title="MIRA Discovery Daemon",
    description="Federation discovery service for MIRA pager system",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for local access
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# =====================================================================
# API Endpoints
# =====================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "discovery_daemon",
        "server_id": discovery_service.gossip_protocol.get_server_id(),
        "last_gossip": discovery_service.last_gossip_time.isoformat() if discovery_service.last_gossip_time else None
    }


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
            time_since = (utc_now() - discovery_service.last_gossip_time).total_seconds()
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
    active_only: bool = True,
    include_blocked: bool = False
) -> List[PeerStatus]:
    """Get list of known peer servers."""
    try:
        query = """
            SELECT server_id, is_neighbor, trust_status, reputation_score,
                   last_seen_at, endpoints
            FROM federation_peers
            WHERE 1=1
        """
        params = []

        if active_only:
            query += " AND last_seen_at > %s"
            params.append(utc_now() - timedelta(days=7))

        if not include_blocked:
            query += " AND trust_status != 'blocked'"

        query += " ORDER BY is_neighbor DESC, reputation_score DESC"

        peers = discovery_service.db.execute_query(query, tuple(params))

        return [
            PeerStatus(
                server_id=p['server_id'],
                is_neighbor=p['is_neighbor'],
                trust_status=p['trust_status'],
                reputation_score=p['reputation_score'],
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
        discovery_service._processed_queries[query.query_id] = utc_now()

        # Process the query using gossip protocol
        response = discovery_service.gossip_protocol._handle_domain_query(
            query,
            from_server=query.requester
        )

        if response:
            # We have an answer (either found or not found after max hops)
            return response

        # No answer and hops remaining - forward to our neighbors
        query.max_hops -= 1
        neighbors = discovery_service.peer_manager.get_active_neighbors()

        import httpx
        with httpx.Client(timeout=3.0) as client:
            for neighbor in neighbors:
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
        query_id = f"QUERY-{int(utc_now().timestamp() * 1000)}"
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

        # Query neighbors (they will forward if needed)
        import httpx
        with httpx.Client(timeout=5.0) as client:
            for neighbor in neighbors:
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


@app.post("/api/v1/reputation/report")
async def report_reputation(report: ReputationReportRequest):
    """Report server behavior for reputation tracking."""
    try:
        # Map report type to reputation delta
        delta_map = {
            "success": 0.1,      # Successful message delivery
            "failure": -0.05,    # Failed delivery
            "spam": -0.3,        # Spam or abuse
            "timeout": -0.1,     # Timeout/unresponsive
        }

        delta = delta_map.get(report.report_type, 0.0)
        if delta == 0.0:
            raise ValueError(f"Unknown report type: {report.report_type}")

        discovery_service.peer_manager.update_peer_reputation(report.server_id, delta)

        return {
            "status": "accepted",
            "server_id": report.server_id,
            "reputation_change": delta
        }

    except Exception as e:
        logger.error(f"Error reporting reputation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/reputation/{server_id}")
async def get_reputation(server_id: str):
    """Get reputation score for a specific server."""
    try:
        result = discovery_service.db.execute_single(
            """
            SELECT reputation_score, trust_status, last_seen_at
            FROM federation_peers
            WHERE server_id = %s
            """,
            (server_id,)
        )

        if not result:
            raise HTTPException(status_code=404, detail="Server not found")

        return {
            "server_id": server_id,
            "reputation_score": result['reputation_score'],
            "trust_status": result['trust_status'],
            "last_seen": result['last_seen_at'].isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting reputation for {server_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/gossip/receive")
async def receive_gossip(message: GossipMessage):
    """Receive gossip message from another server."""
    try:
        # Get sender's existing peer record
        sender = discovery_service.db.execute_single(
            "SELECT public_key, server_uuid FROM federation_peers WHERE server_id = %s",
            (message.from_server,)
        )

        # Rate limiting: 100 gossip messages per minute per peer
        if sender:
            rate_check = discovery_service.db.execute_single(
                """
                UPDATE federation_peers
                SET query_count = CASE
                        WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < NOW()
                        THEN 1
                        ELSE query_count + 1
                    END,
                    rate_limit_reset_at = CASE
                        WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < NOW()
                        THEN NOW() + INTERVAL '1 minute'
                        ELSE rate_limit_reset_at
                    END
                WHERE server_id = %s
                RETURNING query_count
                """,
                (message.from_server,)
            )
            if rate_check and rate_check['query_count'] > 100:
                logger.warning(f"Rate limit exceeded for gossip from {message.from_server}")
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
                # This prevents arbitrary servers from joining without introduction
                bootstrap_domains = [url.split('//')[1].split('/')[0].split(':')[0] for url in discovery_service.bootstrap_servers]
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
        else:
            # For non-announcement messages, sender must be known
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
# - New MIRA server wants to join large existing federation
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
# - Bootstrap servers (configured in Vault: FEDERATION_BOOTSTRAP_SERVERS)
# - Gossip protocol (peers share neighbor lists automatically)
#
# TO RE-IMPLEMENT:
# See PeerExchangeFile model in models.py and add proper key fetching/verification
# =====================================================================


@app.post("/api/v1/maintenance/update_neighbors")
async def trigger_neighbor_update(background_tasks: BackgroundTasks):
    """
    Trigger neighbor selection update (called by main MIRA scheduler).

    This endpoint is designed to be called by the main MIRA application's
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
async def process_message_queue():
    """
    Process pending federated messages for delivery (called by main MIRA scheduler).

    This endpoint processes messages queued in the federation_messages table
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
async def trigger_cleanup():
    """
    Trigger cleanup of stale data (called by main MIRA scheduler).

    This endpoint is designed to be called by the main MIRA application's
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
    # Port 8302 for WAN gossip (use 8301 for LAN deployments)
    uvicorn.run(app, host="0.0.0.0", port=8302, log_level="info")