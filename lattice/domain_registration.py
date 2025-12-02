"""
Domain registration and verification for Lattice.

Implements the protocol for verifying domain name uniqueness before registration.
"""

import logging
import time
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from .sqlite_client import SQLiteClient
from .models import DomainQuery, DomainResponse
from .peer_manager import PeerManager
from .gossip_protocol import GossipProtocol

logger = logging.getLogger(__name__)


class DomainRegistrationRequest(BaseModel):
    """Request to register a domain name in the federation."""
    desired_domain: str = Field(description="Domain name to register (e.g., 'myserver')")
    server_uuid: str = Field(description="Server's permanent UUID")
    public_key: str = Field(description="Server's public key")


class DomainRegistrationResult(BaseModel):
    """Result of domain registration verification."""
    domain: str
    available: bool
    collision_detected: bool = False
    existing_owner_uuid: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in result (based on network coverage)")
    servers_queried: int = 0
    message: str


class DomainRegistrationService:
    """Handles domain name registration and uniqueness verification."""

    def __init__(self):
        self.db = SQLiteClient()
        self.peer_manager = PeerManager()
        self.gossip_protocol = GossipProtocol()

    def verify_domain_availability(
        self,
        desired_domain: str,
        requester_uuid: str,
        max_hops: int = 20
    ) -> DomainRegistrationResult:
        """
        Verify if a domain name is available for registration.

        Queries the federation network with high hop count to maximize coverage
        and confidence that the domain is unique.

        Args:
            desired_domain: Domain name to check
            requester_uuid: UUID of server requesting the domain
            max_hops: Maximum hops for query propagation (higher = more thorough)

        Returns:
            DomainRegistrationResult with availability status and confidence
        """
        logger.info(
            f"Verifying domain '{desired_domain}' availability with max_hops={max_hops}"
        )

        # Check if we already know about this domain
        existing_peer = self.peer_manager.get_peer_by_domain(desired_domain)

        if existing_peer:
            # Domain is already known locally
            is_us = existing_peer.get('server_uuid') == requester_uuid

            if is_us:
                # This is our own domain
                return DomainRegistrationResult(
                    domain=desired_domain,
                    available=True,
                    message=f"Domain '{desired_domain}' is already registered to you"
                )
            else:
                # Domain belongs to someone else
                return DomainRegistrationResult(
                    domain=desired_domain,
                    available=False,
                    collision_detected=True,
                    existing_owner_uuid=existing_peer.get('server_uuid'),
                    confidence=1.0,
                    message=f"Domain '{desired_domain}' is already registered to another server"
                )

        # Query the network
        query = DomainQuery(
            query_id=f"REG-{int(time.time() * 1000)}",
            domain=desired_domain,
            requester=requester_uuid,
            max_hops=max_hops
        )

        # Get active neighbors
        neighbors = self.peer_manager.get_active_neighbors()
        servers_queried = 0
        found_owner = None

        if not neighbors:
            logger.warning("No neighbors available for domain verification")
            return DomainRegistrationResult(
                domain=desired_domain,
                available=True,  # Assume available if no neighbors
                confidence=0.0,  # But with zero confidence
                servers_queried=0,
                message=f"No neighbors available to verify '{desired_domain}' - proceeding with low confidence"
            )

        # Track network visibility with COUNT instead of full table scans
        peer_count_before = self.db.execute_single(
            "SELECT COUNT(*) as count FROM lattice_peers"
        )['count']

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
                        timeout=15.0  # Long timeout for thorough forwarding
                    )

                    servers_queried += 1

                    if response.status_code == 200:
                        result = DomainResponse(**response.json())
                        if result.found:
                            # Someone has this domain
                            found_owner = result.server_id
                            logger.warning(
                                f"Domain '{desired_domain}' already claimed by {result.server_id}"
                            )
                            break

                except Exception as e:
                    logger.debug(f"Query to {neighbor['server_id']} failed: {e}")
                    continue

        # Check network visibility after queries using COUNT
        peer_count_after = self.db.execute_single(
            "SELECT COUNT(*) as count FROM lattice_peers"
        )['count']

        # Calculate confidence based on network visibility saturation
        # High confidence = few new peers discovered (full visibility)
        # Low confidence = many new peers discovered (incomplete visibility)

        total_neighbors = len(neighbors)
        if total_neighbors == 0:
            confidence = 0.0
        else:
            # How many new peers were discovered during verification?
            new_peer_count = peer_count_after - peer_count_before

            # Confidence inversely proportional to new discoveries
            # No new peers = full visibility = confidence 0.95
            # Many new peers = limited visibility = confidence 0.3-0.5

            if new_peer_count == 0:
                # No new peers discovered - we have full visibility
                base_confidence = 0.95
            elif new_peer_count <= 2:
                # Very few new peers - good visibility
                base_confidence = 0.8
            elif new_peer_count <= 5:
                # Some new peers - moderate visibility
                base_confidence = 0.6
            else:
                # Many new peers - limited visibility
                base_confidence = 0.4

            # Adjust by how many servers we successfully queried
            query_coverage = servers_queried / total_neighbors
            confidence = base_confidence * query_coverage

            logger.info(
                f"Domain verification visibility: {new_peer_count} new peers discovered, "
                f"{servers_queried}/{total_neighbors} servers queried, confidence={confidence:.2f}"
            )

        if found_owner:
            return DomainRegistrationResult(
                domain=desired_domain,
                available=False,
                collision_detected=True,
                existing_owner_uuid=found_owner,
                confidence=confidence,
                servers_queried=servers_queried,
                message=f"Domain '{desired_domain}' is already registered in the federation"
            )

        return DomainRegistrationResult(
            domain=desired_domain,
            available=True,
            confidence=confidence,
            servers_queried=servers_queried,
            message=f"Domain '{desired_domain}' appears available (confidence: {confidence:.2f}, queried {servers_queried} servers)"
        )

    def register_domain(
        self,
        domain: str,
        server_uuid: str,
        public_key: str,
        skip_verification: bool = False,
        allow_low_confidence: bool = False
    ) -> Dict[str, Any]:
        """
        Register a domain for this server.

        Args:
            domain: Domain name to register
            server_uuid: Server's permanent UUID
            public_key: Server's public key
            skip_verification: Skip network verification (ONLY use for initial setup
                              when no peers exist yet, or for testing. Creates risk
                              of domain collision in production networks)
            allow_low_confidence: Allow registration even if confidence < 0.8
                                 (manual override when network visibility is limited)

        Returns:
            Dict with registration status and details
        """
        if not skip_verification:
            # Verify domain availability first
            verification = self.verify_domain_availability(domain, server_uuid)

            if not verification.available:
                return {
                    "success": False,
                    "domain": domain,
                    "reason": "Domain already registered",
                    "verification": verification.model_dump()
                }

            if verification.confidence < 0.8:
                if not allow_low_confidence:
                    logger.error(
                        f"Domain '{domain}' registration blocked - confidence {verification.confidence:.2f} < 0.8 threshold. "
                        f"Network visibility insufficient. Use allow_low_confidence=True to override."
                    )
                    return {
                        "success": False,
                        "reason": "Insufficient confidence - network visibility too low",
                        "confidence": verification.confidence,
                        "threshold": 0.8,
                        "verification": verification.model_dump()
                    }
                else:
                    logger.warning(
                        f"Registering domain '{domain}' with low confidence ({verification.confidence:.2f}) - manual override enabled"
                    )

        # Register in local database
        try:
            # Check if identity already exists
            existing = self.db.execute_single(
                "SELECT server_id, server_uuid FROM lattice_identity WHERE id = 1"
            )

            if existing:
                # Identity already exists
                logger.error(
                    f"Cannot register domain '{domain}': federation identity already exists "
                    f"(current: {existing['server_id']}, UUID: {existing['server_uuid']})"
                )
                return {
                    "success": False,
                    "domain": domain,
                    "reason": f"Federation identity already registered as '{existing['server_id']}'. "
                             "Cannot register new domain without destroying existing identity."
                }

            # Insert new identity
            from .secrets import get_private_key_path
            self.db.execute_insert(
                """
                INSERT INTO lattice_identity (id, server_id, server_uuid, private_key_path, public_key, fingerprint)
                VALUES (1, %(server_id)s, %(server_uuid)s, %(private_key_path)s, %(public_key)s, %(fingerprint)s)
                """,
                {
                    'server_id': domain,
                    'server_uuid': server_uuid,
                    'private_key_path': str(get_private_key_path()),
                    'public_key': public_key,
                    'fingerprint': self.gossip_protocol.generate_fingerprint(public_key)
                }
            )

            logger.info(f"Registered domain '{domain}' with UUID {server_uuid}")

            return {
                "success": True,
                "domain": domain,
                "server_uuid": server_uuid,
                "message": f"Domain '{domain}' registered successfully"
            }

        except Exception as e:
            logger.error(f"Error registering domain: {e}")
            return {
                "success": False,
                "domain": domain,
                "reason": f"Database error: {e}"
            }