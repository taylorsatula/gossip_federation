"""
Peer management for federation gossip protocol.

Handles neighbor selection, peer scoring, and connection management.
"""

import logging
import random
from datetime import timedelta
from typing import List, Dict, Any, Optional

from clients.postgres_client import PostgresClient
from utils.timezone_utils import utc_now
from .models import ServerAnnouncement

logger = logging.getLogger(__name__)


class PeerManager:
    """Manages federation peer relationships and neighbor selection."""

    def __init__(self, max_neighbors: int = 8):
        """
        Initialize peer manager.

        Args:
            max_neighbors: Maximum number of active gossip neighbors
        """
        self.max_neighbors = max_neighbors
        self.db = PostgresClient("mira_service")
        logger.info(f"PeerManager initialized with max_neighbors={max_neighbors}")

    def add_or_update_peer(self, announcement: ServerAnnouncement) -> bool:
        """
        Add or update a peer based on server announcement.

        Handles collision detection: if server_id already exists but server_uuid differs,
        this indicates a domain name collision. The announcement is rejected.

        Args:
            announcement: Server announcement message

        Returns:
            True if peer was added/updated successfully
        """
        try:
            # Check if peer exists by UUID first (permanent identity)
            existing_by_uuid = self.db.execute_single(
                "SELECT id, server_id, trust_status FROM federation_peers WHERE server_uuid = %(server_uuid)s",
                {'server_uuid': announcement.server_uuid}
            )

            # Check if server_id is already taken
            existing_by_id = self.db.execute_single(
                "SELECT id, server_uuid, trust_status FROM federation_peers WHERE server_id = %(server_id)s",
                {'server_id': announcement.server_id}
            )

            # Collision detection: same server_id but different UUIDs
            if existing_by_id and existing_by_id['server_uuid'] != announcement.server_uuid:
                logger.error(
                    f"COLLISION DETECTED: server_id '{announcement.server_id}' claimed by UUID {announcement.server_uuid} "
                    f"but already owned by UUID {existing_by_id['server_uuid']}"
                )
                return False

            # Check blocklist
            if existing_by_id and existing_by_id['trust_status'] == 'blocked':
                logger.warning(f"Ignoring announcement from blocked peer: {announcement.server_id}")
                return False

            peer_data = {
                'server_id': announcement.server_id,
                'server_uuid': announcement.server_uuid,
                'public_key': announcement.public_key,
                'capabilities': announcement.capabilities.model_dump(),
                'endpoints': announcement.endpoints.model_dump(),
                'last_seen_at': utc_now(),
                'last_announcement': announcement.model_dump()
            }

            if existing_by_uuid:
                # Update existing peer (UUID match means it's the same server, possibly renamed)
                self.db.execute_update(
                    """
                    UPDATE federation_peers
                    SET server_id = %(server_id)s,
                        public_key = %(public_key)s,
                        capabilities = %(capabilities)s::jsonb,
                        endpoints = %(endpoints)s::jsonb,
                        last_seen_at = %(last_seen_at)s,
                        last_announcement = %(last_announcement)s::jsonb
                    WHERE server_uuid = %(server_uuid)s
                    """,
                    {**peer_data, 'last_announcement': announcement.model_dump()}
                )
                logger.info(f"Updated peer: {announcement.server_id} (UUID: {announcement.server_uuid})")
            else:
                # Add new peer
                peer_data['first_seen_at'] = peer_data['last_seen_at']
                self.db.execute_insert(
                    """
                    INSERT INTO federation_peers
                    (server_id, server_uuid, public_key, capabilities, endpoints,
                     first_seen_at, last_seen_at, last_announcement)
                    VALUES (%(server_id)s, %(server_uuid)s, %(public_key)s, %(capabilities)s::jsonb,
                            %(endpoints)s::jsonb, %(first_seen_at)s, %(last_seen_at)s,
                            %(last_announcement)s::jsonb)
                    """,
                    {**peer_data, 'last_announcement': announcement.model_dump()}
                )
                logger.info(f"Added new peer: {announcement.server_id} (UUID: {announcement.server_uuid})")

            return True

        except Exception as e:
            logger.error(f"Error adding/updating peer {announcement.server_id}: {e}")
            return False

    def get_active_neighbors(self) -> List[Dict[str, Any]]:
        """
        Get list of active neighbor peers for gossip.

        Returns:
            List of neighbor peer records
        """
        try:
            neighbors = self.db.execute_query(
                """
                SELECT server_id, endpoints, public_key, last_seen_at
                FROM federation_peers
                WHERE is_neighbor = true
                  AND trust_status != 'blocked'
                  AND last_seen_at > %(cutoff_time)s
                ORDER BY neighbor_score DESC, last_seen_at DESC
                """,
                {'cutoff_time': utc_now() - timedelta(hours=24)}
            )

            return neighbors

        except Exception as e:
            logger.error(f"Error getting active neighbors: {e}")
            return []

    def select_new_neighbors(self) -> None:
        """Select new neighbors based on scoring criteria."""
        try:
            # Get current neighbor count
            current_neighbors = self.db.execute_single(
                "SELECT COUNT(*) as count FROM federation_peers WHERE is_neighbor = true"
            )
            current_count = current_neighbors['count'] if current_neighbors else 0

            if current_count >= self.max_neighbors:
                # Possibly replace low-scoring neighbors
                self._replace_poor_neighbors()
            else:
                # Add new neighbors
                needed = self.max_neighbors - current_count
                self._add_new_neighbors(needed)

        except Exception as e:
            logger.error(f"Error selecting new neighbors: {e}")

    def _add_new_neighbors(self, count: int) -> None:
        """Add new neighbors from available peers."""
        try:
            # Get candidate peers (not blocked, recently seen, not already neighbors)
            candidates = self.db.execute_query(
                """
                SELECT server_id,
                       reputation_score,
                       EXTRACT(EPOCH FROM (NOW() - last_seen_at))/3600 as hours_ago
                FROM federation_peers
                WHERE is_neighbor = false
                  AND trust_status != 'blocked'
                  AND last_seen_at > %(cutoff_time)s
                ORDER BY reputation_score DESC, last_seen_at DESC
                LIMIT %(limit_count)s
                """,
                {'cutoff_time': utc_now() - timedelta(days=7), 'limit_count': count * 2}
            )

            if not candidates:
                logger.info("No eligible peers to add as neighbors")
                return

            # Randomly select from top candidates (introduces diversity)
            selected = random.sample(candidates, min(count, len(candidates)))

            for peer in selected:
                # Calculate neighbor score based on reputation and recency
                # Clamp hours_ago to non-negative (clock skew protection)
                hours_ago = max(0, peer['hours_ago'])
                recency_factor = max(0.1, 1.0 - (hours_ago / 168))  # Decay over 1 week
                neighbor_score = peer['reputation_score'] * 0.7 + recency_factor * 0.3

                self.db.execute_update(
                    """
                    UPDATE federation_peers
                    SET is_neighbor = true,
                        neighbor_score = %(neighbor_score)s
                    WHERE server_id = %(server_id)s
                    """,
                    {'neighbor_score': neighbor_score, 'server_id': peer['server_id']}
                )
                logger.info(f"Added neighbor: {peer['server_id']} (score: {neighbor_score:.2f})")

        except Exception as e:
            logger.error(f"Error adding new neighbors: {e}")

    def _replace_poor_neighbors(self) -> None:
        """Replace low-scoring neighbors with better candidates."""
        try:
            # Get worst performing neighbor
            worst_neighbor = self.db.execute_single(
                """
                SELECT server_id, neighbor_score
                FROM federation_peers
                WHERE is_neighbor = true
                ORDER BY neighbor_score ASC
                LIMIT 1
                """
            )

            if not worst_neighbor:
                return

            # Get best non-neighbor candidate
            best_candidate = self.db.execute_single(
                """
                SELECT server_id, reputation_score
                FROM federation_peers
                WHERE is_neighbor = false
                  AND trust_status != 'blocked'
                  AND last_seen_at > %(cutoff_time)s
                ORDER BY reputation_score DESC
                LIMIT 1
                """,
                {'cutoff_time': utc_now() - timedelta(days=7)}
            )

            if not best_candidate:
                return

            # Replace if candidate is significantly better
            if best_candidate['reputation_score'] > worst_neighbor['neighbor_score'] + 0.2:
                # Remove old neighbor
                self.db.execute_update(
                    "UPDATE federation_peers SET is_neighbor = false WHERE server_id = %(server_id)s",
                    {'server_id': worst_neighbor['server_id']}
                )

                # Add new neighbor
                self.db.execute_update(
                    """
                    UPDATE federation_peers
                    SET is_neighbor = true,
                        neighbor_score = %(neighbor_score)s
                    WHERE server_id = %(server_id)s
                    """,
                    {'neighbor_score': best_candidate['reputation_score'], 'server_id': best_candidate['server_id']}
                )

                logger.info(
                    f"Replaced neighbor {worst_neighbor['server_id']} "
                    f"with {best_candidate['server_id']}"
                )

        except Exception as e:
            logger.error(f"Error replacing poor neighbors: {e}")

    def get_peer_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Get peer information for a specific domain.

        Args:
            domain: Domain to look up

        Returns:
            Peer record or None if not found
        """
        try:
            # First check if it matches a server_id directly
            peer = self.db.execute_single(
                """
                SELECT server_id, endpoints, public_key, trust_status
                FROM federation_peers
                WHERE server_id = %s
                """,
                (domain.lower(),)
            )

            if peer:
                return peer

            # Check routing cache
            route = self.db.execute_single(
                """
                SELECT p.server_id, p.endpoints, p.public_key, p.trust_status
                FROM federation_routes r
                JOIN federation_peers p ON r.server_id = p.server_id
                WHERE r.domain = %s
                  AND r.expires_at > NOW()
                ORDER BY r.confidence DESC
                LIMIT 1
                """,
                (domain.lower(),)
            )

            return route

        except Exception as e:
            logger.error(f"Error getting peer by domain {domain}: {e}")
            return None

    def update_peer_reputation(self, server_id: str, delta: float) -> None:
        """
        Update peer reputation score.

        Args:
            server_id: Server to update
            delta: Amount to change reputation by (-1.0 to 1.0)
        """
        try:
            self.db.execute_update(
                """
                UPDATE federation_peers
                SET reputation_score = GREATEST(0.0, LEAST(1.0, reputation_score + %(delta)s))
                WHERE server_id = %(server_id)s
                """,
                {'delta': delta, 'server_id': server_id}
            )

            # Update neighbor score if this is a neighbor (include recency)
            self.db.execute_update(
                """
                UPDATE federation_peers
                SET neighbor_score = reputation_score * 0.7 +
                    (CASE
                        WHEN EXTRACT(EPOCH FROM (NOW() - last_seen_at)) / 3600 < 168
                        THEN GREATEST(0.1, 1.0 - (EXTRACT(EPOCH FROM (NOW() - last_seen_at)) / 3600 / 168))
                        ELSE 0.1
                    END) * 0.3
                WHERE server_id = %(server_id)s AND is_neighbor = true
                """,
                {'server_id': server_id}
            )

        except Exception as e:
            logger.error(f"Error updating reputation for {server_id}: {e}")

    def is_blocked(self, server_id: str) -> bool:
        """Check if a server is blocked."""
        try:
            # Check peer blocklist
            peer_blocked = self.db.execute_single(
                "SELECT 1 FROM federation_peers WHERE server_id = %s AND trust_status = 'blocked'",
                (server_id,)
            )

            if peer_blocked:
                return True

            # Check general blocklist
            blocked = self.db.execute_single(
                """
                SELECT 1 FROM federation_blocklist
                WHERE blocked_identifier = %s
                  AND block_type IN ('server', 'domain')
                  AND (expires_at IS NULL OR expires_at > NOW())
                """,
                (server_id,)
            )

            return bool(blocked)

        except Exception as e:
            logger.error(f"Error checking if {server_id} is blocked: {e}")
            return False  # Fail open for now

    def cleanup_stale_peers(self, days: int = 30) -> int:
        """
        Clean up peers not seen in specified days.

        Args:
            days: Number of days of inactivity before cleanup

        Returns:
            Number of peers cleaned up
        """
        try:
            result = self.db.execute_returning(
                """
                UPDATE federation_peers
                SET is_neighbor = false
                WHERE last_seen_at < %(cutoff_time)s
                  AND is_neighbor = true
                RETURNING server_id
                """,
                {'cutoff_time': utc_now() - timedelta(days=days)}
            )

            count = len(result) if result else 0
            if count > 0:
                logger.info(f"Cleaned up {count} stale neighbors")

            # Also delete peers not seen in 90+ days (prevents unbounded table growth)
            deleted = self.db.execute_returning(
                """
                DELETE FROM federation_peers
                WHERE last_seen_at < %(cutoff_time)s
                RETURNING server_id
                """,
                {'cutoff_time': utc_now() - timedelta(days=90)}
            )

            deleted_count = len(deleted) if deleted else 0
            if deleted_count > 0:
                logger.info(f"Deleted {deleted_count} dead peers (not seen in 90+ days)")

            return count + deleted_count

        except Exception as e:
            logger.error(f"Error cleaning up stale peers: {e}")
            return 0