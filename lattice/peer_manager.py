"""
Peer management for federation gossip protocol.

Handles neighbor selection and connection management.

NOTE: Reputation scoring was considered but removed as premature optimization.
If spam/abuse becomes a problem in the future, consider adding:
- reputation_score column (0.0-1.0) updated on delivery success/failure
- neighbor_score = reputation * 0.7 + recency * 0.3
- Reputation-weighted neighbor selection
See git history for original implementation.
"""

import logging
import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

from .sqlite_client import SQLiteClient
from .models import ServerAnnouncement, KeyRotation, IdentityRevocation

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
        self.db = SQLiteClient()
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
            # Check if UUID is revoked (cyanide pill)
            revoked = self.db.execute_single(
                "SELECT 1 FROM lattice_revocations WHERE server_uuid = %(uuid)s",
                {'uuid': announcement.server_uuid}
            )
            if revoked:
                logger.warning(f"Rejecting announcement from revoked UUID: {announcement.server_uuid}")
                return False

            # Check if peer exists by UUID first (permanent identity)
            # Use FOR UPDATE to prevent race conditions during collision check
            existing_by_uuid = self.db.execute_single(
                "SELECT id, server_id, trust_status FROM lattice_peers WHERE server_uuid = %(server_uuid)s FOR UPDATE",
                {'server_uuid': announcement.server_uuid}
            )

            # Check if server_id is already taken
            existing_by_id = self.db.execute_single(
                "SELECT id, server_uuid, trust_status FROM lattice_peers WHERE server_id = %(server_id)s FOR UPDATE",
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

            import json
            import uuid as uuid_module
            last_seen = datetime.now(timezone.utc).isoformat()
            peer_data = {
                'server_id': announcement.server_id,
                'server_uuid': announcement.server_uuid,
                'public_key': announcement.public_key,
                'capabilities': json.dumps(announcement.capabilities.model_dump()),
                'endpoints': json.dumps(announcement.endpoints.model_dump()),
                'last_seen_at': last_seen,
                'last_announcement': json.dumps(announcement.model_dump())
            }

            if existing_by_uuid:
                # Update existing peer (UUID match means it's the same server, possibly renamed)
                self.db.execute_update(
                    """
                    UPDATE lattice_peers
                    SET server_id = %(server_id)s,
                        public_key = %(public_key)s,
                        capabilities = %(capabilities)s,
                        endpoints = %(endpoints)s,
                        last_seen_at = %(last_seen_at)s,
                        last_announcement = %(last_announcement)s
                    WHERE server_uuid = %(server_uuid)s
                    """,
                    peer_data
                )
                logger.info(f"Updated peer: {announcement.server_id} (UUID: {announcement.server_uuid})")
            else:
                # Add new peer
                peer_data['id'] = str(uuid_module.uuid4())
                peer_data['first_seen_at'] = last_seen
                self.db.execute_insert(
                    """
                    INSERT INTO lattice_peers
                    (id, server_id, server_uuid, public_key, capabilities, endpoints,
                     first_seen_at, last_seen_at, last_announcement)
                    VALUES (%(id)s, %(server_id)s, %(server_uuid)s, %(public_key)s, %(capabilities)s,
                            %(endpoints)s, %(first_seen_at)s, %(last_seen_at)s,
                            %(last_announcement)s)
                    """,
                    peer_data
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
            cutoff_time = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            neighbors = self.db.execute_query(
                """
                SELECT server_id, endpoints, public_key, last_seen_at
                FROM lattice_peers
                WHERE is_neighbor = 1
                  AND trust_status != 'blocked'
                  AND last_seen_at > %(cutoff_time)s
                ORDER BY last_seen_at DESC
                """,
                {'cutoff_time': cutoff_time}
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
                "SELECT COUNT(*) as count FROM lattice_peers WHERE is_neighbor = 1"
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
        """Add new neighbors from available peers (random selection from recent peers)."""
        try:
            # Get all candidate peers (not blocked, recently seen, not already neighbors)
            cutoff_time = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            candidates = self.db.execute_query(
                """
                SELECT server_id
                FROM lattice_peers
                WHERE is_neighbor = 0
                  AND trust_status != 'blocked'
                  AND last_seen_at > %(cutoff_time)s
                """,
                {'cutoff_time': cutoff_time}
            )

            if not candidates:
                logger.info("No eligible peers to add as neighbors")
                return

            # Randomly select from all eligible candidates (pure random for network diversity)
            selected = random.sample(candidates, min(count, len(candidates)))

            for peer in selected:
                self.db.execute_update(
                    """
                    UPDATE lattice_peers
                    SET is_neighbor = 1
                    WHERE server_id = %(server_id)s
                    """,
                    {'server_id': peer['server_id']}
                )
                logger.info(f"Added neighbor: {peer['server_id']}")

        except Exception as e:
            logger.error(f"Error adding new neighbors: {e}")

    def _replace_poor_neighbors(self) -> None:
        """
        Occasionally rotate a random neighbor for network diversity.

        With random neighbor selection, we still want some rotation to discover
        new peers and maintain network health. Randomly replace one neighbor
        with another eligible peer.
        """
        try:
            # Get a random current neighbor
            current_neighbor = self.db.execute_single(
                """
                SELECT server_id
                FROM lattice_peers
                WHERE is_neighbor = 1
                ORDER BY RANDOM()
                LIMIT 1
                """
            )

            if not current_neighbor:
                return

            # Get a random non-neighbor candidate
            cutoff_time = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
            candidate = self.db.execute_single(
                """
                SELECT server_id
                FROM lattice_peers
                WHERE is_neighbor = 0
                  AND trust_status != 'blocked'
                  AND last_seen_at > %(cutoff_time)s
                ORDER BY RANDOM()
                LIMIT 1
                """,
                {'cutoff_time': cutoff_time}
            )

            if not candidate:
                return

            # Swap them (20% chance to actually rotate for stability)
            if random.random() < 0.2:
                # Remove old neighbor
                self.db.execute_update(
                    "UPDATE lattice_peers SET is_neighbor = 0 WHERE server_id = %(server_id)s",
                    {'server_id': current_neighbor['server_id']}
                )

                # Add new neighbor
                self.db.execute_update(
                    "UPDATE lattice_peers SET is_neighbor = 1 WHERE server_id = %(server_id)s",
                    {'server_id': candidate['server_id']}
                )

                logger.info(
                    f"Rotated neighbor {current_neighbor['server_id']} "
                    f"with {candidate['server_id']}"
                )

        except Exception as e:
            logger.error(f"Error rotating neighbors: {e}")

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
                FROM lattice_peers
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
                FROM lattice_routes r
                JOIN lattice_peers p ON r.server_id = p.server_id
                WHERE r.domain = %s
                  AND r.expires_at > datetime('now')
                ORDER BY r.confidence DESC
                LIMIT 1
                """,
                (domain.lower(),)
            )

            return route

        except Exception as e:
            logger.error(f"Error getting peer by domain {domain}: {e}")
            return None

    def is_blocked(self, server_id: str) -> bool:
        """Check if a server is blocked."""
        try:
            # Check peer blocklist
            peer_blocked = self.db.execute_single(
                "SELECT 1 FROM lattice_peers WHERE server_id = %s AND trust_status = 'blocked'",
                (server_id,)
            )

            if peer_blocked:
                return True

            # Check general blocklist
            blocked = self.db.execute_single(
                """
                SELECT 1 FROM lattice_blocklist
                WHERE blocked_identifier = %s
                  AND block_type IN ('server', 'domain')
                  AND (expires_at IS NULL OR expires_at > datetime('now'))
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
            cutoff_time = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            result = self.db.execute_returning(
                """
                UPDATE lattice_peers
                SET is_neighbor = 0
                WHERE last_seen_at < %(cutoff_time)s
                  AND is_neighbor = 1
                RETURNING server_id
                """,
                {'cutoff_time': cutoff_time}
            )

            count = len(result) if result else 0
            if count > 0:
                logger.info(f"Cleaned up {count} stale neighbors")

            # Also delete peers not seen in 90+ days (prevents unbounded table growth)
            cutoff_time_90 = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
            deleted = self.db.execute_returning(
                """
                DELETE FROM lattice_peers
                WHERE last_seen_at < %(cutoff_time)s
                RETURNING server_id
                """,
                {'cutoff_time': cutoff_time_90}
            )

            deleted_count = len(deleted) if deleted else 0
            if deleted_count > 0:
                logger.info(f"Deleted {deleted_count} dead peers (not seen in 90+ days)")

            return count + deleted_count

        except Exception as e:
            logger.error(f"Error cleaning up stale peers: {e}")
            return 0

    def rotate_peer_key(self, rotation: KeyRotation, from_server: str) -> bool:
        """
        Process key rotation for a peer.

        Validates old_public_key matches stored key, then updates.
        Signature verification is done by gossip_protocol before calling this.
        """
        try:
            # Get existing peer by UUID
            peer = self.db.execute_single(
                "SELECT server_id, public_key FROM lattice_peers WHERE server_uuid = %(uuid)s",
                {'uuid': rotation.server_uuid}
            )

            if not peer:
                logger.warning(f"Key rotation for unknown UUID: {rotation.server_uuid}")
                return False

            # Verify old key matches what we have stored
            if peer['public_key'] != rotation.old_public_key:
                logger.error(f"Key rotation rejected: old_public_key doesn't match stored key for {peer['server_id']}")
                return False

            # Generate fingerprints for logging
            import hashlib
            old_fp = hashlib.sha256(rotation.old_public_key.encode()).digest()[:16].hex().upper()
            new_fp = hashlib.sha256(rotation.new_public_key.encode()).digest()[:16].hex().upper()

            # Update the public key
            self.db.execute_update(
                "UPDATE lattice_peers SET public_key = %(new_key)s WHERE server_uuid = %(uuid)s",
                {'new_key': rotation.new_public_key, 'uuid': rotation.server_uuid}
            )

            # Log the rotation
            import uuid as uuid_module
            self.db.execute_insert(
                """
                INSERT INTO lattice_key_rotations
                (id, server_uuid, old_key_fingerprint, new_key_fingerprint, reason, received_from)
                VALUES (%(id)s, %(uuid)s, %(old_fp)s, %(new_fp)s, %(reason)s, %(from_server)s)
                """,
                {'id': str(uuid_module.uuid4()), 'uuid': rotation.server_uuid, 'old_fp': old_fp, 'new_fp': new_fp,
                 'reason': rotation.reason, 'from_server': from_server}
            )

            logger.info(f"Rotated key for {peer['server_id']}: {old_fp[:8]}... -> {new_fp[:8]}...")
            return True

        except Exception as e:
            logger.error(f"Error processing key rotation: {e}")
            return False

    def revoke_peer(self, revocation: IdentityRevocation, from_server: str) -> bool:
        """
        Permanently revoke a peer identity (cyanide pill).

        Signature verification is done by gossip_protocol before calling this.
        """
        try:
            # Check if already revoked
            existing = self.db.execute_single(
                "SELECT 1 FROM lattice_revocations WHERE server_uuid = %(uuid)s",
                {'uuid': revocation.server_uuid}
            )
            if existing:
                logger.info(f"UUID {revocation.server_uuid} already revoked")
                return True

            # Add to revocations table
            import uuid as uuid_module
            self.db.execute_insert(
                """
                INSERT INTO lattice_revocations (id, server_uuid, server_id, reason, signature)
                VALUES (%(id)s, %(uuid)s, %(server_id)s, %(reason)s, %(signature)s)
                """,
                {'id': str(uuid_module.uuid4()), 'uuid': revocation.server_uuid, 'server_id': revocation.server_id,
                 'reason': revocation.reason, 'signature': revocation.signature}
            )

            # Update peer trust_status and remove from neighbors
            self.db.execute_update(
                "UPDATE lattice_peers SET trust_status = 'revoked', is_neighbor = 0 WHERE server_uuid = %(uuid)s",
                {'uuid': revocation.server_uuid}
            )

            logger.warning(f"IDENTITY REVOKED: {revocation.server_id} (UUID: {revocation.server_uuid}) - {revocation.reason}")
            return True

        except Exception as e:
            logger.error(f"Error processing identity revocation: {e}")
            return False