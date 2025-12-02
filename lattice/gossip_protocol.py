"""
Gossip protocol implementation for federation.

Handles message serialization, signing, and verification.
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from dateutil import parser as dateutil_parser
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from .sqlite_client import SQLiteClient
from .models import (
    ServerAnnouncement,
    PeerExchange,
    GossipMessage,
    DomainQuery,
    DomainResponse,
    KeyRotation,
    IdentityRevocation
)

logger = logging.getLogger(__name__)


class GossipProtocol:
    """Handles gossip protocol message signing and verification."""

    def __init__(self):
        """Initialize gossip protocol handler."""
        self.db = SQLiteClient()
        self._private_key = None
        self._public_key = None
        self._server_id = None
        self._load_identity()

        # Initialize PeerManager for processing announcements
        from .peer_manager import PeerManager
        self.peer_manager = PeerManager()

    def _load_identity(self) -> None:
        """Load server identity from database and secrets."""
        try:
            identity = self.db.execute_single(
                "SELECT server_id, server_uuid, private_key_path, public_key FROM lattice_identity WHERE id = 1"
            )

            if identity:
                self._server_id = identity['server_id']
                self._server_uuid = identity['server_uuid']

                # Load private key using secrets fallback chain
                from .secrets import load_private_key
                private_key_pem = load_private_key()

                # Validate that key was retrieved
                if not private_key_pem:
                    raise RuntimeError("Private key not found")

                if len(private_key_pem.strip()) < 100:  # Sanity check for valid PEM
                    raise RuntimeError(f"Invalid private key (too short): {len(private_key_pem)} chars")

                self._private_key = serialization.load_pem_private_key(
                    private_key_pem.encode(),
                    password=None,
                    backend=default_backend()
                )

                # Validate key works by test signing
                try:
                    test_sig = self._private_key.sign(
                        b"federation_key_validation_test",
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    logger.info("Federation private key validated successfully")
                except Exception as e:
                    logger.error(f"Private key validation failed: {e}")
                    raise RuntimeError(f"Cannot use private key: {e}")

                # Load public key from database
                self._public_key = serialization.load_pem_public_key(
                    identity['public_key'].encode(),
                    backend=default_backend()
                )
                logger.info(f"Loaded federation identity for: {self._server_id} (UUID: {self._server_uuid})")
            else:
                logger.warning("No federation identity found")

        except Exception as e:
            logger.error(f"Error loading federation identity: {e}")

    def get_server_id(self) -> Optional[str]:
        """Get our server's ID."""
        return self._server_id

    def get_server_uuid(self) -> Optional[str]:
        """Get our server's permanent UUID."""
        return self._server_uuid

    def generate_keypair(self) -> Tuple[str, str]:
        """
        Generate new RSA keypair for server identity.

        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        # Generate 2048-bit RSA keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Export private key to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Export public key to PEM
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_pem, public_pem

    def sign_message(self, message_dict: Dict[str, Any]) -> str:
        """
        Sign a message dictionary with server's private key.

        Args:
            message_dict: Message to sign

        Returns:
            Base64-encoded signature
        """
        if not self._private_key:
            raise RuntimeError("No private key loaded")

        # Create canonical JSON representation (sorted keys)
        canonical = json.dumps(message_dict, sort_keys=True)

        # Sign with RSA-SHA256
        signature = self._private_key.sign(
            canonical.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message_dict: Dict[str, Any], signature: str, public_key_pem: str) -> bool:
        """
        Verify message signature using provided public key.

        Args:
            message_dict: Message to verify
            signature: Base64-encoded signature
            public_key_pem: Public key in PEM format

        Returns:
            True if signature is valid
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )

            # Recreate canonical JSON
            canonical = json.dumps(message_dict, sort_keys=True)

            # Decode signature
            signature_bytes = base64.b64decode(signature)

            # Verify signature
            public_key.verify(
                signature_bytes,
                canonical.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except InvalidSignature:
            logger.warning(f"Invalid signature for message")
            return False
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False

    def create_server_announcement(self) -> Optional[ServerAnnouncement]:
        """Create signed server announcement for gossip."""
        if not self._server_id or not self._server_uuid:
            logger.error("Cannot create announcement without server identity")
            return None

        try:
            from .secrets import load_config

            # Get APP_URL from config
            app_url = load_config("APP_URL")
            if not app_url:
                logger.error("No APP_URL configured")
                return None

            # Create announcement
            from .models import ServerEndpoints
            announcement = ServerAnnouncement(
                server_id=self._server_id,
                server_uuid=self._server_uuid,
                public_key=self._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                endpoints=ServerEndpoints(
                    federation=f"{app_url}/api/federation",
                    discovery=f"{app_url}/api/discovery"
                )
            )

            # Sign the announcement
            announcement_dict = announcement.model_dump(exclude={'signature'})
            announcement.signature = self.sign_message(announcement_dict)

            return announcement

        except Exception as e:
            logger.error(f"Error creating server announcement: {e}")
            return None

    def create_peer_exchange(self, peer_list: list[str]) -> Optional[PeerExchange]:
        """Create signed peer exchange message."""
        if not self._server_id:
            return None

        try:
            exchange = PeerExchange(
                from_server=self._server_id,
                peers=peer_list,
                signature=""  # Will be set below
            )

            # Sign the exchange
            exchange_dict = exchange.model_dump(exclude={'signature'})
            exchange.signature = self.sign_message(exchange_dict)

            return exchange

        except Exception as e:
            logger.error(f"Error creating peer exchange: {e}")
            return None

    def process_gossip_message(self, message: GossipMessage, sender_public_key: str) -> bool:
        """
        Process incoming gossip message.

        Args:
            message: Gossip message to process
            sender_public_key: Sender's public key for verification

        Returns:
            True if message was processed successfully
        """
        try:
            # Route based on message type
            if message.message_type == "announcement":
                announcement = ServerAnnouncement(**message.payload)

                # Validate timestamp to prevent replay attacks
                try:
                    announcement_time = dateutil_parser.parse(announcement.timestamp)
                    if announcement_time.tzinfo is None:
                        announcement_time = announcement_time.replace(tzinfo=timezone.utc)
                    age = datetime.now(timezone.utc) - announcement_time

                    if age > timedelta(hours=1):
                        logger.warning(f"Stale announcement from {announcement.server_id} (age: {age})")
                        return False

                    if age < timedelta(minutes=-5):  # 5-minute clock skew tolerance
                        logger.warning(f"Future-dated announcement from {announcement.server_id} (skew: {-age})")
                        return False
                except (ValueError, AttributeError) as e:
                    logger.warning(f"Invalid timestamp in announcement from {message.from_server}: {e}")
                    return False

                # Verify announcement signature
                ann_dict = announcement.model_dump(exclude={'signature'})
                if not self.verify_signature(ann_dict, announcement.signature, sender_public_key):
                    logger.warning(f"Invalid announcement signature from {message.from_server}")
                    return False
                # Process announcement
                return self.peer_manager.add_or_update_peer(announcement)

            elif message.message_type == "peer_exchange":
                exchange = PeerExchange(**message.payload)
                # Verify exchange signature
                exc_dict = exchange.model_dump(exclude={'signature'})
                if not self.verify_signature(exc_dict, exchange.signature, sender_public_key):
                    logger.warning(f"Invalid peer exchange signature from {message.from_server}")
                    return False
                # Process peer list (implementation depends on strategy)
                logger.info(f"Received {len(exchange.peers)} peers from {exchange.from_server}")
                return True

            elif message.message_type == "key_rotation":
                rotation = KeyRotation(**message.payload)
                # Verify signature with OLD public key (the one being rotated out)
                rotation_dict = rotation.model_dump(exclude={'signature'})
                if not self.verify_signature(rotation_dict, rotation.signature, rotation.old_public_key):
                    logger.warning(f"Invalid key rotation signature from {message.from_server}")
                    return False
                return self.peer_manager.rotate_peer_key(rotation, message.from_server)

            elif message.message_type == "identity_revocation":
                revocation = IdentityRevocation(**message.payload)
                # Verify signature with sender's current public key
                revocation_dict = revocation.model_dump(exclude={'signature'})
                if not self.verify_signature(revocation_dict, revocation.signature, sender_public_key):
                    logger.warning(f"Invalid revocation signature from {message.from_server}")
                    return False
                return self.peer_manager.revoke_peer(revocation, message.from_server)

            else:
                # Note: domain_query and domain_response have dedicated endpoints
                logger.warning(f"Unknown gossip message type: {message.message_type}")
                return False

        except Exception as e:
            logger.error(f"Error processing gossip message: {e}")
            return False

    def _handle_domain_query(self, query: DomainQuery, from_server: str) -> Optional[DomainResponse]:
        """
        Handle incoming domain resolution query.

        Returns DomainResponse if we can answer, None if query should be forwarded.
        """
        try:
            # Check if we know this domain
            route = self.db.execute_single(
                """
                SELECT r.server_id, r.endpoint_url, r.hop_count, r.confidence
                FROM lattice_routes r
                WHERE r.domain = %(domain)s
                  AND r.expires_at > datetime('now')
                ORDER BY r.confidence DESC
                LIMIT 1
                """,
                {'domain': query.domain}
            )

            if route:
                # We have a route - create response
                response = DomainResponse(
                    query_id=query.query_id,
                    domain=query.domain,
                    found=True,
                    server_id=route['server_id'],
                    endpoint_url=route['endpoint_url'],
                    hop_count=route['hop_count'] + 1,
                    confidence=route['confidence'] * 0.9  # Reduce confidence per hop
                )
                logger.info(f"Resolved domain {query.domain} for {from_server}")
                return response

            # Check if query has too many hops
            if query.max_hops <= 1:
                # Send not found response
                response = DomainResponse(
                    query_id=query.query_id,
                    domain=query.domain,
                    found=False,
                    hop_count=query.max_hops
                )
                logger.info(f"Domain {query.domain} not found, max hops reached")
                return response

            # We don't know this domain but have hops remaining - signal to forward
            logger.info(f"Domain {query.domain} not in cache, should forward (hops remaining: {query.max_hops})")
            return None  # Caller should forward to neighbors

        except Exception as e:
            logger.error(f"Error handling domain query: {e}")
            # Return not found on error
            return DomainResponse(
                query_id=query.query_id,
                domain=query.domain,
                found=False,
                hop_count=0
            )

    def _handle_domain_response(self, response: DomainResponse) -> bool:
        """Handle domain resolution response."""
        try:
            if not response.found:
                logger.info(f"Domain {response.domain} not found")
                return True

            # Cache the route (use INSERT OR REPLACE for SQLite upsert)
            import uuid as uuid_module
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
            self.db.execute_insert(
                """
                INSERT OR REPLACE INTO lattice_routes
                (id, domain, server_id, endpoint_url, hop_count, confidence, expires_at, last_used_at)
                VALUES (
                    COALESCE((SELECT id FROM lattice_routes WHERE domain = %(domain)s), %(new_id)s),
                    %(domain)s, %(server_id)s, %(endpoint_url)s, %(hop_count)s, %(confidence)s, %(expires_at)s, datetime('now')
                )
                """,
                {
                    'new_id': str(uuid_module.uuid4()),
                    'domain': response.domain,
                    'server_id': response.server_id,
                    'endpoint_url': response.endpoint_url,
                    'hop_count': response.hop_count,
                    'confidence': response.confidence,
                    'expires_at': expires_at
                }
            )

            logger.info(f"Cached route for {response.domain} -> {response.server_id}")
            return True

        except Exception as e:
            logger.error(f"Error handling domain response: {e}")
            return False

    def generate_fingerprint(self, public_key_pem: str) -> str:
        """
        Generate fingerprint from public key.

        Args:
            public_key_pem: Public key in PEM format

        Returns:
            Hex fingerprint string
        """
        # SHA256 hash of the public key
        key_hash = hashlib.sha256(public_key_pem.encode()).digest()
        # Return first 16 bytes as hex (32 chars)
        return key_hash[:16].hex().upper()

    def create_key_rotation(self, new_public_key_pem: str, reason: str = "scheduled") -> Optional[KeyRotation]:
        """Create signed key rotation request (signed with current/old key)."""
        if not self._server_uuid or not self._public_key:
            logger.error("Cannot create key rotation without server identity")
            return None

        try:
            old_public_key_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            rotation = KeyRotation(
                server_uuid=self._server_uuid,
                old_public_key=old_public_key_pem,
                new_public_key=new_public_key_pem,
                reason=reason,
                signature=""
            )

            # Sign with current (old) private key
            rotation_dict = rotation.model_dump(exclude={'signature'})
            rotation.signature = self.sign_message(rotation_dict)

            return rotation

        except Exception as e:
            logger.error(f"Error creating key rotation: {e}")
            return None

    def create_identity_revocation(self, reason: str) -> Optional[IdentityRevocation]:
        """Create cyanide pill to permanently revoke our identity."""
        if not self._server_uuid or not self._server_id:
            logger.error("Cannot create revocation without server identity")
            return None

        try:
            revocation = IdentityRevocation(
                server_uuid=self._server_uuid,
                server_id=self._server_id,
                reason=reason,
                signature=""
            )

            revocation_dict = revocation.model_dump(exclude={'signature'})
            revocation.signature = self.sign_message(revocation_dict)

            return revocation

        except Exception as e:
            logger.error(f"Error creating identity revocation: {e}")
            return None

    def rotate_own_key(self, reason: str = "scheduled") -> bool:
        """
        Rotate this server's keypair (full automation).

        Generates new key, updates storage and DB, gossips to network.
        """
        if not self._server_uuid:
            logger.error("Cannot rotate key without server identity")
            return False

        try:
            from .secrets import save_private_key

            # Generate new keypair
            new_private_pem, new_public_pem = self.generate_keypair()

            # Create rotation message signed with OLD key
            rotation = self.create_key_rotation(new_public_pem, reason)
            if not rotation:
                return False

            # Store new private key to disk
            save_private_key(new_private_pem)

            # Update database
            self.db.execute_update(
                "UPDATE lattice_identity SET public_key = %(key)s, rotated_at = datetime('now') WHERE id = 1",
                {'key': new_public_pem}
            )

            # Reload identity
            self._load_identity()

            # Log rotation locally
            import uuid as uuid_module
            old_fp = self.generate_fingerprint(rotation.old_public_key)
            new_fp = self.generate_fingerprint(new_public_pem)
            self.db.execute_insert(
                """
                INSERT INTO lattice_key_rotations
                (id, server_uuid, old_key_fingerprint, new_key_fingerprint, reason, received_from)
                VALUES (%(id)s, %(uuid)s, %(old_fp)s, %(new_fp)s, %(reason)s, 'self')
                """,
                {'id': str(uuid_module.uuid4()), 'uuid': self._server_uuid, 'old_fp': old_fp, 'new_fp': new_fp, 'reason': reason}
            )

            logger.info(f"Key rotation complete: {old_fp[:8]}... -> {new_fp[:8]}...")
            return True

        except Exception as e:
            logger.error(f"Error rotating own key: {e}")
            return False