"""
Gossip protocol implementation for federation.

Handles message serialization, signing, and verification.
"""

import base64
import hashlib
import json
import logging
from datetime import timedelta
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from clients.postgres_client import PostgresClient
from utils.timezone_utils import utc_now, parse_utc_time_string
from .models import (
    ServerAnnouncement,
    PeerExchange,
    GossipMessage,
    DomainQuery,
    DomainResponse
)

logger = logging.getLogger(__name__)


class GossipProtocol:
    """Handles gossip protocol message signing and verification."""

    def __init__(self):
        """Initialize gossip protocol handler."""
        self.db = PostgresClient("mira_service")
        self._private_key = None
        self._public_key = None
        self._server_id = None
        self._load_identity()

        # Initialize PeerManager for processing announcements
        from .peer_manager import PeerManager
        self.peer_manager = PeerManager()

    def _load_identity(self) -> None:
        """Load server identity from database and Vault."""
        try:
            identity = self.db.execute_single(
                "SELECT server_id, server_uuid, private_key_vault_path, public_key FROM federation_identity WHERE id = 1"
            )

            if identity:
                self._server_id = identity['server_id']
                self._server_uuid = identity['server_uuid']

                # Load private key from Vault
                from clients.vault_client import _ensure_vault_client
                vault = _ensure_vault_client()
                vault_path, field_name = identity['private_key_vault_path'].split(':', 1) if ':' in identity['private_key_vault_path'] else (identity['private_key_vault_path'], 'private_key')
                private_key_pem = vault.get_secret(vault_path, field_name)

                # Validate that key was retrieved
                if not private_key_pem:
                    raise RuntimeError(f"Private key not found in Vault at {vault_path}:{field_name}")

                if len(private_key_pem.strip()) < 100:  # Sanity check for valid PEM
                    raise RuntimeError(f"Invalid private key in Vault (too short): {len(private_key_pem)} chars")

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
                    logger.info(f"Federation private key validated successfully")
                except Exception as e:
                    logger.error(f"Private key validation failed: {e}")
                    raise RuntimeError(f"Cannot use private key from Vault: {e}")

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
            from clients.vault_client import get_service_config

            # Get APP_URL from Vault
            app_url = get_service_config("mira", "APP_URL")
            if not app_url:
                logger.error("No APP_URL configured in Vault")
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
                    announcement_time = parse_utc_time_string(announcement.timestamp)
                    age = utc_now() - announcement_time

                    if age > timedelta(hours=24):
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

            else:
                # Note: domain_query and domain_response have dedicated endpoints
                # (/api/v1/domain/query) and should not come through gossip
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
                FROM federation_routes r
                WHERE r.domain = %(domain)s
                  AND r.expires_at > NOW()
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

            # Cache the route
            self.db.execute_insert(
                """
                INSERT INTO federation_routes
                (domain, server_id, endpoint_url, hop_count, confidence, expires_at)
                VALUES (%(domain)s, %(server_id)s, %(endpoint_url)s, %(hop_count)s, %(confidence)s, %(expires_at)s)
                ON CONFLICT (domain) DO UPDATE
                SET server_id = EXCLUDED.server_id,
                    endpoint_url = EXCLUDED.endpoint_url,
                    hop_count = EXCLUDED.hop_count,
                    confidence = EXCLUDED.confidence,
                    expires_at = EXCLUDED.expires_at,
                    last_used_at = NOW()
                """,
                {
                    'domain': response.domain,
                    'server_id': response.server_id,
                    'endpoint_url': response.endpoint_url,
                    'hop_count': response.hop_count,
                    'confidence': response.confidence,
                    'expires_at': utc_now() + timedelta(hours=24)
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