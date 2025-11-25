"""
Federation Adapter for MIRA Pager System.

Handles message routing between local and remote servers.
Fully synchronous - follows MIRA's "Synchronous Over Async" principle.
"""

import json
import logging
import uuid
from datetime import timedelta
from typing import Dict, Any, Optional

from clients.postgres_client import PostgresClient
from utils.timezone_utils import utc_now
from utils.prompt_injection_defense import PromptInjectionDefense, TrustLevel
from .models import FederatedMessage
from .gossip_protocol import GossipProtocol
from .peer_manager import PeerManager

logger = logging.getLogger(__name__)


class FederationAdapter:
    """
    Handles federated message routing (fully synchronous).

    Responsibilities:
    - Queue outbound messages to remote servers (writes to DB)
    - Accept and validate inbound messages from remote servers
    - Filter federated content for security

    Note: Outbound message delivery is handled by discovery daemon background tasks.
    """

    def __init__(self):
        self.db = PostgresClient("mira_service")
        self.gossip_protocol = GossipProtocol()
        self.peer_manager = PeerManager()
        self.injection_defense = PromptInjectionDefense()

    def _resolve_local_username(self, username: str) -> Optional[str]:
        """
        Resolve a local username to a user_id.

        Args:
            username: The username to resolve (e.g., "taylor")

        Returns:
            User ID (UUID string) if username exists and is active, None otherwise

        Raises:
            ValueError: If username is invalid format
        """
        if not username:
            raise ValueError("Username cannot be empty")

        # Validate username format (alphanumeric, 3-20 chars)
        if not username.isalnum():
            raise ValueError(f"Username '{username}' must be alphanumeric")

        if len(username) < 3 or len(username) > 20:
            raise ValueError(f"Username '{username}' must be 3-20 characters")

        try:
            result = self.db.execute_single(
                """
                SELECT user_id
                FROM global_usernames
                WHERE username = %(username)s
                  AND active = true
                """,
                {'username': username.lower()}
            )

            if result:
                logger.debug(f"Resolved username '{username}' to user_id {result['user_id']}")
                return str(result['user_id'])

            logger.warning(f"Username '{username}' not found or inactive")
            return None

        except Exception as e:
            logger.error(f"Error resolving username '{username}': {e}")
            return None

    def send_federated_message(
        self,
        from_address: str,
        to_address: str,
        content: str,
        authorized_user_id: str,
        priority: int = 0,
        message_type: str = "pager",
        location: Optional[Dict[str, Any]] = None,
        device_secret: Optional[str] = None,
        sender_fingerprint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Queue a message for federated delivery.

        Args:
            from_address: Sender address (user@local-domain)
            to_address: Recipient address (user@remote-domain)
            content: Message content
            authorized_user_id: User ID of caller (REQUIRED for authorization)
            priority: Message priority (0-2)
            message_type: Type of message
            location: Optional location data
            device_secret: Sender's device secret for signing
            sender_fingerprint: Sender's device fingerprint

        Returns:
            Message status and ID

        Raises:
            ValueError: If caller is not authorized to send from from_address
        """
        try:
            # Validate sender authorization - REQUIRED security check
            if '@' not in from_address:
                raise ValueError(f"Invalid sender address format: {from_address}")

            sender_username, sender_domain = from_address.split('@', 1)

            # Verify the caller is authorized to send from this username
            resolved_user_id = self._resolve_local_username(sender_username)
            if not resolved_user_id:
                raise ValueError(f"Sender username '{sender_username}' not found locally")

            if resolved_user_id != authorized_user_id:
                raise ValueError(
                    f"Authorization failed: caller (user_id={authorized_user_id}) is not "
                    f"authorized to send from '{from_address}'"
                )

            # Extract domain from recipient address
            if '@' not in to_address:
                raise ValueError(f"Invalid federated address: {to_address}")

            _, to_domain = to_address.split('@', 1)

            # Create message ID (use UUID for uniqueness under concurrent load)
            message_id = f"MSG-{uuid.uuid4().hex[:12].upper()}"

            # Create federated message
            message = FederatedMessage(
                message_id=message_id,
                from_address=from_address,
                to_address=to_address,
                content=content,
                priority=priority,
                message_type=message_type,
                location=location,
                sender_fingerprint=sender_fingerprint,
                signature=""  # Will be set after signing
            )

            # Sign the message
            message_dict = message.model_dump(exclude={'signature'})
            message.signature = self.gossip_protocol.sign_message(message_dict)

            # Queue for delivery
            # Build metadata dict properly - merge location with existing metadata
            metadata_dict = dict(message.metadata) if message.metadata else {}
            if location:
                metadata_dict['location'] = location

            queue_data = {
                'message_id': message.message_id,
                'from_address': message.from_address,
                'to_address': message.to_address,
                'to_domain': to_domain,
                'message_type': message.message_type,
                'content': message.content,
                'priority': message.priority,
                'metadata': json.dumps(metadata_dict),
                'signature': message.signature,
                'sender_fingerprint': message.sender_fingerprint,
                'status': 'pending',
                'created_at': utc_now(),
                'expires_at': utc_now() + timedelta(hours=1),
                'next_attempt_at': utc_now()
            }

            # Insert into queue (discovery daemon will handle delivery)
            self.db.execute_insert(
                """
                INSERT INTO federation_messages
                (message_id, from_address, to_address, to_domain, message_type,
                 content, priority, metadata, signature, sender_fingerprint,
                 status, created_at, expires_at, next_attempt_at)
                VALUES (%(message_id)s, %(from_address)s, %(to_address)s, %(to_domain)s,
                        %(message_type)s, %(content)s, %(priority)s, %(metadata)s::jsonb,
                        %(signature)s, %(sender_fingerprint)s, %(status)s,
                        %(created_at)s, %(expires_at)s, %(next_attempt_at)s)
                """,
                queue_data
            )

            logger.info(f"Queued federated message {message.message_id} to {to_address} (delivery handled by discovery daemon)")

            return {
                "success": True,
                "message_id": message.message_id,
                "status": "queued",
                "recipient": to_address
            }

        except Exception as e:
            logger.error(f"Error queueing federated message: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def receive_federated_message(self, message: FederatedMessage) -> Dict[str, Any]:
        """
        Receive an inbound federated message from a remote server and deliver it locally.

        Args:
            message: FederatedMessage from remote server

        Returns:
            Dict with delivery status
        """
        try:
            logger.info(f"Receiving federated message {message.message_id} from {message.from_address} to {message.to_address}")

            # Check for duplicate message (idempotency)
            existing = self.db.execute_single(
                "SELECT 1 FROM federation_received_messages WHERE message_id = %s",
                (message.message_id,)
            )

            if existing:
                logger.info(f"Duplicate message {message.message_id} - already processed")
                return {
                    "status": "accepted",
                    "message_id": message.message_id,
                    "note": "duplicate message (already processed)"
                }

            # Extract sender's server domain from from_address
            if '@' not in message.from_address:
                raise ValueError(f"Invalid sender address format: {message.from_address}")

            _, sender_domain = message.from_address.split('@', 1)

            # Look up sender's public key from peers table
            sender_peer = self.peer_manager.get_peer_by_domain(sender_domain)
            if not sender_peer:
                logger.warning(f"Unknown sender domain: {sender_domain}")
                raise ValueError(f"Unknown sender server: {sender_domain}")

            sender_public_key = sender_peer.get('public_key')
            if not sender_public_key:
                raise ValueError(f"No public key for sender: {sender_domain}")

            # Verify signature using sender's public key
            message_dict = message.model_dump(exclude={'signature'})
            if not self.gossip_protocol.verify_signature(message_dict, message.signature, sender_public_key):
                logger.warning(f"Invalid signature on message {message.message_id} from {sender_domain}")
                raise ValueError("Message signature verification failed")

            # Filter content for prompt injection (UNTRUSTED source)
            filtered_content = self.injection_defense.filter_text(
                message.content,
                trust_level=TrustLevel.UNTRUSTED
            )

            content_was_filtered = (filtered_content != message.content)
            if content_was_filtered:
                logger.warning(f"Prompt injection detected in federated message {message.message_id}")
                # Add metadata flag indicating content was modified
                if not message.metadata:
                    message.metadata = {}
                message.metadata['content_filtered'] = True
                message.metadata['filter_reason'] = 'prompt_injection_detected'

            # Extract username from address (user@domain format)
            if '@' not in message.to_address:
                raise ValueError(f"Invalid recipient address format: {message.to_address}")

            username, _domain = message.to_address.split('@', 1)

            # Resolve username to local user_id
            user_id = self._resolve_local_username(username)

            if not user_id:
                logger.warning(f"Username '{username}' not found locally")
                raise ValueError(f"Recipient username '{username}' not found")

            # Deliver to local pager (write-only, no read access to user data)
            # Note: PagerTool.deliver_federated_message will be implemented in next step
            from tools.implementations.secondarytools_notincontextrn.pager_tool import PagerTool

            pager = PagerTool(user_id=user_id)
            delivery_result = pager.deliver_federated_message(
                from_address=message.from_address,
                content=filtered_content,
                priority=message.priority,
                metadata=message.metadata
            )

            if delivery_result.get("success"):
                # Record successful delivery for idempotency tracking
                self.db.execute_insert(
                    """
                    INSERT INTO federation_received_messages (message_id, from_address, received_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (message_id) DO NOTHING
                    """,
                    (message.message_id, message.from_address)
                )

                logger.info(f"Federated message {message.message_id} delivered to local user {username}")
                return {
                    "status": "accepted",
                    "message_id": message.message_id,
                    "delivered_to": username
                }
            else:
                logger.error(f"Failed to deliver federated message {message.message_id}: {delivery_result.get('error')}")
                raise ValueError(f"Delivery failed: {delivery_result.get('error')}")

        except ValueError as e:
            # Validation errors (signature, format, etc.)
            logger.warning(f"Federated message validation failed: {e}")
            return {
                "status": "rejected",
                "reason": str(e)
            }
        except Exception as e:
            logger.error(f"Error receiving federated message: {e}", exc_info=True)
            return {
                "status": "error",
                "reason": "Internal server error"
            }
