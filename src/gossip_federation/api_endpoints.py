"""
Federation API endpoint - handles inbound federated messages.

Receives messages from remote federation servers and routes them to local users.
"""
import logging
from datetime import timedelta
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .base import BaseHandler, APIResponse, create_success_response, create_error_response
from federation.federation_adapter import FederationAdapter
from federation.models import FederatedMessage

logger = logging.getLogger(__name__)

router = APIRouter()


class MessageReceiveEndpoint(BaseHandler):
    """Handles inbound federated messages from remote servers."""

    def __init__(self):
        super().__init__()
        self.federation_adapter = FederationAdapter()
        from clients.postgres_client import PostgresClient
        self.db = PostgresClient("mira_service")

    def _check_rate_limit(self, sender_domain: str) -> bool:
        """
        Check if sender has exceeded rate limit (atomic operation).

        Rate limit: 100 messages per minute per peer.

        Args:
            sender_domain: Sending server's domain

        Returns:
            True if within limit, False if exceeded
        """
        from utils.timezone_utils import utc_now

        peer = self.db.execute_single(
            """
            SELECT message_count, rate_limit_reset_at
            FROM federation_peers
            WHERE server_id = %s
            """,
            (sender_domain,)
        )

        if not peer:
            # Unknown peer - will be rejected by signature verification anyway
            return True

        now = utc_now()

        # Atomic increment with limit check using UPDATE with WHERE clause
        # This prevents race conditions by checking and incrementing in single DB operation
        result = self.db.execute_returning(
            """
            UPDATE federation_peers
            SET message_count = CASE
                    WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at <= %s THEN 1
                    ELSE message_count + 1
                END,
                rate_limit_reset_at = CASE
                    WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at <= %s THEN %s
                    ELSE rate_limit_reset_at
                END
            WHERE server_id = %s
              AND (rate_limit_reset_at IS NULL
                   OR rate_limit_reset_at <= %s
                   OR message_count < 100)
            RETURNING message_count
            """,
            (now, now, now + timedelta(minutes=1), sender_domain, now)
        )

        if not result:
            # UPDATE matched no rows - rate limit exceeded
            logger.warning(f"Rate limit exceeded for {sender_domain}: 100 messages per minute")
            return False

        return True

    def process_request(self, **params) -> APIResponse:
        """
        Receive and process a federated message.

        Args:
            message: FederatedMessage from remote server

        Returns:
            APIResponse with delivery status
        """
        message: FederatedMessage = params['message']

        try:
            # Validate sender address format BEFORE rate limiting
            if '@' not in message.from_address:
                return create_error_response(
                    error_code="INVALID_ADDRESS",
                    message=f"Invalid sender address format (must be user@domain)",
                    status_code=400
                )

            # Extract sender domain for rate limiting
            _, sender_domain = message.from_address.split('@', 1)

            # Check rate limit before processing
            if not self._check_rate_limit(sender_domain):
                return create_error_response(
                    error_code="RATE_LIMIT_EXCEEDED",
                    message=f"Rate limit exceeded: maximum 100 messages per minute",
                    status_code=429
                )

            result = self.federation_adapter.receive_federated_message(message)

            return create_success_response(
                data=result,
                message="Message received and processed"
            )

        except ValueError as e:
            logger.warning(f"Invalid federated message: {e}")
            return create_error_response(
                error_code="INVALID_MESSAGE",
                message=str(e),
                status_code=400
            )
        except Exception as e:
            logger.error(f"Error processing federated message: {e}", exc_info=True)
            return create_error_response(
                error_code="PROCESSING_ERROR",
                message="Failed to process federated message",
                status_code=500
            )


@router.post("/federation/messages/receive")
async def receive_federation_message(message: FederatedMessage) -> Dict[str, Any]:
    """
    Receive a federated message from a remote server.

    This endpoint is called by remote federation servers to deliver
    messages to local users.
    """
    handler = MessageReceiveEndpoint()
    response = handler.process_request(message=message)

    if response.status == "error":
        raise HTTPException(
            status_code=response.metadata.get("status_code", 500),
            detail=response.error
        )

    return response.data
