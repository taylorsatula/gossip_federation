"""
HTTP client for the Lattice federation service.
"""

import logging
import os
from typing import Dict, Any, Optional, Literal
from datetime import datetime

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class FederatedMessage(BaseModel):
    """Message model for Lattice protocol."""
    to_address: str
    from_address: str
    content: str
    message_type: Literal["pager", "location", "ai_to_ai"] = "pager"
    priority: int = 0
    content_type: str = "text/plain"
    timestamp: Optional[datetime] = None
    reply_to: Optional[str] = None
    federation_metadata: Dict[str, Any] = Field(default_factory=dict)


class LatticeClient:
    """HTTP client for sending federated messages and querying Lattice status."""

    def __init__(self, base_url: str = "http://localhost:1113", timeout: int = 30, admin_token: Optional[str] = None):
        """
        Initialize Lattice client.

        Args:
            base_url: URL of the Lattice service
            timeout: Request timeout in seconds
            admin_token: Token for local admin endpoints.
        """
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token or os.getenv("LATTICE_ADMIN_TOKEN") or os.getenv("ADMIN_TOKEN")
        self.client = httpx.Client(timeout=timeout)

    def _admin_headers(self) -> Dict[str, str]:
        if not self.admin_token:
            return {}
        return {"X-Lattice-Admin-Token": self.admin_token}

    def _send_payload(self, message: FederatedMessage) -> Dict[str, Any]:
        """Map the public client model to the daemon send API."""
        metadata = dict(message.federation_metadata or {})
        if message.reply_to is not None:
            metadata.setdefault("reply_to", message.reply_to)
        if message.content_type:
            metadata.setdefault("content_type", message.content_type)

        return {
            "to_address": message.to_address,
            "from_address": message.from_address,
            "content": message.content,
            "message_type": message.message_type,
            "priority": message.priority,
            "metadata": metadata
        }

    def send_federated_message(self, message: FederatedMessage) -> Dict[str, Any]:
        """
        Send a message to a federated user.

        Args:
            message: Message to send

        Returns:
            Response with message_id and status

        Raises:
            httpx.HTTPError: If request fails
        """
        try:
            response = self.client.post(
                f"{self.base_url}/api/v1/messages/send",
                json=self._send_payload(message),
                headers=self._admin_headers()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to send federated message: {e}")
            raise

    def get_lattice_status(self) -> Dict[str, Any]:
        """
        Get current Lattice service status.

        Returns:
            Status dictionary with health info
        """
        try:
            response = self.client.get(f"{self.base_url}/api/v1/health", headers=self._admin_headers())
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            return {
                "status": "unavailable",
                "enabled": False,
                "error": "Cannot connect to Lattice service"
            }

    def list_peers(self) -> Dict[str, Any]:
        """
        List known Lattice peers.

        Returns:
            Dictionary with peer information
        """
        try:
            response = self.client.get(f"{self.base_url}/api/v1/peers", headers=self._admin_headers())
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to list peers: {e}")
            return {"peers": [], "error": str(e)}

    def close(self):
        """Close the HTTP client."""
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
