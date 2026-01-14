"""
HTTP client for the Lattice federation service.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class FederatedMessage(BaseModel):
    """Message model for Lattice protocol."""
    to_address: str
    from_address: str
    content: str
    content_type: str = "text/plain"
    timestamp: Optional[datetime] = None
    reply_to: Optional[str] = None
    federation_metadata: Dict[str, Any] = {}


class LatticeClient:
    """HTTP client for sending federated messages and querying Lattice status."""

    def __init__(self, base_url: str = "http://localhost:1113", timeout: int = 30):
        """
        Initialize Lattice client.

        Args:
            base_url: URL of the Lattice service
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout)

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
                json=message.model_dump(mode="json", exclude_none=True)
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
            response = self.client.get(f"{self.base_url}/api/v1/health")
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
            response = self.client.get(f"{self.base_url}/api/v1/peers")
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