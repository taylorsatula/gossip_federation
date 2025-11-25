"""
Initialize federation services for MIRA.

This module handles federation setup including:
- Generating server identity on first run
- Starting discovery daemon
- Registering federation jobs with scheduler
"""

import logging
import os
from typing import Dict, Any

from clients.postgres_client import PostgresClient
from clients.vault_client import _ensure_vault_client, get_service_config
from .gossip_protocol import GossipProtocol
from .domain_registration import DomainRegistrationService

logger = logging.getLogger(__name__)


def ensure_federation_identity() -> Dict[str, Any]:
    """
    Ensure federation identity exists, creating if necessary.

    Returns:
        Dict with server_id, server_uuid, and status
    """
    db = PostgresClient("mira_service")

    try:
        # Check if identity exists
        identity = db.execute_single(
            "SELECT server_id, server_uuid, public_key FROM federation_identity WHERE id = 1"
        )

        if identity:
            logger.info(f"Federation identity exists: {identity['server_id']} (UUID: {identity['server_uuid']})")
            return {
                "exists": True,
                "server_id": identity['server_id'],
                "server_uuid": identity['server_uuid']
            }

        # Need to create new identity
        logger.info("No federation identity found, generating new identity...")

        # Generate keypair
        gossip = GossipProtocol()
        private_pem, public_pem = gossip.generate_keypair()
        fingerprint = gossip.generate_fingerprint(public_pem)

        # Store private key in Vault using CLI
        vault_path = "mira/federation"
        try:
            import subprocess
            import tempfile

            # Write private key to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                f.write(private_pem)
                temp_key_file = f.name

            try:
                # Use vault CLI to patch the secret
                result = subprocess.run(
                    ['vault', 'kv', 'patch', f'secret/{vault_path}', f'private_key={private_pem}'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                logger.info(f"Stored private key in Vault at {vault_path}")
            finally:
                # Clean up temp file
                os.unlink(temp_key_file)

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to store private key in Vault via CLI: {e.stderr}")
            raise RuntimeError(f"Cannot initialize federation without Vault access: {e.stderr}")
        except Exception as e:
            logger.error(f"Failed to store private key in Vault: {e}")
            raise RuntimeError("Cannot initialize federation without Vault access")

        # Get suggested domain from environment or generate
        suggested_domain = os.getenv("FEDERATION_DOMAIN", "mira-" + fingerprint[:8].lower())

        # Create identity record with suggested domain
        import uuid
        server_uuid = str(uuid.uuid4())

        db.execute_insert(
            """
            INSERT INTO federation_identity
            (id, server_id, server_uuid, private_key_vault_path, public_key, fingerprint,
             bootstrap_servers, created_at)
            VALUES (1, %s, %s, %s, %s, %s, %s, NOW())
            """,
            (
                suggested_domain,
                server_uuid,
                f"{vault_path}:private_key",
                public_pem,
                fingerprint,
                []  # Bootstrap servers can be added later
            )
        )

        logger.info(f"Created federation identity with domain '{suggested_domain}' and UUID {server_uuid}")

        return {
            "exists": False,
            "server_id": suggested_domain,
            "server_uuid": server_uuid,
            "message": f"New federation identity created with domain '{suggested_domain}'. "
                      f"To use a different domain, update federation_identity.server_id in the database."
        }

    except Exception as e:
        logger.error(f"Error ensuring federation identity: {e}")
        raise


def initialize_federation_services(scheduler_service) -> bool:
    """
    Initialize federation services and register scheduled tasks.

    Args:
        scheduler_service: The system scheduler service

    Returns:
        bool: True if initialization succeeded
    """
    try:
        # Ensure federation identity exists
        identity_info = ensure_federation_identity()

        # Get federation configuration from Vault
        try:
            bootstrap_servers = get_service_config("mira", "FEDERATION_BOOTSTRAP_SERVERS")
            if bootstrap_servers:
                # Parse comma-separated list
                bootstrap_list = [s.strip() for s in bootstrap_servers.split(",")]
                db = PostgresClient("mira_service")
                db.execute_update(
                    "UPDATE federation_identity SET bootstrap_servers = %(bootstrap_servers)s WHERE id = 1",
                    {'bootstrap_servers': bootstrap_list}
                )
                logger.info(f"Configured {len(bootstrap_list)} bootstrap servers from Vault")
        except Exception as e:
            logger.warning(f"No bootstrap servers configured: {e}")

        # Register scheduled HTTP calls to discovery daemon endpoints
        # The discovery daemon runs as a separate process on port 8302
        _register_federation_scheduler_jobs(scheduler_service)

        logger.info(
            f"Federation services initialized for domain '{identity_info['server_id']}' "
            f"(UUID: {identity_info['server_uuid']})"
        )

        return True

    except Exception as e:
        logger.error(f"Failed to initialize federation services: {e}")
        return False


def _register_federation_scheduler_jobs(scheduler_service):
    """Register scheduled HTTP calls to discovery daemon maintenance endpoints."""
    import httpx
    from apscheduler.triggers.interval import IntervalTrigger

    discovery_daemon_url = "http://localhost:8302"

    # Gossip announcement - every 10 minutes
    def call_gossip_endpoint():
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(f"{discovery_daemon_url}/api/v1/announce", json={"force": False})
                if response.status_code == 200:
                    logger.info("Triggered gossip round")
                else:
                    logger.warning(f"Gossip endpoint returned {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to trigger gossip: {e}")

    # Neighbor selection update - every 6 hours
    def call_neighbor_update_endpoint():
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(f"{discovery_daemon_url}/api/v1/maintenance/update_neighbors")
                if response.status_code == 200:
                    logger.info("Triggered neighbor update")
                else:
                    logger.warning(f"Neighbor update endpoint returned {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to trigger neighbor update: {e}")

    # Cleanup - daily
    def call_cleanup_endpoint():
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(f"{discovery_daemon_url}/api/v1/maintenance/cleanup")
                if response.status_code == 200:
                    logger.info("Triggered federation cleanup")
                else:
                    logger.warning(f"Cleanup endpoint returned {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to trigger cleanup: {e}")

    # Message delivery - every 1 minute
    def call_message_processing_endpoint():
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(f"{discovery_daemon_url}/api/v1/maintenance/process_messages")
                if response.status_code == 200:
                    result = response.json()
                    if result.get('processed', 0) > 0:
                        logger.info(f"Processed {result['processed']} messages: {result['delivered']} delivered, {result['failed']} failed")
                else:
                    logger.warning(f"Message processing endpoint returned {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to trigger message processing: {e}")

    # Register jobs with main MIRA scheduler
    scheduler_service.register_job(
        job_id="federation_gossip",
        func=call_gossip_endpoint,
        trigger=IntervalTrigger(minutes=10),
        component="federation",
        description="Trigger federation gossip round via discovery daemon"
    )

    scheduler_service.register_job(
        job_id="federation_neighbor_update",
        func=call_neighbor_update_endpoint,
        trigger=IntervalTrigger(hours=6),
        component="federation",
        description="Trigger neighbor selection update via discovery daemon"
    )

    scheduler_service.register_job(
        job_id="federation_cleanup",
        func=call_cleanup_endpoint,
        trigger=IntervalTrigger(days=1),
        component="federation",
        description="Trigger federation cleanup via discovery daemon"
    )

    scheduler_service.register_job(
        job_id="federation_message_delivery",
        func=call_message_processing_endpoint,
        trigger=IntervalTrigger(minutes=1),
        component="federation",
        description="Process pending federated messages for delivery"
    )

    logger.info("Registered 4 federation scheduler jobs (calling discovery daemon endpoints)")


def get_federation_status() -> Dict[str, Any]:
    """Get current federation status and configuration."""
    try:
        db = PostgresClient("mira_service")

        identity = db.execute_single(
            "SELECT server_id, server_uuid, fingerprint, created_at FROM federation_identity WHERE id = 1"
        )

        if not identity:
            return {
                "enabled": False,
                "message": "Federation not initialized"
            }

        # Get peer statistics
        peer_stats = db.execute_single(
            """
            SELECT
                COUNT(*) as total_peers,
                COUNT(*) FILTER (WHERE is_neighbor = true) as neighbors,
                COUNT(*) FILTER (WHERE trust_status = 'trusted') as trusted_peers,
                COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '1 day') as active_peers
            FROM federation_peers
            """
        )

        return {
            "enabled": True,
            "server_id": identity['server_id'],
            "server_uuid": identity['server_uuid'],
            "fingerprint": identity['fingerprint'],
            "created_at": identity['created_at'].isoformat(),
            "peers": peer_stats or {"total_peers": 0, "neighbors": 0, "trusted_peers": 0, "active_peers": 0},
            "discovery_daemon_url": "http://localhost:8302"
        }

    except Exception as e:
        logger.error(f"Error getting federation status: {e}")
        return {
            "enabled": False,
            "error": str(e)
        }