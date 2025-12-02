"""
Initialize Lattice services.

This module handles setup including:
- Generating server identity on first run
- Starting discovery daemon
- Registering jobs with scheduler
"""

import logging
import os
import subprocess
from typing import Dict, Any

from .sqlite_client import SQLiteClient


def _secure_delete(filepath: str) -> None:
    """
    Securely delete a file by overwriting before removal.

    Attempts to use 'shred' command if available (Linux), falls back to
    manual overwrite with random data (portable, works on macOS).
    """
    try:
        # Try shred first (Linux) - overwrites 3 times then removes
        subprocess.run(
            ['shred', '-u', '-z', filepath],
            capture_output=True,
            check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: manual overwrite with random data (portable)
        try:
            size = os.path.getsize(filepath)
            with open(filepath, 'wb') as f:
                f.write(os.urandom(size))  # Overwrite with random data
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            os.unlink(filepath)
        except Exception:
            # Last resort: just delete
            if os.path.exists(filepath):
                os.unlink(filepath)


from .secrets import load_config, save_private_key, get_private_key_path
from .gossip_protocol import GossipProtocol
from .domain_registration import DomainRegistrationService

logger = logging.getLogger(__name__)


def ensure_lattice_identity() -> Dict[str, Any]:
    """
    Ensure lattice identity exists, creating if necessary.

    Returns:
        Dict with server_id, server_uuid, and status
    """
    db = SQLiteClient()

    try:
        # Check if identity exists
        identity = db.execute_single(
            "SELECT server_id, server_uuid, public_key FROM lattice_identity WHERE id = 1"
        )

        if identity:
            logger.info(f"Federation identity exists: {identity['server_id']} (UUID: {identity['server_uuid']})")
            return {
                "exists": True,
                "server_id": identity['server_id'],
                "server_uuid": identity['server_uuid']
            }

        # Need to create new identity
        logger.info("No lattice identity found, generating new identity...")

        # Generate keypair
        gossip = GossipProtocol()
        private_pem, public_pem = gossip.generate_keypair()
        fingerprint = gossip.generate_fingerprint(public_pem)

        # Store private key to disk
        try:
            key_path = save_private_key(private_pem)
            logger.info(f"Stored private key at {key_path}")
        except Exception as e:
            logger.error(f"Failed to store private key: {e}")
            raise RuntimeError(f"Cannot initialize federation without saving private key: {e}")

        # Get suggested domain from environment or generate
        suggested_domain = os.getenv("LATTICE_DOMAIN", "lattice-" + fingerprint[:8].lower())

        # Create identity record with suggested domain
        import uuid
        server_uuid = str(uuid.uuid4())

        import json
        db.execute_insert(
            """
            INSERT INTO lattice_identity
            (id, server_id, server_uuid, private_key_path, public_key, fingerprint,
             bootstrap_servers, created_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                suggested_domain,
                server_uuid,
                str(key_path),
                public_pem,
                fingerprint,
                json.dumps([])  # Bootstrap servers can be added later
            )
        )

        logger.info(f"Created lattice identity with domain '{suggested_domain}' and UUID {server_uuid}")

        return {
            "exists": False,
            "server_id": suggested_domain,
            "server_uuid": server_uuid,
            "message": f"New lattice identity created with domain '{suggested_domain}'. "
                      f"To use a different domain, update lattice_identity.server_id in the database."
        }

    except Exception as e:
        logger.error(f"Error ensuring lattice identity: {e}")
        raise


def initialize_lattice_services(scheduler_service) -> bool:
    """
    Initialize lattice services and register scheduled tasks.

    Args:
        scheduler_service: The system scheduler service

    Returns:
        bool: True if initialization succeeded
    """
    try:
        # Ensure lattice identity exists
        identity_info = ensure_lattice_identity()

        # Get federation configuration
        try:
            bootstrap_servers = load_config("BOOTSTRAP_SERVERS")
            if bootstrap_servers:
                # Parse comma-separated list
                bootstrap_list = [s.strip() for s in bootstrap_servers.split(",")]
                import json as json_module
                db = SQLiteClient()
                db.execute_update(
                    "UPDATE lattice_identity SET bootstrap_servers = ? WHERE id = 1",
                    (json_module.dumps(bootstrap_list),)
                )
                logger.info(f"Configured {len(bootstrap_list)} bootstrap servers")
        except Exception as e:
            logger.warning(f"No bootstrap servers configured: {e}")

        # Register scheduled HTTP calls to discovery daemon endpoints
        # The discovery daemon runs as a separate process on port 1113
        _register_lattice_scheduler_jobs(scheduler_service)

        logger.info(
            f"Federation services initialized for domain '{identity_info['server_id']}' "
            f"(UUID: {identity_info['server_uuid']})"
        )

        return True

    except Exception as e:
        logger.error(f"Failed to initialize lattice services: {e}")
        return False


def _register_lattice_scheduler_jobs(scheduler_service):
    """Register scheduled HTTP calls to discovery daemon maintenance endpoints."""
    import httpx
    from apscheduler.triggers.interval import IntervalTrigger

    discovery_daemon_url = "http://localhost:1113"

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
                    logger.info("Triggered lattice cleanup")
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

    # Register jobs with scheduler
    scheduler_service.register_job(
        job_id="lattice_gossip",
        func=call_gossip_endpoint,
        trigger=IntervalTrigger(minutes=10),
        component="lattice",
        description="Trigger lattice gossip round via discovery daemon"
    )

    scheduler_service.register_job(
        job_id="lattice_neighbor_update",
        func=call_neighbor_update_endpoint,
        trigger=IntervalTrigger(hours=6),
        component="lattice",
        description="Trigger neighbor selection update via discovery daemon"
    )

    scheduler_service.register_job(
        job_id="lattice_cleanup",
        func=call_cleanup_endpoint,
        trigger=IntervalTrigger(days=1),
        component="lattice",
        description="Trigger lattice cleanup via discovery daemon"
    )

    scheduler_service.register_job(
        job_id="lattice_message_delivery",
        func=call_message_processing_endpoint,
        trigger=IntervalTrigger(minutes=1),
        component="lattice",
        description="Process pending federated messages for delivery"
    )

    logger.info("Registered 4 lattice scheduler jobs (calling discovery daemon endpoints)")


def get_federation_status() -> Dict[str, Any]:
    """Get current federation status and configuration."""
    try:
        db = SQLiteClient()

        identity = db.execute_single(
            "SELECT server_id, server_uuid, fingerprint, created_at FROM lattice_identity WHERE id = 1"
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
                SUM(CASE WHEN is_neighbor = 1 THEN 1 ELSE 0 END) as neighbors,
                SUM(CASE WHEN trust_status = 'trusted' THEN 1 ELSE 0 END) as trusted_peers,
                SUM(CASE WHEN last_seen_at > datetime('now', '-1 day') THEN 1 ELSE 0 END) as active_peers
            FROM lattice_peers
            """
        )

        return {
            "enabled": True,
            "server_id": identity['server_id'],
            "server_uuid": identity['server_uuid'],
            "fingerprint": identity['fingerprint'],
            "created_at": identity['created_at'],
            "peers": peer_stats or {"total_peers": 0, "neighbors": 0, "trusted_peers": 0, "active_peers": 0},
            "discovery_daemon_url": "http://localhost:1113"
        }

    except Exception as e:
        logger.error(f"Error getting federation status: {e}")
        return {
            "enabled": False,
            "error": str(e)
        }