"""
Test the /api/v1/messages/send endpoint and related functionality.

Uses a real in-memory SQLite database and real cryptographic signing
to verify the message sending flow actually works.
"""

import hashlib
import json
import os
import tempfile
import base64
import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def generate_test_keypair():
    """Generate a real RSA keypair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem, private_key


def sign_payload(private_key, payload):
    canonical = json.dumps(payload, sort_keys=True)
    signature = private_key.sign(
        canonical.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")


def make_remote_ack(env, message_id):
    ack = {
        "version": "1.0",
        "ack_type": "message_received",
        "message_id": message_id,
        "status": "delivered",
        "recipient_server": "remote.example.com",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_message": None,
        "error_code": None
    }
    ack["signature"] = sign_payload(env["remote_private_key"], ack)
    return ack


def make_remote_rejection_ack(env, message_id, reason="Unknown recipient"):
    ack = {
        "version": "1.0",
        "ack_type": "message_failed",
        "message_id": message_id,
        "status": "rejected",
        "recipient_server": "remote.example.com",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_message": reason,
        "error_code": None
    }
    ack["signature"] = sign_payload(env["remote_private_key"], ack)
    return ack


def successful_remote_response(env):
    def _send(_url, data):
        return {"status": "accepted", "ack": make_remote_ack(env, data["message_id"])}
    return _send


@pytest.fixture
def test_env():
    """Set up test environment with real SQLiteClient and temp database."""
    # Create temp database file
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)

    # Set env var before importing anything that uses SQLiteClient
    os.environ['LATTICE_DB_PATH'] = db_path

    # Generate real keys
    private_pem, public_pem, private_key = generate_test_keypair()
    fingerprint = hashlib.sha256(public_pem.encode()).digest()[:16].hex().upper()

    # Now import and get the real client
    from lattice.sqlite_client import SQLiteClient
    db = SQLiteClient(db_path)

    # Insert test identity
    db.execute_insert(
        """INSERT INTO lattice_identity
           (id, server_id, server_uuid, private_key_path, public_key, fingerprint)
           VALUES (1, ?, ?, ?, ?, ?)""",
        ('test.example.com', 'test-uuid-1234', '/fake/path', public_pem, fingerprint)
    )

    # Insert a test peer (remote server we'll send to)
    remote_private, remote_public, remote_private_key = generate_test_keypair()
    db.execute_insert(
        """INSERT INTO lattice_peers
           (id, server_id, server_uuid, public_key, endpoints, trust_status, is_neighbor)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            'peer-1',
            'remote.example.com',
            'remote-uuid-5678',
            remote_public,
            json.dumps({
                'federation': 'https://remote.example.com/api/federation',
                'discovery': 'https://remote.example.com/api/discovery'
            }),
            'trusted',
            1
        )
    )

    yield {
        'db': db,
        'db_path': db_path,
        'private_pem': private_pem,
        'public_pem': public_pem,
        'private_key': private_key,
        'fingerprint': fingerprint,
        'remote_public': remote_public,
        'remote_private_key': remote_private_key,
    }

    # Cleanup
    os.unlink(db_path)
    if 'LATTICE_DB_PATH' in os.environ:
        del os.environ['LATTICE_DB_PATH']


@pytest.fixture
def app_client(test_env):
    """Create test client with real database and crypto, mocked HTTP only."""
    # Import after env var is set
    from lattice.discovery_daemon import app, discovery_service, admin_only

    # Point all components at our test database
    from lattice.sqlite_client import SQLiteClient
    test_db = SQLiteClient(test_env['db_path'])

    discovery_service.db = test_db
    discovery_service.gossip_protocol.db = test_db
    discovery_service.peer_manager.db = test_db
    discovery_service.domain_registration.db = test_db
    discovery_service.domain_registration.peer_manager = discovery_service.peer_manager
    discovery_service.domain_registration.gossip_protocol = discovery_service.gossip_protocol

    # Load the test private key into gossip protocol
    discovery_service.gossip_protocol._private_key = test_env['private_key']
    discovery_service.gossip_protocol._server_id = 'test.example.com'
    discovery_service.gossip_protocol._server_uuid = 'test-uuid-1234'
    original_send = discovery_service._send_to_remote_server
    discovery_service._send_to_remote_server = lambda *_args, **_kwargs: None

    # Mock admin check
    async def mock_admin():
        return "admin"
    app.dependency_overrides[admin_only] = mock_admin

    client = TestClient(app)
    yield client, discovery_service, test_env

    discovery_service._send_to_remote_server = original_send
    app.dependency_overrides.clear()


class TestSendMessageEndpoint:
    """Integration tests for POST /api/v1/messages/send."""

    def test_message_is_queued_in_database(self, app_client):
        """Verify message actually gets inserted into the database."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "bob@test.example.com",
                "content": "Hello, Alice!"
            }
        )

        assert response.status_code == 200
        data = response.json()
        message_id = data["message_id"]

        # Verify message exists in database with correct data
        row = env['db'].execute_single(
            "SELECT * FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        assert row is not None, "Message should be in database"
        assert row['to_address'] == 'alice@remote.example.com'
        assert row['from_address'] == 'bob@test.example.com'
        assert row['to_domain'] == 'remote.example.com'
        assert row['content'] == 'Hello, Alice!'
        assert row['status'] in ('pending', 'sending', 'delivered')  # Background task may have run
        assert row['signature'] is not None and len(row['signature']) > 0

    def test_message_has_valid_signature(self, app_client):
        """Verify the stored signature is non-trivial."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "bob@test.example.com",
                "content": "Test signature"
            }
        )

        assert response.status_code == 200
        message_id = response.json()["message_id"]

        row = env['db'].execute_single(
            "SELECT signature, sender_fingerprint FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        # Signature should be base64-encoded RSA signature (~340+ chars)
        assert row['signature'] is not None
        assert len(row['signature']) > 100
        assert row['sender_fingerprint'] == env['fingerprint']

    def test_addresses_are_normalized_to_lowercase(self, app_client):
        """Verify addresses are stored lowercase regardless of input case."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "ALICE@REMOTE.EXAMPLE.COM",
                "from_address": "BOB@TEST.EXAMPLE.COM",
                "content": "Test"
            }
        )

        assert response.status_code == 200
        message_id = response.json()["message_id"]

        row = env['db'].execute_single(
            "SELECT to_address, from_address, to_domain FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        assert row['to_address'] == 'alice@remote.example.com'
        assert row['from_address'] == 'bob@test.example.com'
        assert row['to_domain'] == 'remote.example.com'

    def test_priority_is_stored_correctly(self, app_client):
        """Verify priority values are stored in database."""
        client, service, env = app_client

        for priority in [0, 1, 2]:
            response = client.post(
                "/api/v1/messages/send",
                json={
                    "to_address": "alice@remote.example.com",
                    "from_address": "bob@test.example.com",
                    "content": f"Priority {priority}",
                    "priority": priority
                }
            )

            assert response.status_code == 200, f"Failed for priority {priority}: {response.json()}"
            message_id = response.json()["message_id"]

            row = env['db'].execute_single(
                "SELECT priority FROM lattice_messages WHERE message_id = ?",
                (message_id,)
            )

            assert row['priority'] == priority

    def test_metadata_is_stored_as_json(self, app_client):
        """Verify metadata is properly JSON-serialized in database."""
        client, service, env = app_client

        metadata = {"thread_id": "abc123", "reply_to": "msg-456", "tags": ["urgent", "work"]}

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "bob@test.example.com",
                "content": "With metadata",
                "metadata": metadata
            }
        )

        assert response.status_code == 200
        message_id = response.json()["message_id"]

        row = env['db'].execute_single(
            "SELECT metadata FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        # SQLiteClient auto-parses JSON
        assert row['metadata'] == metadata

    def test_message_expiry_is_set(self, app_client):
        """Verify messages have an expiry time set."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "bob@test.example.com",
                "content": "Test expiry"
            }
        )

        assert response.status_code == 200
        message_id = response.json()["message_id"]

        row = env['db'].execute_single(
            "SELECT expires_at FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        assert row['expires_at'] is not None

    def test_invalid_to_address_rejected(self, app_client):
        """Verify addresses without @ are rejected with 400."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "invalid-no-at-sign",
                "from_address": "bob@test.example.com",
                "content": "Test"
            }
        )

        assert response.status_code == 400

    def test_invalid_from_address_rejected(self, app_client):
        """Verify sender addresses without @ are rejected with 400."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "invalid-no-at-sign",
                "content": "Test"
            }
        )

        assert response.status_code == 400

    def test_content_over_10kb_rejected(self, app_client):
        """Verify content over 10KB is rejected by validation."""
        client, service, env = app_client

        large_content = "x" * 10001

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "bob@test.example.com",
                "content": large_content
            }
        )

        assert response.status_code == 422  # Pydantic validation error

    def test_priority_out_of_range_rejected(self, app_client):
        """Verify priority > 2 is rejected."""
        client, service, env = app_client

        response = client.post(
            "/api/v1/messages/send",
            json={
                "to_address": "alice@remote.example.com",
                "from_address": "bob@test.example.com",
                "content": "Test",
                "priority": 5
            }
        )

        assert response.status_code == 422

    def test_unique_message_ids(self, app_client):
        """Verify each message gets a unique ID."""
        client, service, env = app_client

        message_ids = set()
        for i in range(5):
            response = client.post(
                "/api/v1/messages/send",
                json={
                    "to_address": "alice@remote.example.com",
                    "from_address": "bob@test.example.com",
                    "content": f"Message {i}"
                }
            )
            assert response.status_code == 200
            message_ids.add(response.json()["message_id"])

        assert len(message_ids) == 5, "All message IDs should be unique"


class TestQueueOutboundMessageMethod:
    """Unit tests for the queue_outbound_message method."""

    def test_returns_valid_uuid(self, app_client):
        """Verify returned message_id is a valid UUID."""
        import uuid
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test"
        )

        # Should not raise
        parsed = uuid.UUID(message_id)
        assert str(parsed) == message_id

    def test_uses_correct_sender_fingerprint(self, app_client):
        """Verify message uses our server's fingerprint."""
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test"
        )

        row = env['db'].execute_single(
            "SELECT sender_fingerprint FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        assert row['sender_fingerprint'] == env['fingerprint']

    def test_raises_on_invalid_to_address(self, app_client):
        """Verify ValueError is raised for invalid addresses."""
        client, service, env = app_client

        with pytest.raises(ValueError, match="to_address"):
            service.queue_outbound_message(
                to_address="no-at-sign",
                from_address="bob@test.example.com",
                content="Test"
            )

    def test_raises_on_invalid_from_address(self, app_client):
        """Verify ValueError is raised for invalid sender addresses."""
        client, service, env = app_client

        with pytest.raises(ValueError, match="from_address"):
            service.queue_outbound_message(
                to_address="alice@remote.example.com",
                from_address="no-at-sign",
                content="Test"
            )


class TestDeliverMessageAsync:
    """Tests for the async delivery method."""

    @pytest.mark.asyncio
    async def test_successful_delivery_marks_delivered(self, app_client):
        """Verify successful HTTP delivery updates status to delivered."""
        client, service, env = app_client

        # Queue directly (bypasses background task from endpoint)
        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test delivery"
        )

        # Verify starts as pending
        row = env['db'].execute_single(
            "SELECT status FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )
        assert row['status'] == 'pending'

        # Mock successful HTTP response
        with patch.object(service, '_send_to_remote_server') as mock_send:
            mock_send.side_effect = successful_remote_response(env)
            await service.deliver_message_async(message_id)

        # Verify status is now delivered
        row = env['db'].execute_single(
            "SELECT status FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )
        assert row['status'] == 'delivered'

    @pytest.mark.asyncio
    async def test_failed_delivery_increments_attempt_count(self, app_client):
        """Verify failed delivery increments attempt count and sets error."""
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test retry"
        )

        # Mock failed HTTP response
        with patch.object(service, '_send_to_remote_server') as mock_send:
            mock_send.return_value = None  # Indicates failure
            await service.deliver_message_async(message_id)

        row = env['db'].execute_single(
            "SELECT status, attempt_count, last_error FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )

        assert row['status'] == 'pending'  # Still pending for retry
        assert row['attempt_count'] == 1
        assert row['last_error'] is not None

    @pytest.mark.asyncio
    async def test_signed_remote_rejection_fails_permanently(self, app_client):
        """Verify signed business rejections are not retried."""
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test permanent rejection"
        )

        with patch.object(service, '_send_to_remote_server') as mock_send:
            mock_send.side_effect = lambda _url, data: {
                "status": "rejected",
                "ack": make_remote_rejection_ack(env, data["message_id"], "Unknown recipient")
            }
            await service.deliver_message_async(message_id)

        row = env['db'].execute_single(
            """
            SELECT status, attempt_count, last_error, ack_received, ack_data
            FROM lattice_messages
            WHERE message_id = ?
            """,
            (message_id,)
        )
        peer = env['db'].execute_single(
            "SELECT circuit_failures FROM lattice_peers WHERE server_id = ?",
            ("remote.example.com",)
        )

        assert row['status'] == 'failed'
        assert row['attempt_count'] == 0
        assert "Unknown recipient" in row['last_error']
        assert row['ack_received'] == 1
        assert row['ack_data']['status'] == 'rejected'
        assert peer['circuit_failures'] == 0

    @pytest.mark.asyncio
    async def test_invalid_rejection_ack_is_retryable(self, app_client):
        """Verify invalid rejection acknowledgments are treated as delivery failures."""
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test invalid rejection"
        )

        with patch.object(service, '_send_to_remote_server') as mock_send:
            def invalid_rejection(_url, data):
                ack = make_remote_rejection_ack(env, data["message_id"])
                ack["signature"] = "invalid"
                return {"status": "rejected", "ack": ack}

            mock_send.side_effect = invalid_rejection
            await service.deliver_message_async(message_id)

        row = env['db'].execute_single(
            "SELECT status, attempt_count, last_error FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )
        peer = env['db'].execute_single(
            "SELECT circuit_failures FROM lattice_peers WHERE server_id = ?",
            ("remote.example.com",)
        )

        assert row['status'] == 'pending'
        assert row['attempt_count'] == 1
        assert row['last_error'] is not None
        assert peer['circuit_failures'] == 1

    @pytest.mark.asyncio
    async def test_missing_rejection_ack_is_retryable(self, app_client):
        """Verify missing acknowledgments still follow retry logic."""
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test missing ack"
        )

        with patch.object(service, '_send_to_remote_server') as mock_send:
            mock_send.return_value = {"status": "rejected"}
            await service.deliver_message_async(message_id)

        row = env['db'].execute_single(
            "SELECT status, attempt_count, last_error FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )
        peer = env['db'].execute_single(
            "SELECT circuit_failures FROM lattice_peers WHERE server_id = ?",
            ("remote.example.com",)
        )

        assert row['status'] == 'pending'
        assert row['attempt_count'] == 1
        assert row['last_error'] is not None
        assert peer['circuit_failures'] == 1

    @pytest.mark.asyncio
    async def test_nonexistent_message_handled_gracefully(self, app_client):
        """Verify delivering a nonexistent message doesn't crash."""
        client, service, env = app_client

        # Should not raise
        await service.deliver_message_async("nonexistent-uuid-12345")

    @pytest.mark.asyncio
    async def test_already_delivered_message_skipped(self, app_client):
        """Verify already-delivered messages are not reprocessed."""
        client, service, env = app_client

        message_id = service.queue_outbound_message(
            to_address="alice@remote.example.com",
            from_address="bob@test.example.com",
            content="Test skip"
        )

        # Manually mark as delivered
        env['db'].execute_update(
            "UPDATE lattice_messages SET status = 'delivered' WHERE message_id = ?",
            (message_id,)
        )

        # Mock should NOT be called
        with patch.object(service, '_send_to_remote_server') as mock_send:
            await service.deliver_message_async(message_id)
            mock_send.assert_not_called()


class TestEndToEndDelivery:
    """End-to-end tests for the full send flow with mocked remote server."""

    def test_send_endpoint_triggers_immediate_delivery(self, app_client):
        """Verify the endpoint queues AND attempts immediate delivery."""
        client, service, env = app_client

        # Mock the remote server response
        with patch.object(service, '_send_to_remote_server') as mock_send:
            mock_send.side_effect = successful_remote_response(env)

            response = client.post(
                "/api/v1/messages/send",
                json={
                    "to_address": "alice@remote.example.com",
                    "from_address": "bob@test.example.com",
                    "content": "Immediate delivery test"
                }
            )

        assert response.status_code == 200
        message_id = response.json()["message_id"]

        # Background task should have run and delivered
        row = env['db'].execute_single(
            "SELECT status FROM lattice_messages WHERE message_id = ?",
            (message_id,)
        )
        assert row['status'] == 'delivered'

        # Verify the mock was called with correct URL
        mock_send.assert_called()
        call_url = mock_send.call_args[0][0]
        assert 'remote.example.com' in call_url
        assert '/messages/receive' in call_url
