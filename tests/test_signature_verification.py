"""
Test signature verification in gossip protocol.

Verifies that announcements can be signed, serialized, deserialized,
and signature-verified correctly across the gossip protocol flow.
"""

import json
import pytest
from cryptography.hazmat.primitives import serialization

from federation.gossip_protocol import GossipProtocol
from federation.models import ServerAnnouncement, ServerEndpoints


def test_announcement_signature_roundtrip():
    """Test that announcement signatures survive serialization/deserialization."""
    # Initialize gossip protocol
    gossip = GossipProtocol()

    # Fail explicitly if federation identity is missing
    assert gossip._server_id, (
        "Federation identity not initialized. "
        "Run 'python -c \"from federation.init_federation import ensure_federation_identity; ensure_federation_identity()\"' "
        "to create server identity before running tests."
    )

    # Create announcement
    announcement = ServerAnnouncement(
        server_id=gossip._server_id,
        server_uuid=gossip._server_uuid,
        public_key=gossip._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        endpoints=ServerEndpoints(
            federation="https://example.com/api/federation",
            discovery="https://example.com/api/discovery"
        ),
        signature=""  # Will be set after signing
    )

    # Sign the announcement
    announcement_dict = announcement.model_dump(exclude={'signature'})
    canonical_json_before = json.dumps(announcement_dict, sort_keys=True)
    announcement.signature = gossip.sign_message(announcement_dict)

    # Verify signature was generated
    assert announcement.signature, "Signature should not be empty"
    assert len(announcement.signature) > 0, "Signature should have content"

    # Simulate serialization to gossip message payload
    payload = announcement.model_dump()

    # Verify payload structure
    assert 'signature' in payload, "Payload should include signature"
    assert payload['signature'] == announcement.signature, "Signature should match"

    # Simulate reconstruction from gossip message (what remote server does)
    reconstructed = ServerAnnouncement(**payload)

    # Verify reconstruction preserves data
    assert reconstructed.server_id == announcement.server_id
    assert reconstructed.signature == announcement.signature

    # Verify signature (mimics process_gossip_message)
    reconstructed_dict = reconstructed.model_dump(exclude={'signature'})
    canonical_json_after = json.dumps(reconstructed_dict, sort_keys=True)

    # Critical check: Canonical JSON must be identical
    assert canonical_json_before == canonical_json_after, (
        "Canonical JSON mismatch between original and reconstructed. "
        "This indicates Pydantic serialization is not idempotent."
    )

    # Verify signature using the announcement's own public key (self-signed)
    verification_result = gossip.verify_signature(
        reconstructed_dict,
        reconstructed.signature,
        reconstructed.public_key
    )

    assert verification_result, (
        "Signature verification failed. Possible causes: "
        "1) Signature generation bug, "
        "2) Key mismatch, "
        "3) Canonical JSON mismatch"
    )


def test_signature_verification_rejects_tampered_message():
    """Test that signature verification rejects tampered messages."""
    gossip = GossipProtocol()

    assert gossip._server_id, (
        "Federation identity not initialized. Cannot test signature rejection without server keys."
    )

    # Create and sign announcement
    announcement = ServerAnnouncement(
        server_id=gossip._server_id,
        server_uuid=gossip._server_uuid,
        public_key=gossip._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        endpoints=ServerEndpoints(
            federation="https://example.com/api/federation",
            discovery="https://example.com/api/discovery"
        ),
        signature=""
    )

    announcement_dict = announcement.model_dump(exclude={'signature'})
    announcement.signature = gossip.sign_message(announcement_dict)

    # Tamper with the message
    tampered_dict = announcement_dict.copy()
    tampered_dict['server_id'] = "evil.hacker.com"

    # Verify that signature verification fails for tampered message
    verification_result = gossip.verify_signature(
        tampered_dict,
        announcement.signature,
        announcement.public_key
    )

    assert not verification_result, "Signature verification should reject tampered messages"


def test_signature_verification_with_wrong_key():
    """Test that signature verification fails with wrong public key."""
    gossip = GossipProtocol()

    assert gossip._server_id, (
        "Federation identity not initialized. Cannot test key mismatch without server keys."
    )

    # Generate a different keypair
    wrong_private, wrong_public = gossip.generate_keypair()

    # Create and sign announcement with gossip's key
    announcement = ServerAnnouncement(
        server_id=gossip._server_id,
        server_uuid=gossip._server_uuid,
        public_key=gossip._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        endpoints=ServerEndpoints(
            federation="https://example.com/api/federation",
            discovery="https://example.com/api/discovery"
        ),
        signature=""
    )

    announcement_dict = announcement.model_dump(exclude={'signature'})
    announcement.signature = gossip.sign_message(announcement_dict)

    # Try to verify with wrong public key
    verification_result = gossip.verify_signature(
        announcement_dict,
        announcement.signature,
        wrong_public  # Wrong key!
    )

    assert not verification_result, "Signature verification should fail with wrong public key"
