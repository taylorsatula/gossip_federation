from unittest.mock import Mock

from lattice.domain_registration import DomainRegistrationService


class FakePeerManager:
    def __init__(self, peer=None, neighbors=None):
        self.peer = peer
        self.neighbors = neighbors or []

    def get_peer_by_domain(self, _domain):
        return self.peer

    def get_active_neighbors(self):
        return self.neighbors


class FakeGossipProtocol:
    def __init__(self):
        self.signed_payloads = []

    def get_server_id(self):
        return "injected.example.com"

    def sign_message(self, payload):
        self.signed_payloads.append(payload)
        return "signed-by-injected-gossip"


def test_own_domain_result_is_valid_and_confident():
    service = DomainRegistrationService(
        db=Mock(),
        peer_manager=FakePeerManager(peer={"server_uuid": "server-uuid"}),
        gossip_protocol=FakeGossipProtocol()
    )

    result = service.verify_domain_availability("local.example.com", "server-uuid")

    assert result.available is True
    assert result.confidence == 1.0
    assert result.servers_queried == 0


def test_domain_queries_are_signed_with_injected_gossip_protocol():
    gossip = FakeGossipProtocol()
    service = DomainRegistrationService(
        db=Mock(),
        peer_manager=FakePeerManager(),
        gossip_protocol=gossip
    )

    result = service.verify_domain_availability("new.example.com", "requester-uuid")

    assert result.available is True
    assert gossip.signed_payloads
    assert gossip.signed_payloads[0]["requester"] == "injected.example.com"
    assert "signature" not in gossip.signed_payloads[0]
