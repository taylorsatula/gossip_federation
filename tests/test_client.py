import json

import httpx

from lattice.client import FederatedMessage, LatticeClient


def test_send_federated_message_maps_public_model_to_daemon_api(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={"status": "queued", "message_id": "msg-1", "immediate_delivery": True}
        )

    monkeypatch.setenv("LATTICE_ADMIN_TOKEN", "env-token")
    client = LatticeClient(base_url="http://lattice.test")
    client.client = httpx.Client(transport=httpx.MockTransport(handler))

    try:
        response = client.send_federated_message(
            FederatedMessage(
                to_address="alice@remote.example.com",
                from_address="bob@test.example.com",
                content="hello",
                message_type="ai_to_ai",
                priority=2,
                reply_to="msg-0",
                federation_metadata={"thread_id": "thread-1"}
            )
        )
    finally:
        client.close()

    payload = json.loads(requests[0].content)

    assert response["message_id"] == "msg-1"
    assert requests[0].headers["X-Lattice-Admin-Token"] == "env-token"
    assert payload == {
        "to_address": "alice@remote.example.com",
        "from_address": "bob@test.example.com",
        "content": "hello",
        "message_type": "ai_to_ai",
        "priority": 2,
        "metadata": {
            "thread_id": "thread-1",
            "reply_to": "msg-0",
            "content_type": "text/plain"
        }
    }


def test_explicit_admin_token_takes_precedence_over_environment(monkeypatch):
    monkeypatch.setenv("LATTICE_ADMIN_TOKEN", "env-token")

    client = LatticeClient(base_url="http://lattice.test", admin_token="explicit-token")
    try:
        assert client._admin_headers() == {"X-Lattice-Admin-Token": "explicit-token"}
    finally:
        client.close()
