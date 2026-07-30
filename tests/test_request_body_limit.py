import json
import os
import tempfile

import pytest

MAX_REQUEST_BODY_BYTES = 1024 * 1024


@pytest.fixture
def daemon_app(monkeypatch):
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    monkeypatch.setenv("LATTICE_DB_PATH", db_path)

    from lattice.discovery_daemon import app

    yield app

    os.unlink(db_path)


async def call_app(app, body_chunks, headers):
    sent_messages = []
    chunks = list(body_chunks)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/messages/send",
        "raw_path": b"/api/v1/messages/send",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80)
    }

    async def receive():
        if chunks:
            body = chunks.pop(0)
            return {
                "type": "http.request",
                "body": body,
                "more_body": bool(chunks)
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent_messages.append(message)

    await app(scope, receive, send)
    return sent_messages


def response_status(sent_messages):
    for message in sent_messages:
        if message["type"] == "http.response.start":
            return message["status"]
    raise AssertionError("No response start message sent")


def response_body(sent_messages):
    body = b"".join(
        message.get("body", b"")
        for message in sent_messages
        if message["type"] == "http.response.body"
    )
    return json.loads(body)


@pytest.mark.asyncio
async def test_declared_oversized_body_is_rejected_before_parsing(daemon_app):
    sent = await call_app(
        daemon_app,
        body_chunks=[b""],
        headers=[
            (b"host", b"testserver"),
            (b"content-type", b"application/json"),
            (b"content-length", str(MAX_REQUEST_BODY_BYTES + 1).encode())
        ]
    )

    assert response_status(sent) == 413
    assert response_body(sent)["detail"] == "Request body too large"


@pytest.mark.asyncio
async def test_chunked_oversized_body_without_content_length_is_rejected(daemon_app):
    sent = await call_app(
        daemon_app,
        body_chunks=[
            b"x" * (MAX_REQUEST_BODY_BYTES // 2),
            b"x" * (MAX_REQUEST_BODY_BYTES // 2 + 1)
        ],
        headers=[
            (b"host", b"testserver"),
            (b"content-type", b"application/json")
        ]
    )

    assert response_status(sent) == 413
    assert response_body(sent)["detail"] == "Request body too large"
