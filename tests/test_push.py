"""Tests for the MISP / OpenCTI STIX push (D20).

A real local HTTP server records the request the engine makes, so the wire
format is asserted rather than assumed. The STIX bundle is the one produced by
:class:`engine.export.stix.STIXExporter` — this suite also pins that the push
transport reuses that single producer instead of re-deriving any STIX object.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
from pathlib import Path

import pytest

from engine.export.push import (
    TAXII_CONTENT_TYPE,
    PushResult,
    PushTarget,
    push_stix,
    write_push_result,
)
from engine.export.stix import STIXExporter

TOKEN = "SUPER-SECRET-TOKEN-9f2b"


class _Recorder:
    def __init__(self, status: int = 200, body: bytes = b'{"ok":true}') -> None:
        self.requests: list[dict] = []
        self.status = status
        self.body = body


def _start_server(recorder: _Recorder) -> tuple[http.server.HTTPServer, str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib name
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            recorder.requests.append({
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": payload,
            })
            self.send_response(recorder.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(recorder.body)))
            self.end_headers()
            self.wfile.write(recorder.body)

        def log_message(self, *_args) -> None:  # silence the test server
            return

    class FastHTTPServer(http.server.HTTPServer):
        def server_bind(self) -> None:
            # ``HTTPServer.server_bind`` calls ``socket.getfqdn()``, a reverse
            # DNS lookup that can block for tens of seconds on a machine with
            # no reverse DNS. Bind the socket directly instead.
            self.socket.bind(self.server_address)
            self.server_address = self.socket.getsockname()
            host, port = self.server_address[:2]
            self.server_name = host
            self.server_port = port

    server = FastHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def server():
    recorder = _Recorder()
    srv, url = _start_server(recorder)
    try:
        yield recorder, url
    finally:
        srv.shutdown()
        srv.server_close()


def _bundle() -> dict:
    exporter = STIXExporter()
    payload = {
        "iocs": [
            {"type": "ip", "value": "185.1.2.3", "source": "static",
             "severity": "high", "context": "connect()", "confidence": "medium"},
            {"type": "domain", "value": "evil.example", "source": "static",
             "severity": "high", "context": "string", "confidence": "medium"},
        ]
    }
    return json.loads(exporter.export_iocs(payload))


def test_misp_push_uses_the_stix2_endpoint_and_api_key_header(server):
    recorder, url = server
    result = push_stix(_bundle(), PushTarget.misp(url, TOKEN))

    assert result.ok is True
    assert result.status_code == 200
    assert len(recorder.requests) == 1
    request = recorder.requests[0]
    assert request["path"] == "/events/upload_stix/2"
    assert request["headers"]["authorization"] == TOKEN
    assert request["headers"]["content-type"] == "application/json"
    # MISP takes the STIX bundle verbatim.
    body = json.loads(request["body"])
    assert body["type"] == "bundle"
    assert body["objects"]


def test_opencti_push_uses_taxii_collection_and_bearer_token(server):
    recorder, url = server
    target = PushTarget.opencti(url, TOKEN, collection="abc-123")
    result = push_stix(_bundle(), target)

    assert result.ok is True
    request = recorder.requests[0]
    assert request["path"] == "/taxii2/root/collections/abc-123/objects/"
    assert request["headers"]["authorization"] == f"Bearer {TOKEN}"
    assert request["headers"]["content-type"] == TAXII_CONTENT_TYPE
    # TAXII envelope, not a STIX bundle wrapper.
    body = json.loads(request["body"])
    assert "objects" in body
    assert body.get("type") is None


def test_push_carries_the_objects_the_single_producer_made(server):
    recorder, url = server
    bundle = _bundle()
    push_stix(bundle, PushTarget.opencti(url, TOKEN, collection="c1"))
    sent = json.loads(recorder.requests[0]["body"])["objects"]
    assert sent == bundle["objects"]


def test_non_2xx_is_fail_closed(server):
    recorder, url = server
    recorder.status = 401
    recorder.body = b'{"message":"Authentication failed"}'
    result = push_stix(_bundle(), PushTarget.misp(url, TOKEN))

    assert result.ok is False
    assert result.status_code == 401
    assert "401" in result.message


def test_transport_error_is_not_silent():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    result = push_stix(_bundle(), PushTarget.misp(f"http://127.0.0.1:{dead_port}", TOKEN))
    assert result.ok is False
    assert "transport error" in result.message


def test_result_never_contains_the_token(server):
    _, url = server
    push_stix(_bundle(), PushTarget.misp(url, TOKEN))
    result = push_stix(_bundle(), PushTarget.opencti(url, TOKEN, collection="c1"))
    assert TOKEN not in json.dumps(result.to_dict())
    assert "token" not in json.dumps(result.to_dict()).lower()


def test_from_env_requires_credentials(monkeypatch):
    for name in ("HATCHERY_MISP_URL", "HATCHERY_MISP_API_KEY",
                 "HATCHERY_OPENCTI_URL", "HATCHERY_OPENCTI_TOKEN",
                 "HATCHERY_OPENCTI_COLLECTION"):
        monkeypatch.delenv(name, raising=False)
    assert PushTarget.from_env("misp") is None
    assert PushTarget.from_env("opencti") is None

    monkeypatch.setenv("HATCHERY_MISP_URL", "https://misp.local")
    monkeypatch.setenv("HATCHERY_MISP_API_KEY", TOKEN)
    target = PushTarget.from_env("misp")
    assert target is not None and target.kind == "misp"

    # OpenCTI also needs its TAXII collection.
    monkeypatch.setenv("HATCHERY_OPENCTI_URL", "https://opencti.local")
    monkeypatch.setenv("HATCHERY_OPENCTI_TOKEN", TOKEN)
    assert PushTarget.from_env("opencti") is None
    monkeypatch.setenv("HATCHERY_OPENCTI_COLLECTION", "c1")
    assert PushTarget.from_env("opencti") is not None


def test_opencti_target_requires_a_collection():
    with pytest.raises(ValueError):
        PushTarget.opencti("https://opencti.local", TOKEN, collection="")


def test_invalid_bundle_is_refused_without_a_request(server):
    recorder, url = server
    result = push_stix({"type": "indicator"}, PushTarget.misp(url, TOKEN))
    assert result.ok is False
    assert "refusing to push" in result.message
    assert recorder.requests == []


def test_write_push_result_omits_credentials(tmp_path: Path, server):
    _, url = server
    target = PushTarget.misp(url, TOKEN)
    result = push_stix(_bundle(), target)
    path = write_push_result(tmp_path, target, result)
    text = path.read_text(encoding="utf-8")
    assert TOKEN not in text
    payload = json.loads(text)
    assert payload["target"] == "misp"
    assert payload["ok"] is True


def test_push_result_shape():
    result = PushResult(ok=False, target="misp", url="https://x")
    assert result.to_dict() == {
        "ok": False, "target": "misp", "url": "https://x",
        "status_code": 0, "message": "", "objects": 0,
    }
