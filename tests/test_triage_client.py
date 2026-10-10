"""The Ollama client: local by default, and it refuses a `:cloud` model.

The cloud-model case is the subtle one: a `:cloud` model is reached through
*localhost*, so a loopback-only check does not stop sample text leaving the
machine. These tests pin that distinction.
"""

from __future__ import annotations

import httpx
import pytest

from engine.triage.client import (
    OllamaClient,
    OllamaError,
    is_local_model,
    is_loopback,
    pick_model,
    supports_completion,
)


def _router(tags: dict, chat: dict | None = None, status: int = 200):
    """A mock transport handler that routes /api/tags and /api/chat."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json=tags)
        if status != 200:
            return httpx.Response(status, text="boom")
        return httpx.Response(200, json=chat or {})

    return handler


def _client(handler, **kwargs) -> OllamaClient:
    transport = httpx.MockTransport(handler)
    return OllamaClient(client=httpx.Client(transport=transport), **kwargs)


LOCAL_TAGS = {
    "models": [
        {"name": "mistral:7b", "capabilities": ["completion", "tools"], "details": {}},
        {"name": "gemma3:4b", "capabilities": ["completion", "vision"], "details": {}},
        {"name": "nomic-embed-text:latest", "capabilities": ["embedding"], "details": {}},
        {"name": "kimi-k2.6:cloud", "remote_host": "https://ollama.com:443",
         "capabilities": ["completion"], "details": {}},
    ]
}

CLOUD_ONLY_TAGS = {"models": [
    {"name": "gpt-oss:120b-cloud", "remote_host": "https://ollama.com:443",
     "capabilities": ["completion"], "details": {}},
]}


def test_loopback_detection() -> None:
    assert is_loopback("127.0.0.1")
    assert is_loopback("localhost")
    assert is_loopback("::1")
    assert not is_loopback("10.0.0.5")
    assert not is_loopback("ollama.example.com")


def test_local_model_detection() -> None:
    assert is_local_model({"name": "mistral:7b", "details": {}})
    assert not is_local_model({"name": "kimi:cloud"})
    assert not is_local_model({"name": "x", "remote_host": "https://ollama.com"})


def test_completion_support_detection() -> None:
    assert supports_completion({"capabilities": ["completion"]})
    assert not supports_completion({"capabilities": ["embedding"]})
    assert supports_completion({})  # older Ollama omits capabilities


def test_non_loopback_endpoint_is_refused_by_default() -> None:
    with pytest.raises(OllamaError, match="non-loopback"):
        OllamaClient(base_url="http://10.0.0.5:11434")


def test_non_loopback_endpoint_allowed_with_flag() -> None:
    client = OllamaClient(base_url="http://10.0.0.5:11434", allow_remote=True)
    assert client.base_url.endswith("11434")


def test_bad_scheme_is_refused() -> None:
    with pytest.raises(OllamaError, match="http"):
        OllamaClient(base_url="ftp://127.0.0.1:11434")


def test_pick_model_prefers_the_documented_order_and_skips_remote_and_embedding() -> None:
    assert pick_model(LOCAL_TAGS["models"]) == "mistral:7b"
    assert pick_model([{"name": "gemma3:4b", "capabilities": ["completion"]}]) == "gemma3:4b"
    assert pick_model([{"name": "x:cloud", "capabilities": ["completion"]}]) is None


def test_resolve_model_auto_picks_a_local_model() -> None:
    client = _client(lambda request: httpx.Response(200, json=LOCAL_TAGS))
    assert client.resolve_model() == "mistral:7b"


def test_resolve_model_refuses_a_cloud_model_by_default() -> None:
    client = _client(
        lambda request: httpx.Response(200, json=LOCAL_TAGS),
        model="kimi-k2.6:cloud",
    )
    with pytest.raises(OllamaError, match="remote"):
        client.resolve_model()


def test_resolve_model_allows_a_cloud_model_with_flag() -> None:
    client = _client(
        lambda request: httpx.Response(200, json=LOCAL_TAGS),
        model="kimi-k2.6:cloud",
        allow_cloud_model=True,
    )
    assert client.resolve_model() == "kimi-k2.6:cloud"


def test_resolve_model_reports_when_only_cloud_models_exist() -> None:
    client = _client(lambda request: httpx.Response(200, json=CLOUD_ONLY_TAGS))
    with pytest.raises(OllamaError, match="remote"):
        client.resolve_model()


def test_resolve_model_rejects_an_uninstalled_model() -> None:
    client = _client(lambda request: httpx.Response(200, json=LOCAL_TAGS), model="llama9:900b")
    with pytest.raises(OllamaError, match="not installed"):
        client.resolve_model()


def test_resolve_model_rejects_an_embedding_only_model() -> None:
    client = _client(
        lambda request: httpx.Response(200, json=LOCAL_TAGS),
        model="nomic-embed-text:latest",
    )
    with pytest.raises(OllamaError, match="embedding"):
        client.resolve_model()


def test_chat_sends_a_schema_and_returns_the_content() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json=LOCAL_TAGS)
        captured["body"] = request.read().decode()
        return httpx.Response(
            200, json={"message": {"role": "assistant", "content": '{"ok": true}'}}
        )

    client = _client(handler, model="mistral:7b")
    content = client.chat([{"role": "user", "content": "hi"}], {"type": "object"})
    assert content == '{"ok": true}'
    assert '"format"' in captured["body"]
    assert '"num_ctx"' in captured["body"]


def test_chat_raises_ollama_error_on_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    client = _client(handler, model="mistral:7b", timeout=1.0)
    with pytest.raises(OllamaError, match="timed out"):
        client.chat([{"role": "user", "content": "hi"}], {"type": "object"}, model="mistral:7b")


def test_chat_raises_ollama_error_on_a_bad_status() -> None:
    client = _client(lambda request: httpx.Response(500, text="boom"), model="mistral:7b")
    with pytest.raises(OllamaError, match="chat failed"):
        client.chat([{"role": "user", "content": "hi"}], {"type": "object"}, model="mistral:7b")


def test_is_available_is_false_when_ollama_is_down() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    assert _client(handler).is_available() is False
