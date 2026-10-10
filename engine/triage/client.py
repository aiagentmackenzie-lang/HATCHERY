"""A minimal, local-first Ollama client for triage.

Two things this client refuses to do, because they are the difference between
"the sample never leaves the box" and a lie:

1. **A non-loopback endpoint.** ``http://127.0.0.1:11434`` is the default and a
   remote host is refused unless ``allow_remote=True``. The CLI exposes that as
   ``--allow-remote-model`` and the run says so.
2. **A ``:cloud`` model.** This one is subtle and easy to get wrong: a
   ``:cloud`` model is still reached through *localhost* — Ollama proxies the
   request to the vendor — so a loopback-only check does **not** stop
   sample-derived text from leaving the machine. The client inspects the model
   metadata (``remote_host`` / ``:cloud`` namespace) and refuses a remote model
   unless ``allow_cloud_model=True``. Both flags are reported in the run.

The client talks to the documented HTTP API directly (``/api/tags``,
``/api/chat``) with ``httpx``, which is already a runtime dependency. Responses
are requested with a JSON-schema ``format`` so decoding is constrained, but the
schema is re-validated by :mod:`engine.triage.contract` regardless: the runtime
is not the validator.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://127.0.0.1:11434"

# Small local models, most-capable first. Only a *local* model is auto-selected;
# a machine that has only cloud models gets an honest "unavailable" instead of a
# silent upload. The operator can always name a model explicitly.
DEFAULT_MODEL_PREFERENCE = (
    "llama3.1:8b",
    "qwen2.5:7b",
    "mistral:7b",
    "gemma3:4b",
    "llama3.2:3b",
    "phi4-mini:latest",
    "gemma3:1b",
)

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class OllamaError(RuntimeError):
    """Any failure talking to Ollama. The message never contains sample data."""


@runtime_checkable
class TriageClient(Protocol):
    """The small surface :func:`engine.triage.triage.run_triage` depends on.

    :class:`OllamaClient` satisfies it; tests supply a fake with the same shape.
    """

    base_url: str
    model: str

    def resolve_model(self) -> str:
        """Return the model to use, or raise :class:`OllamaError`."""
        ...

    def chat(
        self, messages: list[dict[str, str]], schema: dict[str, Any], *, model: Optional[str] = None
    ) -> str:
        """Return the raw assistant content, or raise :class:`OllamaError`."""
        ...


def is_loopback(host: str) -> bool:
    """True for a host that cannot leave this machine."""
    if not host:
        return True
    if host in _LOCAL_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def is_local_model(info: dict[str, Any]) -> bool:
    """True when Ollama reports the model as running on this machine.

    Older Ollama versions omit ``remote_host``; the ``:cloud`` name suffix is the
    reliable marker for the hosted models.
    """
    name = str(info.get("name") or info.get("model") or "")
    if name.endswith(":cloud"):
        return False
    if info.get("remote_host"):
        return False
    details = info.get("details")
    if isinstance(details, dict) and details.get("remote_host"):
        return False
    return True


def supports_completion(info: dict[str, Any]) -> bool:
    """True when the model can generate text (not embedding-only)."""
    capabilities = info.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        return True
    return "completion" in capabilities


def pick_model(infos: list[dict[str, Any]], preferred: tuple[str, ...] = DEFAULT_MODEL_PREFERENCE) -> Optional[str]:
    """Choose a local completion model, preferring the documented order.

    Falls back to any local completion model so an operator with a model not on
    the list is not blocked, but never returns a remote model.
    """
    local = [i for i in infos if is_local_model(i) and supports_completion(i)]
    names = [str(i.get("name") or i.get("model") or "") for i in local]
    for candidate in preferred:
        if candidate in names:
            return candidate
    return names[0] if names else None


@dataclass
class OllamaClient:
    """Local Ollama chat client with structured-output support."""

    model: str = ""
    base_url: str = DEFAULT_BASE_URL
    timeout: float = 180.0
    num_ctx: int = 8192
    temperature: float = 0.0
    seed: int = 0
    allow_remote: bool = False
    allow_cloud_model: bool = False
    keep_alive: str = "5m"
    client: Optional[httpx.Client] = field(default=None, repr=False, compare=False)
    _resolved_model: Optional[str] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https"):
            raise OllamaError(f"Ollama base URL must be http(s), got {self.base_url!r}")
        host = parsed.hostname or ""
        if not self.allow_remote and not is_loopback(host):
            raise OllamaError(
                f"refusing non-loopback Ollama endpoint {host!r}: sample-derived text "
                "would leave this machine. Pass allow_remote=True "
                "(--allow-remote-model) to override."
            )

    # ------------------------------------------------------------- transport

    def _http(self) -> httpx.Client:
        if self.client is not None:
            return self.client
        return httpx.Client(timeout=self.timeout)

    def _owned(self) -> bool:
        return self.client is None

    def _get(self, path: str, *, timeout: Optional[float] = None) -> Any:
        http = self._http()
        try:
            response = http.get(
                self.base_url.rstrip("/") + path,
                timeout=timeout if timeout is not None else self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise OllamaError(
                f"Ollama request failed ({type(exc).__name__}); is it running at "
                f"{self.base_url}?"
            ) from exc
        finally:
            if self._owned():
                http.close()

    def list_models(self, *, timeout: float = 10.0) -> list[dict[str, Any]]:
        """Return the model list, raising :class:`OllamaError` if unreachable."""
        payload = self._get("/api/tags", timeout=timeout)
        models = payload.get("models") if isinstance(payload, dict) else None
        if not isinstance(models, list):
            raise OllamaError("Ollama returned an unexpected /api/tags payload")
        return [m for m in models if isinstance(m, dict)]

    def is_available(self) -> bool:
        """Cheap reachability probe; never raises."""
        try:
            self.list_models()
            return True
        except OllamaError:
            return False

    # ----------------------------------------------------------------- model

    def model_info(self, name: str) -> Optional[dict[str, Any]]:
        for info in self.list_models():
            if str(info.get("name") or info.get("model") or "") == name:
                return info
        return None

    def resolve_model(self) -> str:
        """Return the model to use, verifying it exists and is allowed.

        When no model is configured, a local completion model is auto-selected.
        Raises :class:`OllamaError` when nothing suitable (or allowed) is
        available — never falls back to a remote model silently.
        """
        if self._resolved_model:
            return self._resolved_model

        available = self.list_models()
        name = self.model.strip()

        if not name:
            picked = pick_model(available)
            if not picked:
                has_remote = any(not is_local_model(i) for i in available)
                hint = (
                    "Only remote (`:cloud`) models are installed; "
                    "install a local model or pass allow_cloud_model=True."
                    if has_remote
                    else "No usable local model is installed."
                )
                raise OllamaError(f"No triage model available. {hint}")
            name = picked

        info = next(
            (i for i in available if str(i.get("name") or i.get("model") or "") == name),
            None,
        )
        if info is None:
            raise OllamaError(
                f"model {name!r} is not installed in Ollama; available: "
                + ", ".join(sorted(str(i.get('name') or '') for i in available))[:300]
            )
        if not supports_completion(info):
            raise OllamaError(f"model {name!r} cannot generate text (embedding-only)")
        if not is_local_model(info) and not self.allow_cloud_model:
            raise OllamaError(
                f"model {name!r} runs remotely and would send sample-derived text "
                "off this machine; pass allow_cloud_model=True to override."
            )

        self._resolved_model = name
        return name

    # ------------------------------------------------------------------ chat

    def chat(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        model: Optional[str] = None,
    ) -> str:
        """Send one chat request and return the raw assistant content.

        Raises :class:`OllamaError` on transport failure or timeout; a malformed
        response is the caller's to validate.
        """
        target = model or self.resolve_model()
        body = {
            "model": target,
            "messages": messages,
            "stream": False,
            "format": schema,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
            },
        }
        http = self._http()
        try:
            response = http.post(
                self.base_url.rstrip("/") + "/api/chat",
                json=body,
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.TimeoutException as exc:
            raise OllamaError(f"Ollama request timed out after {self.timeout:.0f}s") from exc
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama chat failed ({type(exc).__name__})") from exc
        finally:
            if self._owned():
                http.close()

        message = payload.get("message") if isinstance(payload, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise OllamaError("Ollama response contained no message content")
        return content


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MODEL_PREFERENCE",
    "OllamaClient",
    "OllamaError",
    "TriageClient",
    "is_local_model",
    "is_loopback",
    "pick_model",
    "supports_completion",
]
