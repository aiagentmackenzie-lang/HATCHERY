"""Push a run's STIX 2.1 bundle to MISP or OpenCTI — one producer, two transports.

The engine already produces exactly **one** STIX 2.1 bundle per run
(:mod:`engine.export.stix`). This module does not re-derive STIX; it reads that
bundle and transports it to a threat-intelligence platform:

* **MISP** — ``POST {url}/events/upload_stix/2`` with the bundle JSON as the
  request body and ``Authorization: <api key>``. This is STIX 2.1 import, not
  the STIX 1 endpoint (``/events/upload_stix``), whose URL differs by a trailing
  path segment. (Contract verified against MISP's ``tools/ingest_stix`` and
  PyMISP's ``upload_stix``.)
* **OpenCTI** — ``POST {url}/taxii2/root/collections/{collection}/objects/``
  with a TAXII 2.1 envelope (``{"objects": [...]}``), a
  ``application/taxii+json;version=2.1`` content type and
  ``Authorization: Bearer <token>``. This is the documented TAXII Push
  ingester endpoint.

Both are fail-closed: a non-2xx response or a transport error returns
``ok=False`` with the reason, never a silent success. The API token is never
included in a result, a log line or an on-disk artefact.

The wire format is tested against a local HTTP server; a live MISP/OpenCTI
instance is not required to exercise it, and live-instance compatibility is
stated as untested in :file:`docs/DECISIONS.md` (D20).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

MISP_STIX2_PATH = "/events/upload_stix/2"
OPENCTI_TAXII_OBJECTS_PATH = "/taxii2/root/collections/{collection}/objects/"
TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"

KINDS = ("misp", "opencti")


def _env_flag(name: str, default: bool = True) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off")


@dataclass
class PushTarget:
    """Where a STIX bundle goes, and with what credentials."""

    kind: str
    url: str
    token: str
    collection: str = ""
    verify_tls: bool = True
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown push target kind: {self.kind!r}")

    @classmethod
    def misp(cls, url: str, token: str, *, verify_tls: bool = True,
             timeout: float = 30.0) -> "PushTarget":
        return cls("misp", url, token, verify_tls=verify_tls, timeout=timeout)

    @classmethod
    def opencti(cls, url: str, token: str, collection: str, *,
                verify_tls: bool = True, timeout: float = 30.0) -> "PushTarget":
        if not collection:
            raise ValueError("OpenCTI push requires a TAXII collection id")
        return cls("opencti", url, token, collection=collection,
                   verify_tls=verify_tls, timeout=timeout)

    @classmethod
    def from_env(cls, kind: str) -> Optional["PushTarget"]:
        """Build a target from environment variables, or ``None`` if unset."""
        if kind == "misp":
            url = os.environ.get("HATCHERY_MISP_URL", "").strip()
            token = os.environ.get("HATCHERY_MISP_API_KEY", "").strip()
            if not url or not token:
                return None
            return cls.misp(url, token, verify_tls=_env_flag("HATCHERY_MISP_VERIFY_TLS"))
        if kind == "opencti":
            url = os.environ.get("HATCHERY_OPENCTI_URL", "").strip()
            token = os.environ.get("HATCHERY_OPENCTI_TOKEN", "").strip()
            collection = os.environ.get("HATCHERY_OPENCTI_COLLECTION", "").strip()
            if not url or not token or not collection:
                return None
            return cls.opencti(url, token, collection,
                               verify_tls=_env_flag("HATCHERY_OPENCTI_VERIFY_TLS"))
        raise ValueError(f"unknown push target kind: {kind!r}")

    def endpoint(self) -> str:
        base = self.url.rstrip("/")
        if self.kind == "misp":
            return base + MISP_STIX2_PATH
        return base + OPENCTI_TAXII_OBJECTS_PATH.format(collection=self.collection)

    def headers(self) -> dict[str, str]:
        if self.kind == "misp":
            return {
                "Authorization": self.token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": TAXII_CONTENT_TYPE,
            "Content-Type": TAXII_CONTENT_TYPE,
        }


@dataclass
class PushResult:
    """The outcome of one push. Never carries the token."""

    ok: bool
    target: str
    url: str
    status_code: int = 0
    message: str = ""
    objects: int = 0

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "target": self.target,
            "url": self.url,
            "status_code": self.status_code,
            "message": self.message,
            "objects": self.objects,
        }


def _validate_bundle(bundle: object) -> dict:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("not a STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX bundle has no objects list")
    return bundle


def _request_body(bundle: dict, target: PushTarget) -> bytes:
    """Build the transport body without re-deriving any STIX object.

    MISP takes the STIX bundle verbatim; OpenCTI's TAXII endpoint takes the
    standard TAXII envelope around the same objects.
    """
    if target.kind == "misp":
        return json.dumps(bundle).encode("utf-8")
    return json.dumps({"objects": bundle["objects"]}).encode("utf-8")


def push_stix(
    bundle: dict,
    target: PushTarget,
    *,
    client: Optional[httpx.Client] = None,
) -> PushResult:
    """POST a STIX bundle to ``target``. Returns a result; never raises for HTTP errors."""
    try:
        _validate_bundle(bundle)
    except ValueError as exc:
        return PushResult(ok=False, target=target.kind, url=target.endpoint(),
                          message=f"refusing to push: {exc}")

    endpoint = target.endpoint()
    body = _request_body(bundle, target)
    objects = len(bundle.get("objects", []))

    owns_client = client is None
    http = client or httpx.Client(
        verify=target.verify_tls,
        timeout=target.timeout,
        follow_redirects=False,
    )
    try:
        response = http.post(endpoint, content=body, headers=target.headers())
    except httpx.HTTPError as exc:
        # The exception text can contain the URL but never the token.
        logger.warning("Push to %s failed at the transport layer: %s",
                       target.kind, type(exc).__name__)
        return PushResult(ok=False, target=target.kind, url=endpoint,
                          message=f"transport error: {type(exc).__name__}: {exc}")
    finally:
        if owns_client:
            http.close()

    ok = 200 <= response.status_code < 300
    detail = response.text[:400].replace("\n", " ") if response.text else ""
    message = "accepted" if ok else f"HTTP {response.status_code}: {detail}"
    logger.info("Push to %s: %s", target.kind, message)
    return PushResult(ok=ok, target=target.kind, url=endpoint,
                      status_code=response.status_code, message=message,
                      objects=objects)


def write_push_result(run_dir, target: PushTarget, result: PushResult):
    """Persist a push outcome next to the run, without credentials."""
    from pathlib import Path

    path = Path(run_dir) / f"push-{target.kind}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path
