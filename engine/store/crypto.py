"""Encryption at rest for the sample store (D28).

Design in one paragraph: a stored sample is an **AEAD envelope** — AES-256-GCM
from ``cryptography`` — whose header is authenticated as additional data, so a
tampered version byte, key id, nonce, length or ciphertext all fail the same
authentication check rather than being half-parsed. The envelope is versioned and
carries a key *id* (a truncated hash of the key, never the key), so a wrong key
is reported as a wrong key instead of as a corrupt file. Decryption verifies the
plaintext SHA-256 against the content address before a caller ever sees bytes.

Key material comes from ``HATCHERY_SAMPLE_KEY`` (hex or base64, 32 bytes) or a
``HATCHERY_SAMPLE_KEY_FILE`` — which must be a regular, non-symlink file with no
group/other permission bits. When nothing is configured, the store **generates**
a local key at ``<store>/.sample-key`` (0600) and says so loudly; it never falls
back to writing plaintext. A generated local key protects against plaintext at
rest (backups, snapshots, a copied directory); it does not protect against an
attacker who can read the store directory itself. That distinction is documented
rather than implied.

Nothing in this module writes key material to a log, an exception message, a
database row or a bundle. ``key_id`` is a one-way hash prefix and is safe to
print.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from engine.store.errors import (
    AUTH_FAILED,
    HASH_MISMATCH,
    KEY_FILE_EXISTS,
    KEY_FILE_MISSING,
    KEY_FILE_PERMISSIONS,
    KEY_FILE_SYMLINK,
    KEY_INVALID,
    KEY_RING_INVALID,
    KEY_RING_NEWER,
    TRUNCATED,
    UNKNOWN_KEY_ID,
    UNKNOWN_VERSION,
    WRONG_KEY,
    SampleStoreError,
)

MAGIC = b"HATCHERY-SAMPLE\x00"
ENVELOPE_VERSION = 1
KEY_LEN = 32
KEY_ID_LEN = 8
NONCE_LEN = 12
LEN_LEN = 8
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 1 + KEY_ID_LEN + NONCE_LEN + LEN_LEN
ENVELOPE_ALGORITHM = "aes-256-gcm"
ENVELOPE_LABEL = f"{ENVELOPE_ALGORITHM}/v{ENVELOPE_VERSION}"
LEGACY_LABEL = "plaintext-legacy"

KEY_FILE_NAME = ".sample-key"
MAX_KEY_FILE_BYTES = 4096

# The key ring is the store's own record of key lifecycle (D29). It is a small,
# versioned JSON document, 0600 like any other secret, holding the active key and
# every retired key still needed to read an old blob. It is only created by an
# explicit rotation; a D28 store with a lone env var or .sample-key has no ring
# and keeps working exactly as before.
KEY_RING_NAME = ".sample-keyring"
KEY_RING_VERSION = 1
MAX_KEY_RING_BYTES = 64 * 1024
MAX_KEY_RING_KEYS = 32
# A hostile envelope may declare a 2**64 length; refuse to allocate before that.
MAX_DECLARED_PLAINTEXT = 1 << 32  # 4 GiB


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SampleKey:
    """A loaded key. ``material`` must never be printed."""

    material: bytes
    source: str
    key_id: str
    generated: bool = False
    created_at: Optional[str] = None

    def __repr__(self) -> str:  # never leak the key through a repr/log line
        return f"SampleKey(source={self.source!r}, key_id={self.key_id!r})"

    def __str__(self) -> str:
        return f"key id {self.key_id} from {self.source}"


def key_id_for(material: bytes) -> str:
    """A stable, non-reversible id for a key (16 hex characters)."""
    return hashlib.sha256(b"hatchery-sample-key\x00" + material).hexdigest()[: KEY_ID_LEN * 2]


@dataclass(frozen=True)
class KeyRing:
    """An active key plus every retired key this store may still need.

    Decryption resolves the envelope's key id **by id** through
    :meth:`get`. There is no trial decryption and no "first key that works": a
    blob names its key, and a missing key is a precise failure rather than a
    search. ``repr`` is safe: :class:`SampleKey` never renders material.
    """

    active: SampleKey
    keys: Mapping[str, SampleKey] = field(default_factory=dict)
    source: str = ""
    ring_path: Optional[Path] = None
    env_ignored: bool = False
    rotation_in_progress: bool = False
    rotation_started_at: Optional[str] = None
    rotation_from: Optional[str] = None

    def __post_init__(self) -> None:
        # Always include the active key, even when a caller built the ring by hand.
        if self.active.key_id not in self.keys:
            object.__setattr__(
                self, "keys", {**dict(self.keys), self.active.key_id: self.active}
            )

    def get(self, key_id: str) -> Optional[SampleKey]:
        return self.keys.get(key_id)

    def ids(self) -> list[str]:
        return sorted(self.keys)

    def retired_ids(self) -> list[str]:
        return [key_id for key_id in self.ids() if key_id != self.active.key_id]

    def public(self) -> dict[str, Any]:
        """What may be printed: ids, never material."""
        return {
            "active_key_id": self.active.key_id,
            "key_ids": self.ids(),
            "retired_key_ids": self.retired_ids(),
            "ring": self.ring_path is not None,
            "rotation_in_progress": self.rotation_in_progress,
        }

    def with_key(self, key: SampleKey) -> "KeyRing":
        keys = dict(self.keys)
        keys[key.key_id] = key
        return KeyRing(
            active=self.active,
            keys=keys,
            source=self.source,
            ring_path=self.ring_path,
            env_ignored=self.env_ignored,
            rotation_in_progress=self.rotation_in_progress,
            rotation_started_at=self.rotation_started_at,
            rotation_from=self.rotation_from,
        )

    def with_active(self, key: SampleKey) -> "KeyRing":
        keys = dict(self.keys)
        keys[key.key_id] = key
        return KeyRing(
            active=key,
            keys=keys,
            source=self.source,
            ring_path=self.ring_path,
            env_ignored=self.env_ignored,
            rotation_in_progress=self.rotation_in_progress,
            rotation_started_at=self.rotation_started_at,
            rotation_from=self.rotation_from,
        )

    def without_key(self, key_id: str) -> "KeyRing":
        keys = {k: v for k, v in self.keys.items() if k != key_id}
        return KeyRing(
            active=self.active,
            keys=keys,
            source=self.source,
            ring_path=self.ring_path,
            env_ignored=self.env_ignored,
            rotation_in_progress=self.rotation_in_progress,
            rotation_started_at=self.rotation_started_at,
            rotation_from=self.rotation_from,
        )

    def with_rotation(
        self,
        *,
        active: SampleKey,
        in_progress: bool,
        started_at: Optional[str] = None,
        from_key_id: Optional[str] = None,
    ) -> "KeyRing":
        keys = dict(self.keys)
        keys[active.key_id] = active
        return KeyRing(
            active=active,
            keys=keys,
            source=self.source,
            ring_path=self.ring_path,
            env_ignored=self.env_ignored,
            rotation_in_progress=in_progress,
            rotation_started_at=started_at,
            rotation_from=from_key_id,
        )


def parse_key_material(text: str) -> bytes:
    """Parse 32 bytes of key material from hex or base64 text."""
    cleaned = "".join(text.split())
    if not cleaned:
        raise SampleStoreError(KEY_INVALID, "the configured key is empty")
    material: Optional[bytes] = None
    if len(cleaned) == KEY_LEN * 2:
        try:
            material = bytes.fromhex(cleaned)
        except ValueError:
            material = None
    if material is None:
        try:
            padded = cleaned + "=" * (-len(cleaned) % 4)
            material = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            material = None
    if material is None or len(material) != KEY_LEN:
        raise SampleStoreError(
            KEY_INVALID,
            "the configured key must be exactly 32 bytes, encoded as 64 hex "
            "characters or base64 (44 characters); its value was not logged",
        )
    return material


def _read_secret_text(path: Path, *, max_bytes: int, label: str = "key file") -> str:
    """Read a secret file, refusing symlinks, loose permissions and oversize input.

    A key file and a key-ring file are the same kind of surface: a symlink could
    point at a device or at a file the operator did not intend, and a
    world-readable secret is not a secret. Both are refusals, not warnings.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise SampleStoreError(KEY_FILE_MISSING, f"the {label} {path} does not exist") from exc
    except OSError as exc:
        raise SampleStoreError(KEY_FILE_MISSING, f"the {label} {path} is unreadable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SampleStoreError(KEY_FILE_SYMLINK, f"the {label} {path} is a symlink; refusing to follow it")
    if not stat.S_ISREG(info.st_mode):
        raise SampleStoreError(KEY_FILE_MISSING, f"the {label} {path} is not a regular file")
    if info.st_mode & 0o077:
        raise SampleStoreError(
            KEY_FILE_PERMISSIONS,
            f"the {label} {path} is accessible by group/other "
            f"(mode {oct(info.st_mode & 0o777)}); chmod 600 it",
        )
    if info.st_size > max_bytes:
        raise SampleStoreError(KEY_INVALID, f"the {label} {path} is implausibly large")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SampleStoreError(KEY_FILE_MISSING, f"the {label} {path} could not be opened: {exc}") from exc
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return handle.read(max_bytes)
    except OSError as exc:
        raise SampleStoreError(KEY_INVALID, f"the {label} {path} could not be read: {exc}") from exc


def _read_key_file(path: Path) -> str:
    return _read_secret_text(path, max_bytes=MAX_KEY_FILE_BYTES)


def write_key_file(path: Path, material: bytes) -> None:
    """Create a key file (0600, no overwrite) for ``hatchery store keygen``."""
    if len(material) != KEY_LEN:  # pragma: no cover - generated internally
        raise SampleStoreError(KEY_INVALID, "generated key material has the wrong length")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SampleStoreError(
            KEY_FILE_EXISTS, f"{path} already exists; refusing to overwrite a key"
        ) from exc
    except OSError as exc:
        raise SampleStoreError(KEY_INVALID, f"could not create the key file {path}: {exc}") from exc
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, base64.b64encode(material) + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        directory = os.open(path.parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_key_file(path: Path | str) -> SampleKey:
    """Load an operator-supplied key file, refusing symlinks and loose modes."""
    target = Path(path).expanduser()
    material = parse_key_material(_read_key_file(target))
    return SampleKey(
        material,
        f"file:{target}",
        key_id_for(material),
        created_at=_now_iso(),
    )


def _generate_key_file(path: Path) -> SampleKey:
    material = secrets.token_bytes(KEY_LEN)
    try:
        write_key_file(path, material)
    except SampleStoreError as exc:
        # Two processes racing to create the first key: the loser must use the
        # winner's key, not fail. The file is read back and validated (regular
        # file, 0600, correct length) before it is trusted.
        if exc.reason != KEY_FILE_EXISTS:
            raise
        existing = parse_key_material(_read_key_file(path))
        return SampleKey(
            material=existing,
            source=f"file:{path}",
            key_id=key_id_for(existing),
            created_at=_now_iso(),
        )
    return SampleKey(
        material=material,
        source=f"generated:{path}",
        key_id=key_id_for(material),
        generated=True,
        created_at=_now_iso(),
    )


def key_file_path(store_root: Path) -> Path:
    return Path(store_root) / KEY_FILE_NAME


def key_ring_path(store_root: Path) -> Path:
    return Path(store_root) / KEY_RING_NAME


def _serialize_ring(ring: KeyRing) -> bytes:
    payload: dict[str, Any] = {
        "version": KEY_RING_VERSION,
        "active": ring.active.key_id,
        "rotation": {
            "in_progress": bool(ring.rotation_in_progress),
            "started_at": ring.rotation_started_at,
            "from": ring.rotation_from,
        },
        "keys": [
            {
                "id": key_id,
                "material": base64.b64encode(ring.keys[key_id].material).decode("ascii"),
                "created_at": ring.keys[key_id].created_at,
            }
            for key_id in ring.ids()
        ],
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_key_ring_file(path: Path, ring: KeyRing) -> None:
    """Write a key ring atomically: 0600 temp, fsync, rename, directory fsync.

    A reader therefore sees either the previous ring or the new one, never a
    half-written file — which is what makes an interrupted rotation resumable.
    """
    payload = _serialize_ring(ring)
    if len(payload) > MAX_KEY_RING_BYTES:  # pragma: no cover - bounded by MAX_KEY_RING_KEYS
        raise SampleStoreError(KEY_RING_INVALID, "the key ring is larger than the supported limit")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".tmp-ring-{os.getpid()}-{time.time_ns()}"
    fd = -1
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | (getattr(os, "O_NOFOLLOW", 0)),
            0o600,
        )
        os.fchmod(fd, 0o600)
        os.write(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise SampleStoreError(KEY_RING_INVALID, f"could not write the key ring {path}: {exc}") from exc
    finally:
        if fd >= 0:  # pragma: no cover - only on an exception between open and close
            os.close(fd)
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:  # pragma: no cover
            pass


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:  # pragma: no cover - platforms without directory fds
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(fd)


def parse_key_ring(text: str, *, source: str, path: Optional[Path] = None) -> KeyRing:
    """Parse and validate a key-ring document. Never echoes key material."""
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise SampleStoreError(
            KEY_RING_INVALID, f"the key ring {source} is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise SampleStoreError(KEY_RING_INVALID, f"the key ring {source} is not an object")
    version = payload.get("version")
    if not isinstance(version, int) or version < 1:
        raise SampleStoreError(
            KEY_RING_INVALID, f"the key ring {source} has no valid version"
        )
    if version > KEY_RING_VERSION:
        raise SampleStoreError(
            KEY_RING_NEWER,
            f"the key ring {source} declares version {version}; this build "
            f"understands version {KEY_RING_VERSION}. Refusing to read or rewrite "
            "a ring written by a newer build.",
        )
    entries = payload.get("keys")
    if not isinstance(entries, list) or not entries:
        raise SampleStoreError(KEY_RING_INVALID, f"the key ring {source} has no keys")
    if len(entries) > MAX_KEY_RING_KEYS:
        raise SampleStoreError(
            KEY_RING_INVALID,
            f"the key ring {source} holds {len(entries)} keys; the limit is "
            f"{MAX_KEY_RING_KEYS}",
        )
    keys: dict[str, SampleKey] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise SampleStoreError(
                KEY_RING_INVALID, f"the key ring {source} has a non-object key entry"
            )
        encoded = entry.get("material")
        if not isinstance(encoded, str) or not encoded:
            raise SampleStoreError(
                KEY_RING_INVALID, f"the key ring {source} has a key with no material"
            )
        try:
            material = parse_key_material(encoded)
        except SampleStoreError as exc:
            raise SampleStoreError(
                KEY_RING_INVALID, f"the key ring {source} has an invalid key entry: {exc.message}"
            ) from exc
        key_id = key_id_for(material)
        declared = entry.get("id")
        if declared is not None and str(declared) != key_id:
            raise SampleStoreError(
                KEY_RING_INVALID,
                f"the key ring {source} names key id {declared} for material whose id is "
                f"{key_id}",
            )
        if key_id in keys:
            raise SampleStoreError(
                KEY_RING_INVALID, f"the key ring {source} contains key id {key_id} twice"
            )
        created = entry.get("created_at")
        keys[key_id] = SampleKey(
            material,
            source,
            key_id,
            created_at=str(created) if created else None,
        )
    active_id = payload.get("active")
    active = keys.get(str(active_id)) if active_id is not None else None
    if active is None:
        raise SampleStoreError(
            KEY_RING_INVALID,
            f"the key ring {source} names active key {active_id!r}, which is not in the ring",
        )
    rotation = payload.get("rotation")
    rotation = rotation if isinstance(rotation, dict) else {}
    return KeyRing(
        active=active,
        keys=keys,
        source=source,
        ring_path=path,
        rotation_in_progress=bool(rotation.get("in_progress")),
        rotation_started_at=rotation.get("started_at") if isinstance(rotation.get("started_at"), str) else None,
        rotation_from=rotation.get("from") if isinstance(rotation.get("from"), str) else None,
    )


def load_key_ring(path: Path) -> KeyRing:
    text = _read_secret_text(path, max_bytes=MAX_KEY_RING_BYTES, label="key ring")
    return parse_key_ring(text, source=f"ring:{path}", path=Path(path))


def _env_key() -> Optional[SampleKey]:
    configured = os.environ.get("HATCHERY_SAMPLE_KEY", "").strip()
    if configured:
        material = parse_key_material(configured)
        return SampleKey(
            material, "env:HATCHERY_SAMPLE_KEY", key_id_for(material), created_at=_now_iso()
        )
    return None


def resolve_key_ring(store_root: Path, *, create: bool = False) -> Optional[KeyRing]:
    """The store's key ring: the active key plus any retired keys.

    Resolution order (D29):

    1. ``<store>/.sample-keyring`` if it exists — the ring is authoritative once
       rotation has created one, because it is the store's own record of which
       keys may read which blobs. ``HATCHERY_SAMPLE_KEY``/``_FILE`` are then
       ignored (``env_ignored`` says so) rather than silently out-voting it.
    2. ``HATCHERY_SAMPLE_KEY`` (a D28 store, unchanged).
    3. ``HATCHERY_SAMPLE_KEY_FILE`` or ``<store>/.sample-key`` (also D28).
    4. With ``create``, generate ``<store>/.sample-key`` exactly as D28 did.

    ``None`` means nothing is configured, which lets a read-only consumer work
    without a key. A *misconfigured* key with no ring is always an error, never
    a silent "no key".
    """
    root = Path(store_root)
    ring_path = key_ring_path(root)
    if ring_path.exists() or ring_path.is_symlink():
        ring = load_key_ring(ring_path)
        env_present = bool(
            os.environ.get("HATCHERY_SAMPLE_KEY", "").strip()
            or os.environ.get("HATCHERY_SAMPLE_KEY_FILE", "").strip()
        )
        return KeyRing(
            active=ring.active,
            keys=ring.keys,
            source=ring.source,
            ring_path=ring.ring_path,
            env_ignored=env_present,
            rotation_in_progress=ring.rotation_in_progress,
            rotation_started_at=ring.rotation_started_at,
            rotation_from=ring.rotation_from,
        )

    key = _env_key()
    if key is None:
        configured_file = os.environ.get("HATCHERY_SAMPLE_KEY_FILE", "").strip()
        path = Path(configured_file).expanduser() if configured_file else key_file_path(root)
        explicit = bool(configured_file)
        if path.exists() or explicit:
            material = parse_key_material(_read_key_file(path))
            key = SampleKey(material, f"file:{path}", key_id_for(material), created_at=_now_iso())
    if key is None:
        if not create:
            return None
        key = _generate_key_file(key_file_path(root))
    return KeyRing(
        active=key,
        keys={key.key_id: key},
        source=key.source,
        ring_path=None,
    )


def resolve_key(store_root: Path, *, create: bool = False) -> Optional[SampleKey]:
    """The active key, or ``None`` when nothing is configured (D28 API)."""
    ring = resolve_key_ring(store_root, create=create)
    return ring.active if ring is not None else None


def generate_key(path: Path) -> SampleKey:
    """Create a fresh key file at ``path``. Never prints the key.

    Unlike the automatic first-write key, this is an explicit operator action:
    an existing file is refused, never silently reused.
    """
    target = Path(path).expanduser()
    material = secrets.token_bytes(KEY_LEN)
    write_key_file(target, material)
    return SampleKey(
        material=material,
        source=f"file:{target}",
        key_id=key_id_for(material),
        generated=True,
        created_at=_now_iso(),
    )


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def is_envelope(blob: bytes) -> bool:
    return blob.startswith(MAGIC)


def envelope_version(blob: bytes) -> Optional[int]:
    if not is_envelope(blob) or len(blob) <= len(MAGIC):
        return None
    return blob[len(MAGIC)]


def encrypt(plaintext: bytes, key: SampleKey, *, nonce: Optional[bytes] = None) -> bytes:
    """Encrypt bytes into a versioned envelope. The header is authenticated."""
    nonce = nonce if nonce is not None else secrets.token_bytes(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    key_id = bytes.fromhex(key.key_id)
    header = (
        MAGIC
        + bytes([ENVELOPE_VERSION])
        + key_id
        + nonce
        + len(plaintext).to_bytes(LEN_LEN, "big")
    )
    ciphertext = AESGCM(key.material).encrypt(nonce, plaintext, header)
    return header + ciphertext


def decrypt(
    blob: bytes,
    key: "SampleKey | KeyRing",
    *,
    max_bytes: int = MAX_DECLARED_PLAINTEXT,
    address: Optional[str] = None,
) -> bytes:
    """Authenticate and decrypt an envelope, resolving the key **by its id**.

    ``key`` is either one :class:`SampleKey` (D28: a wrong key is ``wrong-key``)
    or a :class:`KeyRing` (D29: the envelope names its key; a key id absent from
    the ring is ``unknown-key-id``, naming the key id and the blob). There is no
    trial decryption. Every failure raises :class:`SampleStoreError` with a
    distinct reason: ``unknown-version``, ``truncated``, ``wrong-key``,
    ``unknown-key-id``, ``auth-failed``. The caller is responsible for checking
    the plaintext hash against the content address (see
    :meth:`engine.store.store.SampleStore.read`).
    """
    if not is_envelope(blob):
        raise SampleStoreError(UNKNOWN_VERSION, "the stored file is not a HATCHERY envelope")
    if len(blob) < HEADER_LEN:
        raise SampleStoreError(
            TRUNCATED, f"the envelope is {len(blob)} bytes; a header alone needs {HEADER_LEN}"
        )
    version = blob[len(MAGIC)]
    if version != ENVELOPE_VERSION:
        raise SampleStoreError(
            UNKNOWN_VERSION,
            f"envelope version {version} is not supported by this build "
            f"(this build understands version {ENVELOPE_VERSION})",
        )
    offset = len(MAGIC) + 1
    stored_key_id = blob[offset : offset + KEY_ID_LEN].hex()
    offset += KEY_ID_LEN
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    declared = int.from_bytes(blob[offset : offset + LEN_LEN], "big")
    offset += LEN_LEN
    header = blob[:offset]
    ciphertext = blob[offset:]

    if isinstance(key, KeyRing):
        resolved = key.get(stored_key_id)
        if resolved is None:
            # A D28 single configured key keeps its `wrong-key` reason; a real
            # key ring (a file, or more than one key) names the missing key id.
            if key.ring_path is None and len(key.keys) == 1:
                where = f" (blob {address})" if address else ""
                raise SampleStoreError(
                    WRONG_KEY,
                    f"the envelope{where} was written with key id {stored_key_id}, but "
                    f"the configured key is {key.active.key_id}",
                )
            where = f" blob {address}" if address else ""
            raise SampleStoreError(
                UNKNOWN_KEY_ID,
                f"the envelope{where} names key id {stored_key_id}, which is not in "
                f"the key ring ({', '.join(key.ids())}); the blob is untouched — "
                "restore the retired key or re-add it to the ring",
            )
        material = resolved.material
    else:
        if stored_key_id != key.key_id:
            where = f" (blob {address})" if address else ""
            raise SampleStoreError(
                WRONG_KEY,
                f"the envelope{where} was written with key id {stored_key_id}, but the "
                f"configured key is {key.key_id}",
            )
        material = key.material
    if declared > max_bytes:
        raise SampleStoreError(
            TRUNCATED,
            f"the envelope declares {declared} plaintext bytes, above the "
            f"{max_bytes}-byte limit; refusing to allocate",
        )
    if len(ciphertext) != declared + TAG_LEN:
        raise SampleStoreError(
            TRUNCATED,
            f"the envelope declares {declared} plaintext bytes but carries "
            f"{len(ciphertext)} ciphertext bytes (expected {declared + TAG_LEN})",
        )
    try:
        plaintext = AESGCM(material).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise SampleStoreError(
            AUTH_FAILED,
            "the envelope failed authentication: the ciphertext or its header was "
            "modified, or the file was written with a different key that happens "
            "to share this key id",
        ) from exc
    if len(plaintext) != declared:  # pragma: no cover - AESGCM enforces this
        raise SampleStoreError(TRUNCATED, "the decrypted length disagrees with the header")
    return plaintext


def verify_plaintext_hash(plaintext: bytes, expected_sha256: str) -> str:
    """Return the plaintext SHA-256, refusing a content-address mismatch."""
    actual = hashlib.sha256(plaintext).hexdigest()
    if expected_sha256 and actual != expected_sha256:
        raise SampleStoreError(
            HASH_MISMATCH,
            f"the decrypted sample has sha256 {actual}, but the store address is "
            f"{expected_sha256}; refusing to use bytes that are not the sample",
        )
    return actual


__all__ = [
    "ENVELOPE_ALGORITHM",
    "ENVELOPE_LABEL",
    "ENVELOPE_VERSION",
    "HEADER_LEN",
    "KEY_FILE_NAME",
    "KEY_RING_NAME",
    "KEY_RING_VERSION",
    "LEGACY_LABEL",
    "MAGIC",
    "MAX_DECLARED_PLAINTEXT",
    "MAX_KEY_RING_BYTES",
    "MAX_KEY_RING_KEYS",
    "KeyRing",
    "SampleKey",
    "decrypt",
    "encrypt",
    "envelope_version",
    "generate_key",
    "is_envelope",
    "key_file_path",
    "key_id_for",
    "key_ring_path",
    "load_key_file",
    "load_key_ring",
    "parse_key_material",
    "parse_key_ring",
    "resolve_key",
    "resolve_key_ring",
    "verify_plaintext_hash",
    "write_key_file",
    "write_key_ring_file",
]
