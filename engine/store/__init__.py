"""The HATCHERY sample store (D28).

Content-addressed by SHA-256, encrypted at rest with an authenticated envelope,
indexed in SQLite, and aware of which run bundles and queued jobs still need a
sample. One implementation serves direct submission, ``--enqueue``, the worker,
replay and the ``hatchery store`` commands.

See ``docs/DECISIONS.md`` D28 and ``docs/RETENTION.md``.
"""

from engine.store.backup import create_backup, restore_backup
from engine.store.crypto import (
    ENVELOPE_LABEL,
    KEY_RING_NAME,
    KEY_RING_VERSION,
    LEGACY_LABEL,
    KeyRing,
    SampleKey,
    decrypt,
    encrypt,
    generate_key,
    is_envelope,
    key_ring_path,
    load_key_file,
    load_key_ring,
    parse_key_ring,
    resolve_key,
    resolve_key_ring,
    write_key_ring_file,
)
from engine.store.errors import SampleStoreError
from engine.store.index import SampleRecord
from engine.store.references import Reference, ReferenceScan, collect_references
from engine.store.roots import resolve_results_roots, resolve_store_root
from engine.store.staging import StagedPlaintext, stage_plaintext
from engine.store.store import (
    DEFAULT_MAX_SAMPLE_BYTES,
    SampleStore,
    StoredSample,
    is_sha256,
    resolve_ttl,
)

__all__ = [
    "DEFAULT_MAX_SAMPLE_BYTES",
    "ENVELOPE_LABEL",
    "KEY_RING_NAME",
    "KEY_RING_VERSION",
    "KeyRing",
    "LEGACY_LABEL",
    "Reference",
    "ReferenceScan",
    "SampleKey",
    "SampleRecord",
    "SampleStore",
    "SampleStoreError",
    "StagedPlaintext",
    "StoredSample",
    "collect_references",
    "create_backup",
    "decrypt",
    "encrypt",
    "generate_key",
    "is_envelope",
    "is_sha256",
    "key_ring_path",
    "load_key_file",
    "load_key_ring",
    "parse_key_ring",
    "resolve_key",
    "resolve_key_ring",
    "resolve_results_roots",
    "resolve_store_root",
    "resolve_ttl",
    "restore_backup",
    "stage_plaintext",
    "write_key_ring_file",
]
