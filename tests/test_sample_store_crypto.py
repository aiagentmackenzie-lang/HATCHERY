"""Encryption at rest for the sample store (D28).

The envelope, the key handling and every distinct failure reason, against real
ciphertext written to a temporary store. The assertions that matter:

* the stored blob does not contain the plaintext;
* every failure mode has its own reason (wrong key, tampered, truncated,
  unknown version, hash mismatch, no key);
* no key material ever appears in a repr, an error message or a status report.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from _store_builder import KEY, KEY_BYTES, OTHER_KEY

from engine.store import SampleStore, SampleStoreError
from engine.store.crypto import (
    ENVELOPE_VERSION,
    HEADER_LEN,
    MAGIC,
    SampleKey,
    decrypt,
    encrypt,
    is_envelope,
    key_id_for,
    parse_key_material,
    resolve_key,
)

PAYLOAD = b"MZ\x90\x00 not really a PE, but hostile-looking bytes \x00\x01\x02\n" * 8


def test_envelope_round_trip_and_no_plaintext_on_disk(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    record = store.put_bytes(PAYLOAD)

    blob = store.blob_path(record.sha256).read_bytes()
    assert is_envelope(blob)
    assert blob[: len(MAGIC)] == MAGIC
    assert blob[len(MAGIC)] == ENVELOPE_VERSION
    assert PAYLOAD not in blob
    assert PAYLOAD[:16] not in blob
    # And nothing else in the store directory holds the plaintext either.
    for path in (tmp_path / "samples").rglob("*"):
        if path.is_file() and path.name != "index.db" and not path.name.startswith("index.db"):
            assert PAYLOAD not in path.read_bytes(), path

    stored = store.read(record.sha256)
    assert stored.data == PAYLOAD
    assert stored.sha256 == record.sha256
    assert record.encryption_version == 1
    assert record.key_id == KEY.key_id
    assert stat.S_IMODE(store.blob_path(record.sha256).stat().st_mode) == 0o600
    store.close()


def test_wrong_key_fails_closed_with_its_own_reason(tmp_path: Path) -> None:
    writer = SampleStore(tmp_path / "samples", key=KEY)
    record = writer.put_bytes(PAYLOAD)
    writer.close()

    reader = SampleStore(tmp_path / "samples", key=OTHER_KEY)
    with pytest.raises(SampleStoreError) as excinfo:
        reader.read(record.sha256)
    assert excinfo.value.reason == "wrong-key"
    assert KEY.key_id in excinfo.value.message
    assert OTHER_KEY.key_id in excinfo.value.message
    # Never the key itself.
    assert KEY_BYTES.hex() not in str(excinfo.value)
    reader.close()


def test_tampered_ciphertext_fails_authentication(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    record = store.put_bytes(PAYLOAD)
    path = store.blob_path(record.sha256)
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0x01  # flip one bit in the GCM tag
    path.write_bytes(bytes(blob))

    with pytest.raises(SampleStoreError) as excinfo:
        store.read(record.sha256)
    assert excinfo.value.reason == "auth-failed"
    store.close()


def test_tampered_header_is_authenticated_too(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    record = store.put_bytes(PAYLOAD)
    path = store.blob_path(record.sha256)
    blob = bytearray(path.read_bytes())
    blob[len(MAGIC) + 1 + 8] ^= 0xFF  # a nonce byte
    path.write_bytes(bytes(blob))

    with pytest.raises(SampleStoreError) as excinfo:
        store.read(record.sha256)
    assert excinfo.value.reason == "auth-failed"
    store.close()


def test_truncated_envelope_is_distinct_from_tampering(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    record = store.put_bytes(PAYLOAD)
    path = store.blob_path(record.sha256)

    header_only = path.read_bytes()[: HEADER_LEN + 3]
    path.write_bytes(header_only)
    with pytest.raises(SampleStoreError) as excinfo:
        store.read(record.sha256)
    assert excinfo.value.reason == "truncated"

    path.write_bytes(MAGIC + b"\x01")
    with pytest.raises(SampleStoreError) as excinfo:
        store.read(record.sha256)
    assert excinfo.value.reason == "truncated"
    store.close()


def test_unknown_envelope_version_is_refused(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    record = store.put_bytes(PAYLOAD)
    path = store.blob_path(record.sha256)
    blob = bytearray(path.read_bytes())
    blob[len(MAGIC)] = 99
    path.write_bytes(bytes(blob))

    with pytest.raises(SampleStoreError) as excinfo:
        store.read(record.sha256)
    assert excinfo.value.reason == "unknown-version"
    assert "99" in excinfo.value.message
    store.close()


def test_plaintext_hash_is_verified_against_the_content_address(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    # Encrypt one payload but store it under another payload's address.
    other = b"a different sample"
    import hashlib

    address = hashlib.sha256(other).hexdigest()
    store.blob_path(address).write_bytes(encrypt(PAYLOAD, KEY))

    with pytest.raises(SampleStoreError) as excinfo:
        store.read(address)
    assert excinfo.value.reason == "hash-mismatch"
    store.close()


def test_reading_an_encrypted_sample_without_a_key_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for variable in ("HATCHERY_SAMPLE_KEY", "HATCHERY_SAMPLE_KEY_FILE"):
        monkeypatch.delenv(variable, raising=False)
    writer = SampleStore(tmp_path / "samples", key=KEY)
    record = writer.put_bytes(PAYLOAD)
    writer.close()

    reader = SampleStore(tmp_path / "samples")
    assert reader.key(create=False) is None
    with pytest.raises(SampleStoreError) as excinfo:
        reader.read(record.sha256)
    assert excinfo.value.reason == "no-key"
    reader.close()


def test_legacy_plaintext_is_readable_but_reported_as_such(tmp_path: Path) -> None:
    store = SampleStore(tmp_path / "samples", key=KEY)
    data = b"pre-D28 plaintext sample"
    import hashlib

    sha256 = hashlib.sha256(data).hexdigest()
    store.blob_path(sha256).write_bytes(data)

    stored = store.read(sha256)
    assert stored.data == data
    assert stored.encryption == "plaintext-legacy"
    report = store.verify()
    assert report["legacy"] == 1
    assert report["ok"] is False  # encryption at rest is not satisfied yet
    assert report["failures"] == []
    assert report["entries"][0]["reason"] == "plaintext-legacy"
    store.close()


def test_legacy_blob_with_the_wrong_bytes_is_refused(tmp_path: Path) -> None:
    import hashlib

    store = SampleStore(tmp_path / "samples", key=KEY)
    address = hashlib.sha256(b"expected").hexdigest()
    store.blob_path(address).write_bytes(b"not the expected bytes")
    with pytest.raises(SampleStoreError) as excinfo:
        store.read(address)
    assert excinfo.value.reason == "legacy-hash-mismatch"
    store.close()


# ---------------------------------------------------------------------------
# Key sources
# ---------------------------------------------------------------------------


def test_key_parsing_accepts_hex_and_base64_and_refuses_anything_else() -> None:
    import base64

    assert parse_key_material(KEY_BYTES.hex()) == KEY_BYTES
    assert parse_key_material(base64.b64encode(KEY_BYTES).decode()) == KEY_BYTES
    assert parse_key_material("  " + KEY_BYTES.hex() + "\n") == KEY_BYTES
    for bad in ("", "zz", KEY_BYTES.hex()[:-2], "g" * 64):
        with pytest.raises(SampleStoreError) as excinfo:
            parse_key_material(bad)
        assert excinfo.value.reason == "key-invalid"
        assert KEY_BYTES.hex() not in excinfo.value.message


def test_key_file_must_be_0600_and_not_a_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HATCHERY_SAMPLE_KEY", raising=False)
    key_file = tmp_path / "sample.key"
    key_file.write_text(KEY_BYTES.hex() + "\n", encoding="utf-8")
    os.chmod(key_file, 0o644)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY_FILE", str(key_file))

    with pytest.raises(SampleStoreError) as excinfo:
        SampleStore(tmp_path / "samples").key(create=False)
    assert excinfo.value.reason == "key-file-permissions"

    os.chmod(key_file, 0o600)
    key = SampleStore(tmp_path / "samples").key(create=False)
    assert key is not None and key.key_id == KEY.key_id

    link = tmp_path / "linked.key"
    link.symlink_to(key_file)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY_FILE", str(link))
    with pytest.raises(SampleStoreError) as excinfo:
        SampleStore(tmp_path / "samples").key(create=False)
    assert excinfo.value.reason == "key-file-symlink"


def test_an_invalid_env_key_is_an_error_not_a_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", "too-short")
    store = SampleStore(tmp_path / "samples")
    with pytest.raises(SampleStoreError) as excinfo:
        store.put_bytes(b"data")
    assert excinfo.value.reason == "key-invalid"
    assert not list((tmp_path / "samples").glob("*.sample"))
    store.close()


def test_env_key_wins_over_a_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = tmp_path / "sample.key"
    key_file.write_text(OTHER_KEY.material.hex(), encoding="utf-8")
    os.chmod(key_file, 0o600)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY_FILE", str(key_file))
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY.material.hex())

    key = resolve_key(tmp_path / "samples", create=False)
    assert key is not None
    assert key.key_id == KEY.key_id
    assert key.source == "env:HATCHERY_SAMPLE_KEY"


def test_no_key_generates_a_local_0600_key_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for variable in ("HATCHERY_SAMPLE_KEY", "HATCHERY_SAMPLE_KEY_FILE"):
        monkeypatch.delenv(variable, raising=False)
    root = tmp_path / "samples"
    store = SampleStore(root)
    record = store.put_bytes(b"first encrypted sample")

    key_file = root / ".sample-key"
    assert key_file.is_file()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert store.generated_key_notice and "generated" in store.generated_key_notice
    assert store.read(record.sha256).data == b"first encrypted sample"

    status = store.status()
    assert status["key"]["configured"] is True
    assert status["key"]["warning"]
    serialized = json.dumps(status)
    assert store.key(create=False).material.hex() not in serialized  # type: ignore[union-attr]
    store.close()


def test_a_key_repr_never_contains_the_key() -> None:
    key = SampleKey(KEY_BYTES, "test", key_id_for(KEY_BYTES))
    assert KEY_BYTES.hex() not in repr(key)
    assert KEY_BYTES.hex() not in str(key)
    assert key.key_id in repr(key)


def test_direct_decrypt_rejects_a_non_envelope() -> None:
    with pytest.raises(SampleStoreError) as excinfo:
        decrypt(b"%PDF-1.7 not an envelope", KEY)
    assert excinfo.value.reason == "unknown-version"
