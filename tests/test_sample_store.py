"""The sample store's storage, index and migration behaviour (D28).

Real SQLite index, real blobs, temporary roots. These tests deliberately break
things — a crashing rename, a crash between the blob and its index row, an
interrupted migration — and assert the store stays readable and consistent.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from _store_builder import KEY, make_queue_db, make_store, write_legacy_blob

from engine.store import SampleStore, SampleStoreError
from engine.store.crypto import encrypt, is_envelope
from engine.store.index import DELETING, INDEX_SCHEMA_VERSION, SampleIndex


def test_put_is_content_addressed_and_deduplicated(tmp_path: Path) -> None:
    now = [1000.0]
    store = make_store(tmp_path, clock=lambda: now[0])
    first = store.put_bytes(b"same bytes")
    now[0] = 2000.0
    second = store.put_bytes(b"same bytes")

    assert first.sha256 == second.sha256 == hashlib.sha256(b"same bytes").hexdigest()
    blobs = list((tmp_path / "samples").glob("*.sample"))
    assert len(blobs) == 1
    # Re-storing does not reset the retention clock.
    assert second.stored_at == first.stored_at
    store.close()


def test_put_file_refuses_symlinks_and_oversized_input(tmp_path: Path) -> None:
    store = make_store(tmp_path, max_bytes=8)
    real = tmp_path / "real.bin"
    real.write_bytes(b"12345678")
    link = tmp_path / "link.bin"
    link.symlink_to(real)

    with pytest.raises(SampleStoreError) as excinfo:
        store.put_file(link)
    assert excinfo.value.reason == "symlink"

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 9)
    with pytest.raises(SampleStoreError) as excinfo:
        store.put_file(big)
    assert excinfo.value.reason == "too-large"

    with pytest.raises(SampleStoreError) as excinfo:
        store.put_bytes(b"")
    assert excinfo.value.reason == "empty"
    store.close()


def test_invalid_addresses_are_refused_before_touching_disk(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    for bad in ("../../etc/passwd", "ABC", "z" * 64, ""):
        with pytest.raises(SampleStoreError) as excinfo:
            store.read(bad)
        assert excinfo.value.reason == "invalid-sha256"
    store.close()


def test_a_crashing_rename_leaves_no_blob_no_row_and_no_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = make_store(tmp_path)

    def boom(source: str, target: str) -> None:
        raise OSError("simulated crash during rename")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.put_bytes(b"never stored")

    root = tmp_path / "samples"
    assert not list(root.glob("*.sample"))
    assert not list(root.glob(".tmp-*"))
    assert store.index.all() == []
    store.close()


def test_an_abandoned_temp_file_is_ciphertext_and_is_cleaned_up(tmp_path: Path) -> None:
    store = make_store(tmp_path, clock=lambda: 10_000.0)
    record = store.put_bytes(b"payload")
    root = tmp_path / "samples"
    stale = root / ".tmp-deadbeef-1234"
    stale.write_bytes(encrypt(b"payload", KEY))
    fresh = root / ".tmp-cafe0000-9"
    fresh.write_bytes(encrypt(b"payload", KEY))
    os.utime(stale, (0, 0))  # very old
    os.utime(fresh, (10_000.0, 10_000.0))  # just now

    report = store.reconcile()
    assert "stale" not in " ".join([p.name for p in root.glob(".tmp-*")])
    assert not stale.exists()
    assert fresh.exists(), "a fresh temporary may be a concurrent write"
    assert fresh.name in report["temporary_in_progress"]
    # A temporary is never mistaken for a sample.
    assert [row.sha256 for row in store.index.all()] == [record.sha256]
    store.close()


def test_an_orphan_blob_is_adopted_and_a_missing_blob_drops_its_row(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    root = tmp_path / "samples"

    # Crash shape 1: the blob was renamed into place but the row was never written.
    data = b"orphan bytes"
    sha256 = hashlib.sha256(data).hexdigest()
    (root / f"{sha256}.sample").write_bytes(encrypt(data, KEY))
    report = store.reconcile()
    assert sha256 in report["adopted"]
    assert store.read(sha256).data == data
    assert store.index.get(sha256).encryption_version == 1

    # Crash shape 2: the row exists but its blob is gone.
    gone = store.put_bytes(b"row without a blob")
    store.blob_path(gone.sha256).unlink()
    report = store.reconcile()
    assert any(item["sha256"] == gone.sha256 for item in report["dropped"])
    assert store.index.get(gone.sha256) is None
    store.close()


def test_an_interrupted_delete_is_recovered_both_ways(tmp_path: Path) -> None:
    store = make_store(tmp_path, clock=lambda: 5000.0)
    kept = store.put_bytes(b"delete was interrupted before the unlink")
    store.index.set_state(kept.sha256, DELETING)
    store.reconcile()
    assert store.index.get(kept.sha256).state == "active"  # type: ignore[union-attr]

    finished = store.put_bytes(b"delete was interrupted after the unlink")
    store.index.set_state(finished.sha256, DELETING)
    store.blob_path(finished.sha256).unlink()
    store.reconcile()
    assert store.index.get(finished.sha256) is None
    store.close()


def test_an_index_from_a_newer_build_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "index.db"
    conn = sqlite3.connect(str(path))
    conn.execute(f"PRAGMA user_version = {INDEX_SCHEMA_VERSION + 1}")
    conn.close()
    with pytest.raises(SampleStoreError) as excinfo:
        SampleIndex(path)
    assert excinfo.value.reason == "index-error"


def test_verify_passes_for_encrypted_samples_and_names_corruption(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    good = store.put_bytes(b"a good sample")
    bad = store.put_bytes(b"a sample that gets corrupted")
    blob = bytearray(store.blob_path(bad.sha256).read_bytes())
    blob[-1] ^= 0xFF
    store.blob_path(bad.sha256).write_bytes(bytes(blob))

    report = store.verify()
    assert report["ok"] is False
    assert report["failed"] == 1
    assert report["passed"] == 1
    assert report["failures"][0]["sha256"] == bad.sha256
    assert report["failures"][0]["reason"] == "auth-failed"
    assert report["legacy"] == 0

    one = store.verify(sha256=good.sha256)
    assert one["ok"] is True
    assert one["checked"] == 1
    store.close()


# ---------------------------------------------------------------------------
# Legacy plaintext migration
# ---------------------------------------------------------------------------


def test_legacy_store_migrates_idempotently_and_verifies(tmp_path: Path) -> None:
    root = tmp_path / "samples"
    first_sha, first_path = write_legacy_blob(root, b"legacy sample one")
    second_sha, second_path = write_legacy_blob(root, b"legacy sample two")
    assert not is_envelope(first_path.read_bytes())

    store = make_store(tmp_path)
    dry = store.migrate(apply=False)
    assert dry["legacy_found"] == 2
    assert not dry["encrypted"]
    assert not is_envelope(first_path.read_bytes()), "a dry run must not write"

    report = store.migrate(apply=True)
    assert sorted(item["sha256"] for item in report["encrypted"]) == sorted([first_sha, second_sha])
    assert report["failed"] == []
    assert is_envelope(first_path.read_bytes())
    assert is_envelope(second_path.read_bytes())
    assert store.read(first_sha).data == b"legacy sample one"

    verify = store.verify()
    assert verify["ok"] is True
    assert verify["legacy"] == 0
    assert verify["passed"] == 2

    # Idempotent and resumable: a second run finds nothing to do.
    again = store.migrate(apply=True)
    assert again["legacy_found"] == 0
    assert again["encrypted"] == []
    assert again["failed"] == []
    store.close()


def test_migration_resumes_after_the_rename_but_before_the_index_update(tmp_path: Path) -> None:
    root = tmp_path / "samples"
    sha256, path = write_legacy_blob(root, b"interrupted migration")
    store = make_store(tmp_path)
    store.reconcile()
    assert store.index.get(sha256).encryption_version == 0  # type: ignore[union-attr]

    # Simulate the crash: the blob is already re-encrypted, the row still says
    # plaintext. The next reconcile must believe the blob (the truth).
    path.write_bytes(encrypt(b"interrupted migration", KEY))
    report = store.migrate(apply=True)
    assert sha256 in report["reconcile"]["repaired"]
    assert report["legacy_found"] == 0
    assert store.read(sha256).data == b"interrupted migration"
    assert store.verify()["ok"] is True
    store.close()


def test_migration_reports_a_corrupt_legacy_blob_without_deleting_it(tmp_path: Path) -> None:
    import hashlib

    root = tmp_path / "samples"
    address = hashlib.sha256(b"the real bytes").hexdigest()
    path = root / f"{address}.sample"
    root.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"the WRONG bytes")
    os.chmod(path, 0o600)

    store = make_store(tmp_path)
    report = store.migrate(apply=True)
    assert report["failed"]
    assert report["failed"][0]["sha256"] == address
    assert report["failed"][0]["reason"] == "legacy-hash-mismatch"
    assert path.exists() and not is_envelope(path.read_bytes()), "the operator's bytes are kept"
    store.close()


def test_migration_of_a_legacy_store_also_adopts_queued_jobs(tmp_path: Path) -> None:
    sample = tmp_path / "queued.bin"
    sample.write_bytes(b"queued before D28")
    sha256 = hashlib.sha256(b"queued before D28").hexdigest()
    queue_db = make_queue_db(
        tmp_path / "queue.db",
        [
            {"job_id": "legacy-queued", "sample_path": str(sample), "status": "queued"},
            {"job_id": "legacy-done", "sample_path": str(sample), "status": "completed"},
        ],
    )

    store = make_store(tmp_path)
    report = store.migrate(apply=True, queue_db=queue_db)
    assert report["adopted_queue_jobs"] == [{"job_id": "legacy-queued", "sha256": sha256}]
    assert report["failed"] == []

    from engine.queue.store import JobStore

    jobs = JobStore(queue_db)
    try:
        adopted = jobs.get("legacy-queued")
        assert adopted is not None
        assert adopted.status == "queued" and adopted.job_id == "legacy-queued"
        assert adopted.sample_sha256 == sha256
        assert adopted.sample_store_ref == sha256
        done = jobs.get("legacy-done")
        assert done is not None and done.status == "completed"
    finally:
        jobs.close()
    assert store.read(sha256).data == b"queued before D28"
    store.close()


# ---------------------------------------------------------------------------
# Concurrency and locking
# ---------------------------------------------------------------------------


def test_two_store_instances_cannot_prune_at_the_same_time(tmp_path: Path) -> None:
    first = make_store(tmp_path)
    second = make_store(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with first.operation_lock():
            entered.set()
            release.wait(5)

    thread = threading.Thread(target=hold, daemon=True)
    thread.start()
    assert entered.wait(5)
    with pytest.raises(SampleStoreError) as excinfo:
        with second.operation_lock():
            pass  # pragma: no cover - the lock must be refused
    assert excinfo.value.reason == "store-locked"
    release.set()
    thread.join(timeout=5)
    second.close()
    first.close()


def test_concurrent_writers_of_the_same_bytes_leave_one_valid_blob(tmp_path: Path) -> None:
    """Several *processes* would each have their own store; instances emulate that."""
    errors: list[Exception] = []
    stores = [make_store(tmp_path) for _ in range(8)]

    def put(store: SampleStore) -> None:
        try:
            store.put_bytes(b"contended bytes" * 100)
        except Exception as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=put, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(list((tmp_path / "samples").glob("*.sample"))) == 1
    address = hashlib.sha256(b"contended bytes" * 100).hexdigest()
    for store in stores:
        assert store.read(address).data == b"contended bytes" * 100
        store.close()


def test_status_is_read_only_for_the_store(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    record = store.put_bytes(b"status must not modify it")
    before = store.blob_path(record.sha256).read_bytes()
    report = store.status()
    assert report["samples"] == 1
    assert report["encrypted"] == 1
    assert report["legacy_plaintext"] == 0
    assert report["ttl_enabled"] is False
    assert store.blob_path(record.sha256).read_bytes() == before
    assert stat.S_IMODE(store.blob_path(record.sha256).stat().st_mode) == 0o600
    store.close()


def test_a_symlinked_blob_is_not_followed(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    address = hashlib.sha256(b"outside").hexdigest()
    store.blob_path(address).symlink_to(outside)

    with pytest.raises(SampleStoreError) as excinfo:
        store.read(address)
    assert excinfo.value.reason == "symlink"
    report = store.reconcile()
    assert f"{address}.sample" in report["symlinks"]
    store.close()
