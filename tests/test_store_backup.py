"""Backup and restore of the encrypted store and the durable queue (D29).

Real stores, real SQLite index and queue, real backup directories, temporary
roots. The claims under test:

* the manifest describes every copied file, hashes every blob, excludes the key
  by default and says whether the backup is restorable without it;
* an interrupted backup has no manifest and cannot be mistaken for a complete
  one, and a rerun produces a valid backup;
* restore into an empty root verifies, preserves job ids/states/references and
  leaves a retained sample replayable;
* restore refuses a non-empty target, a newer schema, a tampered blob and a
  path-traversal manifest entry — and writes nothing;
* a backup taken while a writer is active is consistent and restorable;
* a restore without the key does not claim success, and becomes complete once
  the key is supplied.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import stat
import threading
from pathlib import Path

import pytest

from _replay_builder import bundle_with, fake_submit_runner, write_run
from _store_builder import KEY, KEY_BYTES, make_store

from engine.queue.store import JobStore
from engine.replay.replay import run_replay
from engine.store import SampleStore, SampleStoreError
from engine.store.backup import create_backup, restore_backup

PAYLOADS = [b"backup payload one\n", b"backup payload two\n", b"backup payload three\n"]


def _clear_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in (
        "HATCHERY_SAMPLE_KEY",
        "HATCHERY_SAMPLE_KEY_FILE",
        "HATCHERY_SAMPLE_STORE",
        "HATCHERY_QUEUE_DB",
    ):
        monkeypatch.delenv(variable, raising=False)


def _populated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    shas = [store.put_bytes(payload).sha256 for payload in PAYLOADS]
    store.close()
    return shas


def _manifest(path: Path) -> dict:
    return json.loads((path / "manifest.json").read_text(encoding="utf-8"))


def _no_plaintext_in(tree: Path) -> None:
    for path in tree.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for payload in PAYLOADS:
            assert payload not in data, f"plaintext leaked into {path}"


def test_manifest_hashes_every_blob_and_excludes_the_key_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    output = tmp_path / "backup"

    create_backup(tmp_path / "samples", output)

    manifest = _manifest(output)
    assert manifest["format"] == "hatchery-backup"
    assert manifest["manifest_version"] == 1
    assert manifest["counts"]["samples"] == len(PAYLOADS)
    assert manifest["counts"]["queue_present"] is False
    assert manifest["key"]["included"] is False
    assert manifest["key"]["restorable_without_operator_key"] is False
    assert manifest["key"]["secret_path"] is None
    assert not (output / "secrets" / "sample-keyring").exists()
    assert manifest["key"]["key_ids"] == [KEY.key_id]
    assert manifest["schema"]["store_index"] == 1
    assert manifest["excluded"], "the manifest must say what it does not contain"

    blobs = [entry for entry in manifest["files"] if entry["kind"] == "blob"]
    assert len(blobs) == len(PAYLOADS)
    for entry in blobs:
        path = output / entry["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == entry["sha256"]
        assert path.stat().st_size == entry["size"]
        assert entry["key_id"] == KEY.key_id
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    _no_plaintext_in(output)
    assert KEY_BYTES.hex() not in (output / "manifest.json").read_text()
    assert base64.b64encode(KEY_BYTES).decode() not in (output / "manifest.json").read_text()


def test_include_key_is_0600_loudly_warned_and_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    warnings: list[str] = []
    output = tmp_path / "backup"

    report = create_backup(
        tmp_path / "samples", output, include_key=True, warn=warnings.append
    )

    assert warnings and "INCLUDED" in warnings[0]
    secret = output / "secrets" / "sample-keyring"
    assert secret.is_file()
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    manifest = _manifest(output)
    assert manifest["key"]["included"] is True
    assert manifest["key"]["secret_path"] == "secrets/sample-keyring"
    assert manifest["key"]["restorable_without_operator_key"] is True
    assert "secret" in manifest["key"]["warning"].lower()
    # Key ids are safe; key material is not in the manifest.
    manifest_text = (output / "manifest.json").read_text()
    assert KEY.key_id in manifest_text
    assert KEY_BYTES.hex() not in manifest_text
    assert base64.b64encode(KEY_BYTES).decode() not in manifest_text
    assert report["key"]["included"] is True
    # The copied blob is ciphertext, never the plaintext.
    _no_plaintext_in(output)


def test_interrupted_backup_has_no_manifest_and_a_rerun_is_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    output = tmp_path / "backup"

    import engine.store.backup as backup_module

    def crash(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated power loss before the manifest")

    with monkeypatch.context() as patch:
        patch.setattr(backup_module, "_write_manifest", crash)
        with pytest.raises(RuntimeError):
            create_backup(tmp_path / "samples", output, include_key=True)

    assert not (output / "manifest.json").exists(), "an interrupted backup is not complete"
    with pytest.raises(SampleStoreError) as refused:
        restore_backup(output, tmp_path / "restore-failed")
    assert refused.value.reason == "manifest-missing"

    report = create_backup(tmp_path / "samples", output, include_key=True)
    assert report["ok"] is True
    assert (output / "manifest.json").is_file()
    restored = restore_backup(output, tmp_path / "restore")
    assert restored["ok"] is True, restored


def test_restore_preserves_jobs_and_a_retained_sample_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shas = _populated(tmp_path, monkeypatch)
    sha = shas[0]
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())

    queue_db = tmp_path / "queue.db"
    jobs = JobStore(queue_db)
    try:
        jobs.enqueue(
            tmp_path / "gone.bin",
            output_dir=tmp_path / "out-queued",
            sample_sha256=sha,
            sample_store_ref=sha,
            job_id="queued-job",
        )
        jobs.enqueue(
            tmp_path / "gone.bin",
            output_dir=tmp_path / "out-running",
            sample_sha256=sha,
            sample_store_ref=sha,
            job_id="running-job",
        )
        claimed = [jobs.claim("worker-a", lease_seconds=600), jobs.claim("worker-b", lease_seconds=600)]
        assert {job.job_id for job in claimed if job is not None} == {
            "queued-job", "running-job"
        }
    finally:
        jobs.close()

    backup = tmp_path / "backup"
    create_backup(
        tmp_path / "samples", backup, include_key=True, queue_db=queue_db
    )
    manifest = _manifest(backup)
    assert manifest["counts"]["queue_jobs"] == 2
    assert manifest["counts"]["queue_by_status"] == {"running": 2}

    target = tmp_path / "restored"
    restored = restore_backup(backup, target)
    assert restored["ok"] is True, restored
    assert restored["verify"]["ok"] is True
    assert restored["samples"] == len(PAYLOADS)
    assert restored["queue_jobs"] == 2
    assert restored["missing_sample_jobs"] == []

    # Job ids, states, attempts and store references are preserved, not derived.
    connection = sqlite3.connect(str(target / "queue.db"))
    try:
        rows = {
            str(row[0]): row
            for row in connection.execute(
                "SELECT job_id, status, attempts, sample_store_ref, sample_sha256 "
                "FROM jobs"
            )
        }
    finally:
        connection.close()
    assert set(rows) == {"queued-job", "running-job"}
    assert rows["queued-job"][1] == "running"
    assert rows["running-job"][1] == "running"
    assert rows["running-job"][2] == 1
    assert rows["queued-job"][3] == rows["running-job"][3] == sha

    # The restored sample replays reproducibly through the real store.
    bundle = bundle_with(sha256=sha, sample={"file_path": str(tmp_path / "gone.bin")})
    original = write_run(tmp_path / "results", bundle, "original")
    monkeypatch.delenv("HATCHERY_SAMPLE_KEY", raising=False)
    replay_store = SampleStore(target / "samples")
    result = run_replay(
        original,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with(sha256=sha)),
        store=replay_store,
    )
    assert result.verdict == "reproducible", result.section
    assert result.exit_code == 0
    assert result.section["sample"]["resolution"] == "sample store"
    assert result.section["sample"]["hash_verified"] is True
    replay_store.close()

    # A restored queued job runs from its store reference, not the dead path.
    from engine.queue.worker import build_job_command

    job = JobStore(target / "queue.db").get("queued-job")
    assert job is not None
    command = build_job_command(job)
    assert "--from-store" in command
    assert command[command.index("--from-store") + 1] == sha


def test_restore_refuses_a_non_empty_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    backup = tmp_path / "backup"
    create_backup(tmp_path / "samples", backup, include_key=True)
    target = tmp_path / "restored"
    restore_backup(backup, target)

    with pytest.raises(SampleStoreError) as excinfo:
        restore_backup(backup, target)
    assert excinfo.value.reason == "restore-target-not-empty"

    # --force still never overwrites a differing blob.
    existing_blob = next((target / "samples").glob("*.sample"))
    existing_blob.write_bytes(b"not the backup's bytes")
    with pytest.raises(SampleStoreError) as differs:
        restore_backup(backup, target, force=True)
    assert differs.value.reason == "restore-blob-mismatch"
    assert existing_blob.read_bytes() == b"not the backup's bytes"


def test_restore_refuses_a_newer_schema_a_tampered_blob_and_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    source = tmp_path / "backup"
    create_backup(tmp_path / "samples", source, include_key=True)

    import shutil

    # Newer schema than this build understands.
    newer = tmp_path / "newer"
    shutil.copytree(source, newer)
    manifest = _manifest(newer)
    manifest["schema"]["store_index"] = 99
    (newer / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(SampleStoreError) as schema:
        restore_backup(newer, tmp_path / "restore-newer")
    assert schema.value.reason == "restore-schema-newer"
    assert not (tmp_path / "restore-newer").exists()

    # A tampered blob is refused before anything is written.
    tampered = tmp_path / "tampered"
    shutil.copytree(source, tampered)
    blob = next((tampered / "store" / "blobs").glob("*.sample"))
    data = bytearray(blob.read_bytes())
    data[-1] ^= 0xFF
    blob.write_bytes(bytes(data))
    with pytest.raises(SampleStoreError) as corrupt:
        restore_backup(tampered, tmp_path / "restore-tampered")
    assert corrupt.value.reason == "restore-blob-mismatch"
    assert not (tmp_path / "restore-tampered").exists()

    # A manifest entry that tries to escape the backup root.
    traversal = tmp_path / "traversal"
    shutil.copytree(source, traversal)
    manifest = _manifest(traversal)
    sha = "a" * 64
    outside = traversal / f"{sha}.sample"
    outside.write_bytes(b"not a sample")
    manifest["files"].append(
        {
            "path": f"store/blobs/../../{sha}.sample",
            "kind": "blob",
            "sha256": hashlib.sha256(b"not a sample").hexdigest(),
            "size": len(b"not a sample"),
            "content_address": sha,
            "envelope_version": 1,
            "key_id": KEY.key_id,
        }
    )
    manifest["counts"]["samples"] = int(manifest["counts"]["samples"]) + 1
    (traversal / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(SampleStoreError) as escaped:
        restore_backup(traversal, tmp_path / "restore-traversal")
    assert escaped.value.reason == "restore-path-refused"
    assert not (tmp_path / "restore-traversal").exists()


def test_restore_without_the_key_does_not_claim_success_then_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    create_backup(tmp_path / "samples", backup)  # key deliberately excluded

    target = tmp_path / "restored"
    report = restore_backup(backup, target)
    assert report["ok"] is False
    assert report["samples"] == len(PAYLOADS)
    assert len(report["undecryptable"]) == len(PAYLOADS)
    assert report["undecryptable"][0]["reason"] == "key-missing"
    assert KEY.key_id in report["undecryptable"][0]["message"]
    assert "not configured" in report["undecryptable"][0]["message"]
    # The files are there; only the key is missing.
    assert len(list((target / "samples").glob("*.sample"))) == len(PAYLOADS)
    assert (target / "samples" / "index.db").is_file()

    # A sample that cannot be decrypted is INCONCLUSIVE with the reason,
    # never a pass — even though the bytes were restored successfully.
    sha = _populated_shas(tmp_path)[0]
    bundle = bundle_with(sha256=sha, sample={"file_path": str(tmp_path / "gone.bin")})
    original = write_run(tmp_path / "results", bundle, "original")
    keyless = SampleStore(target / "samples")
    replay = run_replay(
        original,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with(sha256=sha)),
        store=keyless,
    )
    keyless.close()
    assert replay.verdict == "inconclusive"
    assert replay.exit_code == 1
    assert replay.section["sample"]["hash_verified"] is False
    assert replay.section["sample"]["reason"] == "no-key"

    # Supplying the operator's key makes the restored store verify completely.
    restored = SampleStore(target / "samples", key=KEY)
    verified = restored.verify()
    assert verified["ok"] is True
    for sha, payload in zip(_populated_shas(tmp_path), PAYLOADS):
        assert restored.read(sha).data == payload
    restored.close()


def _populated_shas(tmp_path: Path) -> list[str]:
    return [hashlib.sha256(payload).hexdigest() for payload in PAYLOADS]


def test_a_backup_while_writers_are_active_is_consistent_and_restorable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _populated(tmp_path, monkeypatch)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    store = SampleStore(tmp_path / "samples")
    queue_db = tmp_path / "queue.db"
    jobs = JobStore(queue_db)
    stop = threading.Event()
    errors: list[BaseException] = []

    def put_loop() -> None:
        index = 0
        try:
            while not stop.is_set():
                store.put_bytes(f"concurrent-put-{index}-{os.urandom(8).hex()}".encode())
                index += 1
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    def queue_loop() -> None:
        index = 0
        try:
            while not stop.is_set():
                jobs.enqueue(
                    tmp_path / "gone.bin",
                    output_dir=tmp_path / f"out-{index}",
                    job_id=f"concurrent-{index}",
                    sample_store_ref=hashlib.sha256(PAYLOADS[0]).hexdigest(),
                )
                index += 1
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=put_loop), threading.Thread(target=queue_loop)]
    for thread in threads:
        thread.start()
    try:
        backup = tmp_path / "backup"
        create_backup(
            tmp_path / "samples", backup, include_key=True, queue_db=queue_db
        )
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        jobs.close()
        store.close()
    assert errors == []

    restored = restore_backup(backup, tmp_path / "restored")
    assert restored["ok"] is True, restored
    assert restored["verify"]["ok"] is True
    # The backup is a consistent point in time: every blob it copied had an
    # index row and authenticated.
    manifest = _manifest(backup)
    assert manifest["counts"]["samples"] == restored["samples"]
    assert manifest["counts"]["queue_jobs"] == restored["queue_jobs"]


def test_backup_waits_for_an_active_maintenance_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shas = _populated(tmp_path, monkeypatch)
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    holder = SampleStore(tmp_path / "samples")
    started = threading.Event()
    release = threading.Event()

    def hold_the_lock() -> None:
        with holder.operation_lock():
            started.set()
            release.wait(10)

    thread = threading.Thread(target=hold_the_lock)
    thread.start()
    assert started.wait(5)

    def release_soon() -> None:
        import time

        time.sleep(0.2)
        release.set()

    releaser = threading.Thread(target=release_soon)
    releaser.start()
    import time

    began = time.monotonic()
    try:
        backup = tmp_path / "backup"
        create_backup(tmp_path / "samples", backup, include_key=True)
    finally:
        release.set()
        thread.join()
        releaser.join()
        holder.close()
    elapsed = time.monotonic() - began
    assert elapsed >= 0.15, "backup must wait for a maintenance lock, not race it"

    restored = restore_backup(backup, tmp_path / "restored")
    assert restored["ok"] is True, restored
    assert restored["samples"] == len(shas)
