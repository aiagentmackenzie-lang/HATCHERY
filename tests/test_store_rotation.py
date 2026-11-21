"""Key ring, per-blob key resolution and rotation (D29).

Everything here uses a real :class:`SampleStore`, real ciphertext on disk and
real key files. The properties that matter:

* rotation actually re-wraps every blob, and the old key alone stops working;
* a partially rotated store is readable because the ring holds both keys, and
  becomes "complete" only when the last blob moves;
* an interrupted rotation (after the rename, or mid-store) resumes from the
  blobs instead of restarting from an assumption;
* a missing retired key leaves the blob untouched and names it precisely;
* two rotations cannot interleave, and a reader never sees a torn blob;
* a D28 env-only store and the generated-local-key path still work.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from _store_builder import KEY, KEY_BYTES, OTHER_KEY, OTHER_KEY_BYTES, make_store

from engine.store import SampleStore, SampleStoreError
from engine.store.crypto import (
    KeyRing,
    key_ring_path,
    write_key_ring_file,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PAYLOADS = [f"rotation sample {index}".encode() for index in range(6)]


def _clear_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for variable in (
        "HATCHERY_SAMPLE_KEY",
        "HATCHERY_SAMPLE_KEY_FILE",
        "HATCHERY_SAMPLE_STORE",
    ):
        monkeypatch.delenv(variable, raising=False)


def _populate(store: SampleStore) -> list[str]:
    return [store.put_bytes(payload).sha256 for payload in PAYLOADS]


def test_rotation_round_trip_and_the_old_key_alone_stops_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    shas = _populate(store)
    old_id = store.key().key_id  # type: ignore[union-attr]

    report = store.rotate_key()
    assert report["complete"] is True
    assert len(report["rotated"]) == len(PAYLOADS)
    assert report["failed"] == []
    assert report["active_after"] and report["active_after"] != old_id

    new_ring = store.key_ring()
    assert new_ring is not None
    new_id = new_ring.active.key_id
    assert new_ring.get(old_id) is not None, "the retired key stays readable"
    assert new_ring.retired_ids() == [old_id]

    verified = store.verify()
    assert verified["ok"] is True, verified
    assert verified["key"]["rotation_complete"] is True
    assert verified["key"]["active_key_id"] == new_id
    assert verified["key"]["per_key_blob_counts"] == {new_id: len(PAYLOADS)}
    assert old_id not in {entry["key_id"] for entry in verified["entries"]}
    # Reading through the ring still returns the original bytes.
    for sha, payload in zip(shas, PAYLOADS):
        assert store.read(sha).data == payload
    store.close()

    # A D28-style single key configured alone can no longer read the blobs.
    old_only = SampleStore(tmp_path / "samples", key=KEY)
    with pytest.raises(SampleStoreError) as excinfo:
        old_only.read(shas[0])
    assert excinfo.value.reason == "wrong-key"
    assert old_id in excinfo.value.message
    assert KEY_BYTES.hex() not in str(excinfo.value)
    old_only.close()


def test_partial_rotation_reads_with_the_ring_and_reports_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    shas = _populate(store)

    original_write = store._write_atomic
    calls = {"n": 0}

    def crashing_write(sha256: str, envelope: bytes) -> None:
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated SIGKILL mid-store")
        original_write(sha256, envelope)

    monkeypatch.setattr(store, "_write_atomic", crashing_write)
    with pytest.raises(RuntimeError):
        store.rotate_key()
    monkeypatch.setattr(store, "_write_atomic", original_write)

    state = store.rotation_state()
    assert state["rotation_complete"] is False
    assert state["rotation_pending"] == len(PAYLOADS) - 2
    assert len(state["per_key_blob_counts"]) == 2
    # Every blob is still readable: the ring holds both keys.
    for sha, payload in zip(shas, PAYLOADS):
        assert store.read(sha).data == payload
    assert store.key_status()["rotation_complete"] is False
    assert store.key_status()["rotation_in_progress"] is True

    resumed = store.rotate_key()  # no explicit key: resumes the in-progress key
    assert resumed["mode"] == "resume"
    assert resumed["complete"] is True
    assert len(resumed["rotated"]) == len(PAYLOADS) - 2
    assert store.key_status()["rotation_complete"] is True
    assert store.key_status()["rotation_in_progress"] is False
    assert store.status()["keys"]["rotation_complete"] is True
    assert store.verify()["ok"] is True
    store.close()


def test_crash_after_rename_before_index_update_is_repaired_and_resumes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    shas = _populate(store)
    payload_for = dict(zip(shas, PAYLOADS))
    first = sorted(shas)[0]  # rotation walks blobs in content-address order

    original_upsert = store.index.upsert
    failed = {"done": False}

    def crash_once(**kwargs: object) -> None:
        if not failed["done"]:
            failed["done"] = True
            raise RuntimeError("simulated SIGKILL between rename and index update")
        original_upsert(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store.index, "upsert", crash_once)
    with pytest.raises(RuntimeError):
        store.rotate_key()
    monkeypatch.setattr(store.index, "upsert", original_upsert)

    ring = store.key_ring()
    assert ring is not None and ring.rotation_in_progress is True
    # The renamed blob is already under the new key; the index row is stale.
    blob_row = store.index.get(first)
    assert blob_row is not None
    assert blob_row.key_id == KEY.key_id
    assert store.blob_header(first)["key_id"] == ring.active.key_id
    # Still readable before any repair, because the ring has both keys.
    assert store.read(first).data == payload_for[first]

    resumed = store.rotate_key()
    assert resumed["mode"] == "resume"
    assert resumed["complete"] is True
    repaired = store.index.get(first)
    assert repaired is not None and repaired.key_id == ring.active.key_id
    assert store.rotation_state()["rotation_complete"] is True
    assert store.verify()["ok"] is True
    store.close()


def test_a_missing_retired_key_leaves_the_blob_untouched_and_names_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    sha = store.put_bytes(b"readable only with the lost key").sha256
    blob_path = store.blob_path(sha)
    before = blob_path.read_bytes()
    store.close()

    # A ring that does not contain the key the envelope names.
    ring = KeyRing(
        active=OTHER_KEY,
        keys={OTHER_KEY.key_id: OTHER_KEY},
        source="ring",
        ring_path=key_ring_path(tmp_path / "samples"),
    )
    write_key_ring_file(key_ring_path(tmp_path / "samples"), ring)

    reader = SampleStore(tmp_path / "samples")
    report = reader.rotate_key()
    assert report["complete"] is False
    assert len(report["failed"]) == 1
    failure = report["failed"][0]
    assert failure["sha256"] == sha
    assert failure["reason"] == "unknown-key-id"
    assert KEY.key_id in failure["message"]
    assert sha in failure["message"]
    assert blob_path.read_bytes() == before, "an unreadable blob is never rewritten"

    with pytest.raises(SampleStoreError) as excinfo:
        reader.read(sha)
    assert excinfo.value.reason == "unknown-key-id"
    assert KEY.key_id in excinfo.value.message
    assert sha in excinfo.value.message
    assert KEY_BYTES.hex() not in str(excinfo.value)
    assert OTHER_KEY_BYTES.hex() not in str(excinfo.value)

    reader.close()
    assert blob_path.read_bytes() == before


def test_two_concurrent_rotations_exactly_one_proceeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    writer = make_store(tmp_path)
    for index in range(80):
        writer.put_bytes(f"concurrent rotation {index}".encode())
    writer.close()
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())

    stores = [SampleStore(tmp_path / "samples"), SampleStore(tmp_path / "samples")]
    original_write = SampleStore._write_atomic

    def slow_write(self: SampleStore, sha256: str, envelope: bytes) -> None:
        time.sleep(0.004)
        original_write(self, sha256, envelope)

    monkeypatch.setattr(SampleStore, "_write_atomic", slow_write)
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def rotate(store: SampleStore) -> None:
        barrier.wait()
        try:
            outcomes.append(store.rotate_key())
        except SampleStoreError as exc:
            outcomes.append(exc)

    threads = [threading.Thread(target=rotate, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    monkeypatch.setattr(SampleStore, "_write_atomic", original_write)

    locked = [item for item in outcomes if isinstance(item, SampleStoreError)]
    succeeded = [item for item in outcomes if isinstance(item, dict)]
    assert len(locked) == 1, outcomes
    assert locked[0].reason == "store-locked"
    assert len(succeeded) == 1, outcomes
    assert succeeded[0]["complete"] is True

    final = stores[0]
    state = final.rotation_state()
    assert state["rotation_complete"] is True
    assert state["per_key_blob_counts"] == {state["active_key_id"]: 80}
    assert final.verify()["ok"] is True
    for store in stores:
        store.close()


def test_a_reader_during_rotation_never_sees_a_torn_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    shas = _populate(store)
    original_write = store._write_atomic

    def slow_write(sha256: str, envelope: bytes) -> None:
        time.sleep(0.003)
        original_write(sha256, envelope)

    monkeypatch.setattr(store, "_write_atomic", slow_write)
    errors: list[BaseException] = []
    seen: list[bytes] = []

    def rotate() -> None:
        try:
            store.rotate_key()
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    thread = threading.Thread(target=rotate)
    thread.start()
    while thread.is_alive():
        for sha, payload in zip(shas, PAYLOADS):
            try:
                assert store.read(sha).data == payload
                seen.append(payload)
            except BaseException as exc:  # noqa: BLE001 - collected for the assertion
                errors.append(exc)
    thread.join()
    monkeypatch.setattr(store, "_write_atomic", original_write)

    assert errors == []
    assert seen, "the reader actually ran while rotation was in progress"
    assert store.rotation_state()["rotation_complete"] is True
    assert store.verify()["ok"] is True
    store.close()


def test_key_ring_file_is_versioned_0600_and_refuses_a_newer_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    sha = store.put_bytes(b"ring file permissions").sha256
    store.rotate_key()
    store.close()

    ring_path = key_ring_path(tmp_path / "samples")
    assert ring_path.is_file()
    assert stat.S_IMODE(ring_path.stat().st_mode) == 0o600
    document = json.loads(ring_path.read_text())
    assert document["version"] == 1
    assert KEY_BYTES.hex() not in ring_path.read_text(), "only ids/id-derived material, never hex"
    material = [
        entry["material"] for entry in document["keys"]
    ]
    assert all(len(value) == 44 for value in material)  # base64 of 32 bytes
    # The current key material is not the old key's material in hex.
    assert KEY_BYTES.hex() not in "".join(material)

    document["version"] = 99
    ring_path.write_text(json.dumps(document))
    os.chmod(ring_path, 0o600)
    reader = SampleStore(tmp_path / "samples")
    with pytest.raises(SampleStoreError) as excinfo:
        reader.read(sha)
    assert excinfo.value.reason == "key-ring-version"
    reader.close()


def test_a_d28_env_only_store_and_the_generated_key_still_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    # D28: an env-only store, no ring file.
    monkeypatch.setenv("HATCHERY_SAMPLE_KEY", KEY_BYTES.hex())
    env_store = SampleStore(tmp_path / "env-samples")
    sha = env_store.put_bytes(b"env-keyed sample").sha256
    assert env_store.key_ring() is not None
    assert env_store.key_ring().ring_path is None  # type: ignore[union-attr]
    assert env_store.verify()["ok"] is True
    pruned = env_store.prune(ttl=0, results_roots=[tmp_path / "none"])
    assert pruned["summary"]["kept"] == 1
    rotated = env_store.rotate_key()
    assert rotated["complete"] is True
    assert env_store.read(sha).data == b"env-keyed sample"
    assert env_store.verify()["ok"] is True
    env_store.close()

    # D28: no key configured at all -> a generated local key, still announced.
    for variable in ("HATCHERY_SAMPLE_KEY", "HATCHERY_SAMPLE_KEY_FILE"):
        monkeypatch.delenv(variable, raising=False)
    generated = SampleStore(tmp_path / "generated-samples")
    sha2 = generated.put_bytes(b"generated-key sample").sha256
    assert generated.generated_key_notice
    assert (tmp_path / "generated-samples" / ".sample-key").is_file()
    assert generated.verify()["ok"] is True
    state = generated.rotate_key()
    assert state["complete"] is True
    assert generated.read(sha2).data == b"generated-key sample"
    assert key_ring_path(tmp_path / "generated-samples").is_file()
    assert generated.verify()["ok"] is True
    assert KEY_BYTES.hex() not in json.dumps(generated.key_status())
    generated.close()


def test_retiring_a_key_is_refused_while_a_blob_needs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    store.put_bytes(b"still encrypted with the old key")
    old_id = store.key().key_id  # type: ignore[union-attr]
    store.rotate_key()
    new_id = store.key().key_id  # type: ignore[union-attr]
    assert new_id != old_id

    with pytest.raises(SampleStoreError) as active:
        store.retire_key(new_id)
    assert active.value.reason == "key-is-active"

    # All blobs are on the new key, so the old one can be retired explicitly.
    report = store.retire_key(old_id)
    assert report["removed"] is True
    assert report["retired"] == old_id
    assert old_id not in report["key_ids"]
    assert store.key_status()["retired_key_ids"] == []
    store.close()

    # And a key whose blobs still exist is refused, with the blob named.
    base = tmp_path / "partial"
    partial = make_store(base)
    partial.put_bytes(b"needs the old key")
    old = partial.key().key_id  # type: ignore[union-attr]
    original_write = partial._write_atomic
    calls = {"n": 0}

    def fail_all(sha256: str, envelope: bytes) -> None:
        calls["n"] += 1
        raise SampleStoreError("write-failed", "leave the blob on the old key")

    partial._write_atomic = fail_all  # type: ignore[method-assign]
    report = partial.rotate_key()
    partial._write_atomic = original_write  # type: ignore[method-assign]
    assert report["complete"] is False
    with pytest.raises(SampleStoreError) as in_use:
        partial.retire_key(old)
    assert in_use.value.reason == "key-in-use"
    assert report["failed"][0]["sha256"] in in_use.value.message
    partial.close()


def _run_cli(args: list[str], env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=env,
    )


def test_rotation_cli_json_exit_codes_and_no_key_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    store.put_bytes(b"cli rotation")
    store.close()

    env = dict(os.environ)
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "samples")
    env["HATCHERY_SAMPLE_KEY"] = KEY_BYTES.hex()

    rotated = _run_cli(["store", "key", "rotate", "--json"], env, tmp_path)
    assert rotated.returncode == 0, rotated.stderr
    report = json.loads(rotated.stdout)
    assert report["complete"] is True
    assert report["active_after"] != KEY.key_id
    assert KEY_BYTES.hex() not in rotated.stdout + rotated.stderr

    status = _run_cli(["store", "key", "status", "--json"], env, tmp_path)
    assert status.returncode == 0, status.stderr
    payload = json.loads(status.stdout)
    assert payload["key"]["rotation_complete"] is True
    assert payload["key"]["active_key_id"] == report["active_after"]
    assert payload["rotation"]["per_key_blob_counts"] == {
        report["active_after"]: 1
    }
    assert KEY_BYTES.hex() not in status.stdout + status.stderr

    verified = _run_cli(["store", "verify", "--json"], env, tmp_path)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert json.loads(verified.stdout)["key"]["rotation_complete"] is True

    # The retired key cannot be removed while a blob still needs it? It no
    # longer does, so retirement succeeds; the active key is refused.
    retired = _run_cli(
        ["store", "key", "retire", KEY.key_id, "--json"], env, tmp_path
    )
    assert retired.returncode == 0, retired.stderr
    refused = _run_cli(
        ["store", "key", "retire", report["active_after"], "--json"], env, tmp_path
    )
    assert refused.returncode != 0
    assert "key-is-active" in refused.stderr
    assert KEY_BYTES.hex() not in refused.stderr


def test_rotation_cli_reports_a_missing_retired_key_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_key_env(monkeypatch)
    store = make_store(tmp_path)
    sha = store.put_bytes(b"orphaned key").sha256
    store.close()
    ring = KeyRing(
        active=OTHER_KEY,
        keys={OTHER_KEY.key_id: OTHER_KEY},
        source="ring",
        ring_path=key_ring_path(tmp_path / "samples"),
    )
    write_key_ring_file(key_ring_path(tmp_path / "samples"), ring)

    env = dict(os.environ)
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "samples")
    env.pop("HATCHERY_SAMPLE_KEY", None)
    result = _run_cli(["store", "key", "rotate", "--json"], env, tmp_path)
    assert result.returncode == 2
    report = json.loads(result.stdout)
    assert report["complete"] is False
    assert report["failed"][0]["sha256"] == sha
    assert report["failed"][0]["reason"] == "unknown-key-id"
    assert KEY.key_id in report["failed"][0]["message"]
    assert KEY_BYTES.hex() not in result.stdout + result.stderr
    assert (tmp_path / "samples" / f"{sha}.sample").is_file()
