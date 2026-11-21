"""Replay through the encrypted store (D28 + D26).

The replay orchestration is the real one: the real :class:`SampleStore`, the real
``locate_sample``, the real staging file, the real verdict and persistence. The
submit subprocess is injected for speed, except in the last test, which runs the
real ``hatchery submit`` and ``hatchery replay`` commands end to end.

What must hold: an encrypted, retained sample replays with the same verdict;
every way a sample can be unavailable (pruned, expired, wrong key, tampered)
produces INCONCLUSIVE with the precise reason — never a pass and never a
traceback; and no plaintext is left in the store, the index or the results.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from _replay_builder import bundle_with, content_sha256, fake_submit_runner, write_run
from _store_builder import OTHER_KEY, make_store

from engine.replay.replay import run_replay
from engine.store import SampleStore

REPO_ROOT = Path(__file__).resolve().parent.parent
EICAR = REPO_ROOT / "tests" / "fixtures" / "eicar.com"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
PAYLOAD = b"hatchery-replay-fixture\n"


def _original_run(tmp_path: Path, sha256: str) -> Path:
    missing = tmp_path / "gone" / "sample.bin"
    original = bundle_with(sample={"file_path": str(missing), "sha256": sha256})
    return write_run(tmp_path / "results", original, "original")


def _store_with_payload(tmp_path: Path) -> SampleStore:
    store = make_store(tmp_path)
    store.put_bytes(PAYLOAD)
    return store


def test_a_retained_encrypted_sample_replays_through_the_store(tmp_path: Path) -> None:
    store = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)
    out = tmp_path / "replayed"

    result = run_replay(
        original_dir,
        output_dir=out,
        submit_runner=fake_submit_runner(bundle_with()),
        store=store,
    )

    assert result.verdict == "reproducible"
    assert result.exit_code == 0
    section = result.section
    assert section["sample"]["resolution"] == "sample store"
    assert section["sample"]["encryption"] == "aes-256-gcm/v1"
    assert section["sample"]["store_reference"] == sha256
    assert section["sample"]["hash_verified"] is True
    limitations = " ".join(section["limitations"])
    assert "decrypted in memory" in limitations
    assert "single-use staging file" in limitations

    # replay.json is written, and it contains no sample bytes.
    written = (out / "bundle" / "replay.json").read_text()
    assert json.loads(written)["verdict"] == "reproducible"
    assert PAYLOAD.decode().strip() not in written
    store.close()


def test_a_legacy_plaintext_store_still_replays_and_says_so(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    import hashlib

    sha256 = hashlib.sha256(PAYLOAD).hexdigest()
    store.blob_path(sha256).write_bytes(PAYLOAD)
    original_dir = _original_run(tmp_path, sha256)

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with()),
        store=store,
    )
    assert result.verdict == "reproducible"
    assert result.section["sample"]["encryption"] == "plaintext-legacy"
    assert any("legacy plaintext" in line for line in result.section["limitations"])
    store.close()


def test_a_pruned_sample_is_inconclusive_with_the_reason(tmp_path: Path) -> None:
    store = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)

    report = store.prune(ttl=1, apply=True, now=time.time() + 3600, results_roots=[tmp_path / "empty"])
    assert [entry["sha256"] for entry in report["deleted"]] == [sha256]

    out = tmp_path / "replayed"
    result = run_replay(
        original_dir,
        output_dir=out,
        submit_runner=fake_submit_runner(bundle_with()),
        store=store,
    )

    assert result.verdict == "inconclusive"
    assert result.exit_code == 1
    assert result.section["sample"]["reason"] == "not-found"
    assert "INCONCLUSIVE" in " ".join(result.section["limitations"])
    assert json.loads((out / "replay.json").read_text())["verdict"] == "inconclusive"
    # The fake runner must never have been asked to analyse a missing sample.
    assert result.section["replay_task_id"] is None
    store.close()


def test_a_wrong_key_is_inconclusive_not_a_pass(tmp_path: Path) -> None:
    writer = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)
    writer.close()

    reader = make_store(tmp_path, key=OTHER_KEY)
    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with()),
        store=reader,
    )
    assert result.verdict == "inconclusive"
    assert result.exit_code == 1
    assert result.section["sample"]["reason"] == "wrong-key"
    reader.close()


def test_a_tampered_sample_is_inconclusive(tmp_path: Path) -> None:
    store = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)
    blob = bytearray(store.blob_path(sha256).read_bytes())
    blob[-1] ^= 0xFF
    store.blob_path(sha256).write_bytes(bytes(blob))

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with()),
        store=store,
    )
    assert result.verdict == "inconclusive"
    assert result.section["sample"]["reason"] == "auth-failed"
    store.close()


def test_an_expired_sample_is_inconclusive_even_if_the_bytes_are_still_there(
    tmp_path: Path,
) -> None:
    store = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with()),
        store=store,
        ttl=1e-9,
    )
    assert result.verdict == "inconclusive"
    assert result.section["sample"]["reason"] == "expired"
    assert store.blob_path(sha256).exists(), "expiry is a policy verdict, not a delete"
    store.close()


def test_a_prune_during_replay_cannot_corrupt_it(tmp_path: Path) -> None:
    """The sample is decrypted before submit starts, so a later delete is harmless."""
    store = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)
    out = tmp_path / "replayed"
    replay_bundle = bundle_with()

    def prune_then_submit(command: list[str], timeout: float) -> tuple[int, str, str]:
        store.prune(ttl=1, apply=True, now=time.time() + 3600, results_roots=[tmp_path / "empty"])
        assert not store.blob_path(sha256).exists()
        runner = fake_submit_runner(replay_bundle)
        return runner(command, timeout)

    result = run_replay(
        original_dir, output_dir=out, submit_runner=prune_then_submit, store=store
    )
    assert result.verdict == "reproducible"
    assert store.index.get(sha256) is None
    store.close()


def test_replay_leaves_no_plaintext_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    staging_root = tmp_path / "staging"
    staging_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(staging_root))

    store = _store_with_payload(tmp_path)
    sha256 = content_sha256()
    original_dir = _original_run(tmp_path, sha256)
    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replayed",
        submit_runner=fake_submit_runner(bundle_with()),
        store=store,
    )
    assert result.verdict == "reproducible"
    assert list(staging_root.iterdir()) == [], "the staging directory must be removed"

    # The store, the index and the replay output hold no plaintext sample.
    for path in (tmp_path / "samples").rglob("*"):
        if path.is_file() and not path.name.startswith("index.db"):
            assert PAYLOAD not in path.read_bytes(), path
    for path in (tmp_path / "replayed").rglob("*"):
        if path.is_file():
            assert PAYLOAD not in path.read_bytes(), path
    store.close()


# ---------------------------------------------------------------------------
# The real CLI, end to end
# ---------------------------------------------------------------------------


def _run_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
        env=env,
    )


def test_real_submit_then_replay_survives_deletion_and_pruning(tmp_path: Path) -> None:
    sample = tmp_path / "sample.com"
    sample.write_bytes(EICAR.read_bytes())
    store_root = tmp_path / "samples"
    results = tmp_path / "results"
    empty_results = tmp_path / "empty-results"
    empty_results.mkdir()
    env = dict(os.environ)
    env["HATCHERY_SAMPLE_STORE"] = str(store_root)

    submitted = _run_cli(
        ["submit", str(sample), "--no-sandbox", "-o", str(results / "run")], env
    )
    assert submitted.returncode == 0, submitted.stderr[-3000:]
    sample.unlink()  # only the encrypted store copy remains

    first = _run_cli(
        ["replay", str(results / "run" / "bundle"), "--no-sandbox",
         "-o", str(results / "replay-1")], env
    )
    assert first.returncode == 0, first.stdout[-3000:] + first.stderr[-2000:]
    section = json.loads((results / "replay-1" / "bundle" / "replay.json").read_text())
    assert section["verdict"] == "reproducible"
    assert section["sample"]["resolution"] == "sample store"
    assert section["sample"]["store_reference"] == EICAR_SHA256

    # Prune with a results root that does not contain the run: the sample is
    # expired and unreferenced *from that scan's point of view*, and is removed.
    pruned = _run_cli(
        ["store", "prune", "--apply", "--ttl", "0.001", "--json",
         "--results", str(empty_results), "--store", str(store_root),
         "--queue", str(tmp_path / "no-queue.db")], env
    )
    assert pruned.returncode == 0, pruned.stdout + pruned.stderr
    assert json.loads(pruned.stdout)["summary"]["deleted"] == 1

    second = _run_cli(
        ["replay", str(results / "run" / "bundle"), "--no-sandbox",
         "-o", str(results / "replay-2")], env
    )
    assert second.returncode == 1, second.stdout[-3000:]
    assert "Traceback" not in second.stderr
    # An inconclusive replay writes replay.json beside the (absent) new bundle.
    section = json.loads((results / "replay-2" / "replay.json").read_text())
    assert section["verdict"] == "inconclusive"
    assert section["sample"]["reason"] == "not-found"
    assert section["sample"]["hash_verified"] is False
