"""`hatchery store` — JSON output, exit codes and secret hygiene (D28).

Every subcommand is driven as a real process, because the contract is about
what an operator (or a script) actually sees: one JSON object on stdout,
diagnostics on stderr, a documented non-zero exit for a failure, and never a key.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from _store_builder import KEY, KEY_BYTES, make_queue_db

from engine.store import SampleStore

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env(store_root: Path, *, key_bytes: bytes = KEY_BYTES) -> dict[str, str]:
    env = dict(os.environ)
    env["HATCHERY_SAMPLE_STORE"] = str(store_root)
    env["HATCHERY_SAMPLE_KEY"] = key_bytes.hex()
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    return env


def _run(args: list[str], env: dict[str, str], tmp_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=env,
    )


def _results(tmp_path: Path) -> Path:
    root = tmp_path / "results"
    root.mkdir(exist_ok=True)
    return root


def test_status_json_is_parseable_and_reports_counts(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store = SampleStore(store_root, key=KEY)
    store.put_bytes(b"one encrypted sample")
    legacy = b"one legacy sample"
    store.blob_path(hashlib.sha256(legacy).hexdigest()).write_bytes(legacy)
    store.close()

    result = _run(
        ["store", "status", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path))],
        env, tmp_path,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)  # stdout must be pure JSON
    assert report["samples"] == 2
    assert report["encrypted"] == 1
    assert report["legacy_plaintext"] == 1
    assert report["key"]["configured"] is True
    assert report["key"]["key_id"] == KEY.key_id
    assert KEY_BYTES.hex() not in result.stdout
    assert KEY_BYTES.hex() not in result.stderr


def test_verify_exits_zero_only_when_everything_decrypts(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store = SampleStore(store_root, key=KEY)
    good = store.put_bytes(b"a good one")
    bad = store.put_bytes(b"a corrupted one")
    blob = bytearray(store.blob_path(bad.sha256).read_bytes())
    blob[-1] ^= 0xFF
    store.blob_path(bad.sha256).write_bytes(bytes(blob))
    store.close()

    failed = _run(
        ["store", "verify", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path))],
        env, tmp_path,
    )
    assert failed.returncode == 2, failed.stderr
    report = json.loads(failed.stdout)
    assert report["ok"] is False
    assert report["failed"] == 1
    assert report["failures"][0]["sha256"] == bad.sha256
    assert report["failures"][0]["reason"] == "auth-failed"
    assert KEY_BYTES.hex() not in failed.stdout + failed.stderr

    # Verifying one healthy address passes on its own.
    ok = _run(
        ["store", "verify", "--json", "--sha", good.sha256, "--store", str(store_root),
         "--results", str(_results(tmp_path))],
        env, tmp_path,
    )
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["passed"] == 1


def test_verify_fails_closed_when_the_key_is_missing(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    writer = SampleStore(store_root, key=KEY)
    writer.put_bytes(b"encrypted")
    writer.close()

    env = _env(store_root)
    env.pop("HATCHERY_SAMPLE_KEY", None)
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    result = _run(
        ["store", "verify", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path))],
        env, tmp_path,
    )
    assert result.returncode == 2
    report = json.loads(result.stdout)
    assert report["failures"][0]["reason"] == "no-key"


def test_migrate_dry_run_then_apply_is_idempotent(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    data = b"legacy plaintext sample"
    sha = hashlib.sha256(data).hexdigest()
    store_root.mkdir()
    blob = store_root / f"{sha}.sample"
    blob.write_bytes(data)

    dry = _run(
        ["store", "migrate", "--dry-run", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path)), "--no-adopt-queue"],
        env, tmp_path,
    )
    assert dry.returncode == 0, dry.stderr
    report = json.loads(dry.stdout)
    assert report["legacy_found"] == 1
    assert report["would_encrypt"] == [sha]
    assert blob.read_bytes() == data, "a dry run must not write"

    applied = _run(
        ["store", "migrate", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path)), "--no-adopt-queue"],
        env, tmp_path,
    )
    assert applied.returncode == 0, applied.stderr
    assert [item["sha256"] for item in json.loads(applied.stdout)["encrypted"]] == [sha]
    assert blob.read_bytes()[:15] == b"HATCHERY-SAMPLE"

    again = _run(
        ["store", "migrate", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path)), "--no-adopt-queue"],
        env, tmp_path,
    )
    assert again.returncode == 0
    assert json.loads(again.stdout)["encrypted"] == []

    verified = _run(
        ["store", "verify", "--json", "--store", str(store_root),
         "--results", str(_results(tmp_path))],
        env, tmp_path,
    )
    assert verified.returncode == 0, verified.stdout


def test_prune_is_a_dry_run_until_apply_and_refuses_an_unknown_job(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store = SampleStore(store_root, key=KEY)
    record = store.put_bytes(b"expired sample")
    store.close()

    dry = _run(
        ["store", "prune", "--json", "--ttl", "0.001", "--store", str(store_root),
         "--results", str(_results(tmp_path)), "--queue", str(tmp_path / "none.db")],
        env, tmp_path,
    )
    assert dry.returncode == 0, dry.stderr
    report = json.loads(dry.stdout)
    assert report["applied"] is False
    assert [entry["sha256"] for entry in report["would_delete"]] == [record.sha256]
    assert store_root.joinpath(f"{record.sha256}.sample").exists()

    # A queued job whose sample cannot be identified blocks the delete.
    queue_db = make_queue_db(
        tmp_path / "queue.db",
        [{"job_id": "mystery", "sample_path": str(tmp_path / "gone.bin"), "status": "queued"}],
    )
    refused = _run(
        ["store", "prune", "--apply", "--json", "--ttl", "0.001", "--store", str(store_root),
         "--results", str(_results(tmp_path)), "--queue", str(queue_db)],
        env, tmp_path,
    )
    assert refused.returncode == 2
    report = json.loads(refused.stdout)
    assert report["refused"]
    assert report["deleted"] == []
    assert store_root.joinpath(f"{record.sha256}.sample").exists()

    applied = _run(
        ["store", "prune", "--apply", "--json", "--ttl", "0.001", "--store", str(store_root),
         "--results", str(_results(tmp_path)), "--queue", str(tmp_path / "none.db")],
        env, tmp_path,
    )
    assert applied.returncode == 0, applied.stderr
    assert [entry["sha256"] for entry in json.loads(applied.stdout)["deleted"]] == [record.sha256]
    assert not store_root.joinpath(f"{record.sha256}.sample").exists()


def test_keygen_writes_a_0600_key_and_never_prints_it(tmp_path: Path) -> None:
    key_path = tmp_path / "sample.key"
    env = dict(os.environ)
    env.pop("HATCHERY_SAMPLE_KEY", None)
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    created = _run(["store", "keygen", "-o", str(key_path)], env, tmp_path)
    assert created.returncode == 0, created.stderr
    payload = json.loads(created.stdout)
    assert payload["path"] == str(key_path)
    assert payload["mode"] == "0600"
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    import base64

    material = base64.b64decode(key_path.read_text().strip())
    assert len(material) == 32
    assert payload["key_id"]
    assert material.hex() not in created.stdout
    assert material.hex() not in created.stderr

    second = _run(["store", "keygen", "-o", str(key_path)], env, tmp_path)
    assert second.returncode == 1
    assert "already exists" in second.stderr


def test_store_errors_go_to_stderr_and_exit_one(tmp_path: Path) -> None:
    env = _env(tmp_path / "samples")
    env["HATCHERY_SAMPLE_KEY"] = "not-a-key"
    result = _run(
        ["store", "status", "--json", "--store", str(tmp_path / "samples"),
         "--results", str(_results(tmp_path))],
        env, tmp_path,
    )
    assert result.returncode == 1
    assert result.stdout.strip() == "", "stdout is reserved for a JSON object"
    assert "key-invalid" in result.stderr
    assert "not-a-key" not in result.stderr
