"""`hatchery store key|backup|restore` — JSON, exit codes and secret hygiene (D29).

Driven as real processes, because the contract is about what an operator or a
script sees: one JSON object on stdout, diagnostics on stderr, documented
non-zero exits, and never key material.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from _store_builder import KEY, KEY_BYTES

from engine.store import SampleStore

REPO_ROOT = Path(__file__).resolve().parent.parent


def _env(store_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["HATCHERY_SAMPLE_STORE"] = str(store_root)
    env["HATCHERY_SAMPLE_KEY"] = KEY_BYTES.hex()
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    env.pop("HATCHERY_QUEUE_DB", None)
    return env


def _run(args: list[str], env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=env,
    )


def test_backup_and_restore_cli_are_json_and_never_print_key_material(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store = SampleStore(store_root, key=KEY)
    store.put_bytes(b"cli backup payload")
    store.close()

    backup = tmp_path / "backup"
    created = _run(["store", "backup", "--json", "-o", str(backup)], env, tmp_path)
    assert created.returncode == 0, created.stderr
    report = json.loads(created.stdout)
    assert report["counts"]["samples"] == 1
    assert report["key"]["included"] is False
    assert report["key"]["restorable_without_operator_key"] is False
    assert KEY_BYTES.hex() not in created.stdout + created.stderr

    restored = _run(
        ["store", "restore", str(backup), "--target", str(tmp_path / "restored"), "--json"],
        env,
        tmp_path,
    )
    assert restored.returncode == 0, restored.stderr
    payload = json.loads(restored.stdout)
    assert payload["ok"] is True
    assert payload["samples"] == 1
    assert payload["store_root"] == str((tmp_path / "restored" / "samples").resolve())
    assert payload["verify"]["ok"] is True
    assert KEY_BYTES.hex() not in restored.stdout + restored.stderr


def test_include_key_is_warned_on_stderr_and_still_prints_only_ids(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store = SampleStore(store_root, key=KEY)
    store.put_bytes(b"include the key")
    store.close()

    backup = tmp_path / "backup"
    created = _run(
        ["store", "backup", "--json", "--include-key", "-o", str(backup)], env, tmp_path
    )
    assert created.returncode == 0, created.stderr
    report = json.loads(created.stdout)
    assert report["key"]["included"] is True
    assert report["key"]["restorable_without_operator_key"] is True
    assert "INCLUDED" in created.stderr, "including a secret must be loud"
    secret = backup / "secrets" / "sample-keyring"
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    assert KEY_BYTES.hex() not in created.stdout + created.stderr

    # Restoring twice into the same non-empty root is refused with a reason.
    target = tmp_path / "restored"
    first = _run(["store", "restore", str(backup), "--target", str(target), "--json"], env, tmp_path)
    assert first.returncode == 0, first.stderr
    second = _run(["store", "restore", str(backup), "--target", str(target), "--json"], env, tmp_path)
    assert second.returncode == 1
    assert second.stdout.strip() == "", "stdout is reserved for a JSON object"
    assert "restore-target-not-empty" in second.stderr
    assert KEY_BYTES.hex() not in second.stdout + second.stderr


def test_restore_refuses_a_tampered_backup_with_a_documented_exit(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store = SampleStore(store_root, key=KEY)
    store.put_bytes(b"tampered backup payload")
    store.close()
    backup = tmp_path / "backup"
    assert _run(["store", "backup", "--json", "-o", str(backup)], env, tmp_path).returncode == 0

    blob = next((backup / "store" / "blobs").glob("*.sample"))
    data = bytearray(blob.read_bytes())
    data[-1] ^= 0xFF
    blob.write_bytes(bytes(data))
    result = _run(
        ["store", "restore", str(backup), "--target", str(tmp_path / "restored"), "--json"],
        env,
        tmp_path,
    )
    assert result.returncode == 1
    assert "restore-blob-mismatch" in result.stderr
    assert not (tmp_path / "restored").exists()
    assert KEY_BYTES.hex() not in result.stdout + result.stderr


def test_backup_refuses_a_plaintext_legacy_store(tmp_path: Path) -> None:
    store_root = tmp_path / "samples"
    env = _env(store_root)
    store_root.mkdir()
    data = b"pre-D28 plaintext"
    (store_root / f"{hashlib.sha256(data).hexdigest()}.sample").write_bytes(data)

    result = _run(
        ["store", "backup", "--json", "-o", str(tmp_path / "backup")], env, tmp_path
    )
    assert result.returncode == 2
    assert "backup-failed" in result.stderr
    assert "migrate" in result.stderr
    assert not (tmp_path / "backup" / "manifest.json").exists()
    assert list((tmp_path / "backup").glob("store/blobs/*")) == [], (
        "a refused backup must not have copied the plaintext blob"
    )
