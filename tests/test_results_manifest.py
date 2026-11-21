"""The result-bundle manifest: sealing, verification and the anchored limit (D33).

Every test here uses a real run directory and real files. A manifest is only
worth having if the answer it gives on a *real* tampered tree is the honest one,
so nothing here asserts "a function was called".
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from _results_builder import (
    all_files,
    cli_json,
    manifest_bytes,
    manifest_hash,
    make_run,
    run_cli,
    seal_at,
    submit,
)
from engine.results import (
    MANIFEST_FILENAME,
    ManifestError,
    ensure_sealed,
    seal_run,
    serialize,
    verify_run,
)

# ---------------------------------------------------------------------------
# 1. A real submit seals the run; verify passes; the hash is stable
# ---------------------------------------------------------------------------


def test_a_real_submit_writes_a_manifest_at_the_run_root_and_verifies(
    tmp_path: Path,
) -> None:
    run_dir = submit(tmp_path)

    manifest_path = run_dir / MANIFEST_FILENAME
    assert manifest_path.is_file()
    assert not (run_dir / "bundle" / MANIFEST_FILENAME).exists(), (
        "the manifest must never live in bundle/: the API lists and ingests that "
        "directory and replay/cluster read it"
    )

    manifest = json.loads(manifest_path.read_bytes())
    assert manifest["format"] == "hatchery.result-manifest"
    assert manifest["manifest_version"] == 1
    assert manifest["stage"] == "submit"
    assert manifest["sealed_at"] and manifest["created_at"]
    assert manifest["run_id"] == run_dir.name
    assert manifest["algorithm"] == "sha256"
    assert manifest["sample"]["sha256"]
    assert len(manifest["files"]) == manifest["file_count"]
    assert sum(item["size"] for item in manifest["files"]) == manifest["total_bytes"]

    # Every file in the run is hashed, and nothing else is invented.
    assert {item["path"] for item in manifest["files"]} == all_files(run_dir) - {
        MANIFEST_FILENAME
    }
    for item in manifest["files"]:
        data = (run_dir / item["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item["sha256"]
        assert len(data) == item["size"]

    # The manifest is written last: no run file is newer than it.
    manifest_mtime = manifest_path.stat().st_mtime_ns
    for path in all_files(run_dir) - {MANIFEST_FILENAME}:
        assert (run_dir / path).stat().st_mtime_ns <= manifest_mtime

    # The file is 0600 and the bytes are the canonical serialization, so the
    # hash is reproducible rather than a property of dict ordering.
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    assert manifest_bytes(run_dir) == serialize(manifest)
    assert manifest_bytes(run_dir).endswith(b"\n")

    _, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert report["ok"] is True
    assert report["state"] == "intact"
    assert report["classification"] is None
    assert report["manifest_sha256"] == hashlib.sha256(manifest_bytes(run_dir)).hexdigest()
    assert report["stage"] == "submit"
    assert report["file_count"] == manifest["file_count"]
    assert report["hashed"] == manifest["file_count"]

    # Stable across two independent reads (and two independent verifies).
    first = manifest_hash(run_dir)
    second = manifest_hash(run_dir)
    assert first == second
    _, again = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert again["manifest_sha256"] == first


def test_verify_works_on_a_copied_run_and_without_a_database(tmp_path: Path) -> None:
    run_dir = submit(tmp_path, "original")
    copied = tmp_path / "delivery" / "renamed-run"
    copied.parent.mkdir()
    import shutil

    shutil.copytree(run_dir, copied)
    _, report = cli_json(["results", "verify", str(copied), "--json"], tmp_path, expect=0)
    assert report["state"] == "intact"
    # The manifest records the run id it was sealed under; verify reports it but
    # never compares it to the directory name, so a rename still verifies.
    assert report["run_id"] == "original"
    assert report["run_dir"] == str(copied)


# ---------------------------------------------------------------------------
# 2. Every break has a classification and a path
# ---------------------------------------------------------------------------


def _tampered(tmp_path: Path, name: str = "run") -> Path:
    return submit(tmp_path, name)


def test_modified_file_names_the_path_and_exits_one(tmp_path: Path) -> None:
    run_dir = _tampered(tmp_path)
    target = run_dir / "bundle" / "analysis.json"
    data = bytearray(target.read_bytes())
    data[10] ^= 0xFF
    target.write_bytes(bytes(data))

    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["ok"] is False
    assert report["state"] == "broken"
    assert report["classification"] == "modified"
    assert report["path"] == "bundle/analysis.json"


def test_missing_artifact_names_the_path(tmp_path: Path) -> None:
    run_dir = _tampered(tmp_path)
    (run_dir / "ocsf.json").unlink()
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "missing"
    assert report["path"] == "ocsf.json"


def test_extra_file_names_the_path(tmp_path: Path) -> None:
    run_dir = _tampered(tmp_path)
    (run_dir / "sandbox").mkdir(exist_ok=True)
    (run_dir / "sandbox" / "surprise.txt").write_text("added after the fact")
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "extra"
    assert report["path"] == "sandbox/surprise.txt"


def test_truncated_artifact_is_distinguished_from_modified(tmp_path: Path) -> None:
    run_dir = _tampered(tmp_path)
    target = run_dir / "report.md"
    data = target.read_bytes()
    target.write_bytes(data[: max(1, len(data) // 2)])
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "truncated"
    assert report["path"] == "report.md"


def test_symlink_is_a_break_and_its_target_is_never_hashed(tmp_path: Path) -> None:
    run_dir = _tampered(tmp_path)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("not part of the run")
    # A symlink whose size and bytes would match nothing: the point is that it
    # is classified as a symlink instead of being read.
    (run_dir / "bundle" / "link.json").symlink_to(outside)
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "symlink"
    assert report["path"] == "bundle/link.json"

    # A symlinked *directory* is a break too, and is not walked into.
    other = make_run(tmp_path / "results", "with-dir-link", sealed=False)
    (other / "elsewhere").symlink_to(tmp_path)
    with pytest.raises(ManifestError) as excinfo:
        seal_run(other, stage="seal")
    assert excinfo.value.reason == "symlink"
    assert excinfo.value.path == "elsewhere"
    assert not (other / MANIFEST_FILENAME).exists()


def test_a_symlinked_manifest_is_a_break(tmp_path: Path) -> None:
    run_dir = _tampered(tmp_path)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_bytes(manifest_bytes(run_dir))
    (run_dir / MANIFEST_FILENAME).unlink()
    (run_dir / MANIFEST_FILENAME).symlink_to(elsewhere)
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "symlink"
    assert report["path"] == MANIFEST_FILENAME


def test_a_manifest_that_points_outside_the_run_is_invalid_not_followed(
    tmp_path: Path,
) -> None:
    run_dir = make_run(tmp_path / "results", "run")
    document = json.loads((run_dir / MANIFEST_FILENAME).read_bytes())
    document["files"].append(
        {"path": "../escape.txt", "size": 1, "sha256": "0" * 64}
    )
    document["file_count"] = len(document["files"])
    (run_dir / MANIFEST_FILENAME).write_bytes(serialize(document))
    (tmp_path / "results" / "escape.txt").write_text("x")
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "manifest-invalid"
    assert report["path"] == MANIFEST_FILENAME


def test_a_newer_manifest_version_is_refused_not_approximated(tmp_path: Path) -> None:
    run_dir = make_run(tmp_path / "results", "run")
    document = json.loads((run_dir / MANIFEST_FILENAME).read_bytes())
    document["manifest_version"] = 2
    (run_dir / MANIFEST_FILENAME).write_bytes(serialize(document))
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "manifest-version"


def test_unreadable_manifest_is_invalid(tmp_path: Path) -> None:
    run_dir = make_run(tmp_path / "results", "run")
    (run_dir / MANIFEST_FILENAME).write_text("{not json")
    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path)
    assert code == 1
    assert report["classification"] == "manifest-invalid"


# ---------------------------------------------------------------------------
# 3. The anchor: an artifact plus its manifest rewritten together
# ---------------------------------------------------------------------------


def test_the_anchor_catches_a_rewrite_that_a_bare_manifest_cannot(tmp_path: Path) -> None:
    run_dir = submit(tmp_path)
    anchored = manifest_hash(run_dir)

    _, report = cli_json(
        ["results", "verify", str(run_dir), "--json", "--expect-manifest", anchored],
        tmp_path,
        expect=0,
    )
    assert report["ok"] is True
    assert report["anchor"]["match"] is True

    # Rewrite the evidence and regenerate the manifest, exactly as an attacker
    # with write access would. The manifest is internally consistent, so an
    # unanchored verify passes. This is the documented limit, pinned.
    (run_dir / "bundle" / "analysis.json").write_text(
        json.dumps({"task_id": "forged", "sample": {}, "static": {}}), encoding="utf-8"
    )
    seal_at(run_dir, "2026-11-21T00:00:00+00:00", stage="seal")
    assert manifest_hash(run_dir) != anchored

    _, unanchored = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert unanchored["ok"] is True
    assert unanchored["anchor"] is None

    code, replaced = cli_json(
        ["results", "verify", str(run_dir), "--json", "--expect-manifest", anchored],
        tmp_path,
    )
    assert code == 1
    assert replaced["classification"] == "replaced"
    assert replaced["path"] == MANIFEST_FILENAME
    assert replaced["anchor"]["match"] is False


def test_an_anchor_with_no_manifest_is_unambiguous(tmp_path: Path) -> None:
    run_dir = make_run(tmp_path / "results", "run", sealed=False)
    code, report = cli_json(
        [
            "results",
            "verify",
            str(run_dir),
            "--json",
            "--expect-manifest",
            "0" * 64,
        ],
        tmp_path,
    )
    assert code == 1
    assert report["classification"] == "manifest-missing"
    assert report["state"] == "broken"


# ---------------------------------------------------------------------------
# 4. Legacy runs: unsealed, seal, idempotent, refuse, --replace
# ---------------------------------------------------------------------------


def test_a_legacy_run_is_unsealed_not_ok_and_can_be_sealed(tmp_path: Path) -> None:
    run_dir = make_run(tmp_path / "results", "legacy", sealed=False)

    code, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert code == 0, "an unsealed legacy run must not break an existing corpus"
    assert report["ok"] is False, "unsealed is never ok"
    assert report["state"] == "unsealed"
    assert report["manifest_sha256"] is None

    first_code, first = cli_json(["results", "seal", str(run_dir), "--json"], tmp_path, expect=0)
    assert first["written"] is True
    assert first["stage"] == "seal"
    assert (run_dir / MANIFEST_FILENAME).is_file()

    mtime = (run_dir / MANIFEST_FILENAME).stat().st_mtime_ns
    second_code, second = cli_json(["results", "seal", str(run_dir), "--json"], tmp_path, expect=0)
    assert second["written"] is False, "a valid existing manifest is returned unchanged"
    assert second["manifest_sha256"] == first["manifest_sha256"]
    assert (run_dir / MANIFEST_FILENAME).stat().st_mtime_ns == mtime

    _, verified = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert verified["state"] == "intact"
    assert verified["stage"] == "seal"


def test_seal_refuses_a_mismatching_run_and_replace_is_loud(tmp_path: Path) -> None:
    run_dir = make_run(tmp_path / "results", "run")
    old = manifest_hash(run_dir)
    (run_dir / "bundle" / "events.jsonl").write_text('{"tampered":true}\n')

    code, refusal = cli_json(["results", "seal", str(run_dir), "--json"], tmp_path)
    assert code == 2
    assert refusal["reason"] == "manifest-mismatch"
    assert manifest_hash(run_dir) == old, "a refusal writes nothing"

    # The loud path: the old hash is printed and the anchor is declared void.
    human = run_cli(["results", "seal", str(run_dir), "--replace"], tmp_path)
    assert human.returncode == 0, human.stderr
    assert old in human.stdout
    assert "Any anchor recorded against it is void" in human.stdout
    after_replace = manifest_hash(run_dir)
    assert after_replace != old

    # And the same information is available to a script.
    (run_dir / "bundle" / "events.jsonl").write_text('{"tampered":"again"}\n')
    code, replaced = cli_json(
        ["results", "seal", str(run_dir), "--json", "--replace"], tmp_path, expect=0
    )
    assert replaced["written"] is True
    assert replaced["previous_manifest_sha256"] == after_replace
    assert replaced["manifest_sha256"] != after_replace


def test_seal_refuses_a_run_with_no_analysis_bundle(tmp_path: Path) -> None:
    run_dir = tmp_path / "results" / "empty"
    run_dir.mkdir(parents=True)
    with pytest.raises(ManifestError) as excinfo:
        seal_run(run_dir, stage="seal")
    assert excinfo.value.reason == "no-analysis"


def test_seal_is_bounded_by_file_count_and_size(tmp_path: Path, monkeypatch) -> None:
    from engine.results import manifest as manifest_module

    run_dir = make_run(tmp_path / "results", "run")
    (run_dir / "extra").write_bytes(b"x")
    monkeypatch.setattr(manifest_module, "MAX_FILES", 1)
    with pytest.raises(ManifestError) as excinfo:
        seal_run(run_dir, stage="seal")
    assert excinfo.value.reason == "too-many-files"

    monkeypatch.setattr(manifest_module, "MAX_FILES", 10_000)
    monkeypatch.setattr(manifest_module, "MAX_BYTES", 1)
    with pytest.raises(ManifestError) as excinfo:
        seal_run(run_dir, stage="seal")
    assert excinfo.value.reason == "too-large"


def test_the_manifest_never_contains_analysis_facts(tmp_path: Path) -> None:
    run_dir = submit(tmp_path)
    raw = manifest_bytes(run_dir)
    document = json.loads(raw)
    allowed = {
        "format",
        "manifest_version",
        "run_id",
        "task_id",
        "created_at",
        "stage",
        "sealed_at",
        "hatchery_version",
        "algorithm",
        "sample",
        "files",
        "file_count",
        "total_bytes",
    }
    assert set(document) == allowed
    assert set(document["sample"]) == {"sha256", "store_ref"}
    for item in document["files"]:
        assert set(item) == {"path", "size", "sha256"}
    # The EICAR string appears in the bundle and in the report; a manifest that
    # restates content would leak it to whoever receives the run.
    assert b"EICAR" not in raw
    assert b"ioc" not in raw.lower().replace(b"hatchery.result-manifest", b"")


def test_a_crash_before_the_manifest_leaves_no_manifest(tmp_path: Path) -> None:
    """A run directory mid-write reports unsealed, never a half-sealed intact."""
    run_dir = tmp_path / "results" / "inflight"
    (run_dir / "bundle").mkdir(parents=True)
    (run_dir / "bundle" / "analysis.json").write_text(
        json.dumps({"task_id": "inflight", "sample": {}, "static": {}})
    )
    report = verify_run(run_dir)
    assert report["state"] == "unsealed"
    assert report["ok"] is False
    assert not (run_dir / MANIFEST_FILENAME).exists()


def test_a_stale_seal_temporary_is_reported_not_counted(tmp_path: Path) -> None:
    run_dir = make_run(tmp_path / "results", "run")
    stray = run_dir / ".manifest.tmp-999-deadbeef"
    stray.write_text("partial")
    _, report = cli_json(["results", "verify", str(run_dir), "--json"], tmp_path, expect=0)
    assert report["state"] == "intact"
    assert report["stale_temporaries"] == [".manifest.tmp-999-deadbeef"]
    # The next seal ignores it and it never enters the file list.
    seal_run(run_dir, stage="seal")
    document = json.loads((run_dir / MANIFEST_FILENAME).read_bytes())
    assert all(item["path"] != ".manifest.tmp-999-deadbeef" for item in document["files"])


def test_verify_reports_a_missing_directory_as_a_usage_error(tmp_path: Path) -> None:
    result = run_cli(
        ["results", "verify", str(tmp_path / "nope")], tmp_path
    )
    assert result.returncode == 2
    assert "not-found" in result.stderr


def test_ensure_sealed_accepts_a_bundle_directory(tmp_path: Path) -> None:
    run_dir = submit(tmp_path)
    report = ensure_sealed(run_dir / "bundle")
    assert report["run_dir"] == str(run_dir)
    assert report["written"] is False


def test_a_run_id_change_does_not_break_verification(tmp_path: Path) -> None:
    """Relocatable: the manifest never compares its run id to the directory."""
    run_dir = submit(tmp_path)
    moved = tmp_path / "results" / "some-other-name"
    os.rename(run_dir, moved)
    report = verify_run(moved)
    assert report["ok"] is True
    assert report["run_id"] == run_dir.name  # reported
    assert report["run_dir"] == str(moved)  # not compared
