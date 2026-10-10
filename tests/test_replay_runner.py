"""Replay orchestration with an injected submit runner — no Docker, no Ollama.

The fake runner writes the replayed bundle where ``submit -o`` would. That keeps
the test fast while still exercising the real sample lookup, settings comparison,
signal comparison, verdict and bundle/replay.json persistence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from _replay_builder import (
    bundle_with,
    dynamic_bundle_with,
    fake_submit_runner,
    make_sample,
    write_run,
)

from engine.replay.replay import (
    ReplayError,
    build_submit_command,
    locate_sample,
    resolve_run_dir,
    run_replay,
)


def test_identical_static_replay_is_reproducible(tmp_path: Path) -> None:
    sample_path, sha = make_sample(tmp_path)
    overrides = {"sample": {"file_path": str(sample_path), "sha256": sha}}
    original = bundle_with(**overrides)
    replayed = bundle_with(task_id="replay-task", **overrides)
    original_dir = write_run(tmp_path, original, "orig")
    out = tmp_path / "replay-out"

    result = run_replay(
        original_dir, output_dir=out, submit_runner=fake_submit_runner(replayed)
    )

    assert result.verdict == "reproducible"
    assert result.exit_code == 0
    assert result.section["deterministic_mismatches"] == []
    assert result.section["settings"]["reproduced"] is True
    assert result.section["replay_task_id"] == "replay-task"

    # replay.json next to the replayed bundle, and the section patched into it
    replay_json = out / "bundle" / "replay.json"
    assert replay_json.exists()
    assert json.loads(replay_json.read_text())["verdict"] == "reproducible"
    patched = json.loads((out / "bundle" / "analysis.json").read_text())
    assert patched["replay"]["verdict"] == "reproducible"
    assert patched["summary"]["replay_static_identical"] is True

    # the original bundle is never mutated
    assert "replay" not in json.loads((original_dir / "analysis.json").read_text())


def test_static_mismatch_fails_loudly(tmp_path: Path) -> None:
    sample_path, sha = make_sample(tmp_path)
    overrides = {"sample": {"file_path": str(sample_path), "sha256": sha}}
    original = bundle_with(**overrides)
    replayed = bundle_with(
        static={"capa": {"capabilities": [{"name": "create process"}]}},
        **overrides,
    )
    original_dir = write_run(tmp_path, original, "orig")

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replay-out",
        submit_runner=fake_submit_runner(replayed),
    )

    assert result.verdict == "static-mismatch"
    assert result.exit_code == 2
    assert "capa_capabilities" in result.section["deterministic_mismatches"]
    assert any("does NOT reproduce" in line for line in result.section["limitations"])


def test_dynamic_drift_is_reported_not_failed(tmp_path: Path) -> None:
    sample_path, sha = make_sample(tmp_path)
    overrides = {"sample": {"file_path": str(sample_path), "sha256": sha}}
    original = dynamic_bundle_with(**overrides)
    replayed = dynamic_bundle_with(
        summary={"events_total": 250, "events_by_category": {"file": 200}},
        sandbox={"status": "completed", "duration_seconds": 90.0,
                 "monitoring": {"collector": "strace-ptrace"}},
        **overrides,
    )
    original_dir = write_run(tmp_path, original, "orig")

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replay-out",
        submit_runner=fake_submit_runner(replayed),
    )

    assert result.verdict == "dynamic-drift"
    assert result.exit_code == 0
    assert result.section["deterministic_mismatches"] == []
    assert "events_total" in result.section["dynamic_drift"]
    assert any("Dynamic drift" in line for line in result.section["limitations"])


def test_force_no_sandbox_on_a_dynamic_original_is_inconclusive(tmp_path: Path) -> None:
    sample_path, sha = make_sample(tmp_path)
    overrides = {"sample": {"file_path": str(sample_path), "sha256": sha}}
    original = dynamic_bundle_with(**overrides)
    # same static facts, but no detonation
    replayed = bundle_with(**overrides)
    original_dir = write_run(tmp_path, original, "orig")

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replay-out",
        force_no_sandbox=True,
        submit_runner=fake_submit_runner(replayed),
    )

    assert result.verdict == "inconclusive"
    assert result.exit_code == 1
    assert result.section["deterministic_mismatches"] == []
    assert any("skipped detonation" in line for line in result.section["limitations"])


def test_missing_sample_is_inconclusive(tmp_path: Path) -> None:
    original = bundle_with(
        sample={
            "file_path": "/nonexistent/hatchery-replay-missing.bin",
            "sha256": "f" * 64,
        }
    )
    original_dir = write_run(tmp_path, original, "orig")
    out = tmp_path / "replay-out"

    result = run_replay(
        original_dir,
        output_dir=out,
        # a runner that must never be called: there is no sample to submit
        submit_runner=lambda command, timeout: (_ for _ in ()).throw(
            AssertionError("submit must not run without a sample")
        ),
    )

    assert result.verdict == "inconclusive"
    assert result.exit_code == 1
    assert result.section["sample"]["hash_verified"] is False
    assert "could not be located" in result.section["limitations"][1]
    # the failure is still recorded next to the intended replay output
    assert json.loads((out / "replay.json").read_text())["verdict"] == "inconclusive"


def test_sample_with_different_bytes_is_refused(tmp_path: Path) -> None:
    sample_path, _ = make_sample(tmp_path, b"the wrong bytes\n")
    original = bundle_with(
        sample={"file_path": str(sample_path), "sha256": "e" * 64}
    )
    original_dir = write_run(tmp_path, original, "orig")

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replay-out",
        submit_runner=lambda command, timeout: (0, "", ""),
    )

    assert result.verdict == "inconclusive"
    assert "refusing to replay different bytes" in result.section["limitations"][1]


def test_sample_is_recovered_from_the_content_addressed_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    data = b"recovered from the store\n"
    sample_path, sha = make_sample(tmp_path, data)
    sample_path.unlink()  # the recorded path is gone
    store = tmp_path / "samples" / f"{sha}.sample"
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(data)

    original = bundle_with(
        sample={"file_path": str(sample_path), "sha256": sha},
    )
    replayed = bundle_with(sample={"file_path": str(sample_path), "sha256": sha})
    original_dir = write_run(tmp_path, original, "orig")

    result = run_replay(
        original_dir,
        output_dir=tmp_path / "replay-out",
        submit_runner=fake_submit_runner(replayed),
    )

    assert result.verdict == "reproducible"
    assert result.section["sample"]["resolution"] == "stored sample store"


def test_missing_bundle_raises_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="no analysis.json"):
        run_replay(tmp_path / "does-not-exist")


def test_malformed_bundle_raises_a_clean_error(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "bad" / "bundle"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "analysis.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(ReplayError, match="malformed bundle"):
        run_replay(bundle_dir)


def test_resolve_run_dir_accepts_task_and_bundle_dirs(tmp_path: Path) -> None:
    original = bundle_with()
    bundle_dir = write_run(tmp_path, original, "orig")
    assert resolve_run_dir(tmp_path / "orig") == bundle_dir
    assert resolve_run_dir(bundle_dir) == bundle_dir


def test_build_submit_command_reproduces_the_stage_flags(tmp_path: Path) -> None:
    static = build_submit_command(
        tmp_path / "s", tmp_path / "o", dynamic=False, emulation=False
    )
    assert "--no-sandbox" in static
    assert "--emulate" not in static

    full = build_submit_command(
        tmp_path / "s", tmp_path / "o", dynamic=True, emulation=True,
        allow_host_emulation=True,
    )
    assert "--no-sandbox" not in full
    assert "--emulate" in full
    assert "--allow-host-emulation" in full


def test_locate_sample_prefers_an_explicit_override(tmp_path: Path) -> None:
    sample_path, sha = make_sample(tmp_path)
    original = bundle_with(sample={"file_path": "/gone", "sha256": sha})
    resolution = locate_sample(original, tmp_path, override=sample_path)
    assert resolution.hash_verified is True
    assert resolution.resolution == "--sample override"
