"""Result-bundle retention, the growth guard and crash-resume (D33).

The rule under test is not "prune deletes old directories". It is: *a run is
deleted only when it is verified intact, past an explicit policy, and not the
anchor — and the dry run reports exactly what the apply does.* A run that cannot
be verified is never deleted, and nothing runs on its own.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from _results_builder import (
    base_env,
    cli_json,
    iso_days_ago,
    make_run,
    run_cli,
    seal_at,
)
from engine.results import (
    PRUNE_LOG_FILENAME,
    RESULTS_LOCK_FILENAME,
    growth_report,
    parse_duration,
    resolve_policy,
    scan_root,
    verify_run,
)


def _seeded(tmp_path: Path) -> Path:
    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-old", days_ago=30)
    make_run(results, "run-mid", days_ago=20)
    make_run(results, "run-new", days_ago=1)
    return results


# ---------------------------------------------------------------------------
# 6. Dry run, apply, the anchor, the clamp, and fail-closed
# ---------------------------------------------------------------------------


def test_dry_run_deletes_nothing_and_apply_removes_exactly_that(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    before = sorted(path.name for path in results.iterdir() if path.is_dir())

    code, dry = cli_json(
        [
            "results",
            "prune",
            "--older-than",
            "10d",
            "--keep-last",
            "1",
            "--json",
            "--results",
            str(results),
        ],
        tmp_path,
        expect=0,
    )
    assert dry["applied"] is False
    assert [item["run_id"] for item in dry["decisions"] if item["decision"] == "delete"] == [
        "run-old",
        "run-mid",
    ]
    assert sorted(path.name for path in results.iterdir() if path.is_dir()) == before, (
        "a dry run must delete nothing"
    )
    assert not (results / PRUNE_LOG_FILENAME).exists() or json.loads(
        (results / PRUNE_LOG_FILENAME).read_text().splitlines()[-1]
    )["applied"] is False

    code, applied = cli_json(
        [
            "results",
            "prune",
            "--older-than",
            "10d",
            "--keep-last",
            "1",
            "--apply",
            "--json",
            "--results",
            str(results),
        ],
        tmp_path,
        expect=0,
    )
    assert applied["applied"] is True
    assert [item["run_id"] for item in applied["removed"]] == dry["would_remove"]
    assert sorted(path.name for path in results.iterdir() if path.is_dir()) == ["run-new"]
    assert applied["bytes_freed"] == dry["would_free_bytes"]
    assert verify_run(results / "run-new")["state"] == "intact"

    log = results / PRUNE_LOG_FILENAME
    assert log.is_file()
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    entries = [json.loads(line) for line in log.read_text().splitlines() if line]
    assert len(entries) == 2  # one dry run, one apply
    assert entries[-1]["applied"] is True
    assert [item["run_id"] for item in entries[-1]["removed"]] == ["run-old", "run-mid"]
    assert entries[-1]["policy"]["keep_last"] == 1
    assert [item["reason"] for item in entries[-1]["kept"]] == ["not-expired"]


def test_the_newest_run_is_kept_even_when_everything_has_expired(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    for index in range(4):
        make_run(results, f"run-{index}", days_ago=index + 1)

    code, report = cli_json(
        ["results", "prune", "--older-than", "0s", "--keep-last", "1", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert code == 0
    assert [item["run_id"] for item in report["removed"]] == ["run-3", "run-2", "run-1"]
    survivors = sorted(path.name for path in results.iterdir() if path.is_dir())
    assert survivors == ["run-0"], "the newest run is the anchor"
    assert report["clamped"] is True
    assert report["anchor"]["run_id"] == "run-0"


def test_keep_last_zero_is_clamped_to_one_not_refused(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-old", days_ago=5)
    make_run(results, "run-new", days_ago=1)

    code, report = cli_json(
        ["results", "prune", "--older-than", "0s", "--keep-last", "0", "--json",
         "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert report["policy"]["keep_last"] == 1
    assert report["policy"]["keep_last_requested"] == 0
    assert report["clamped"] is True
    assert report["would_remove"] == ["run-old"]
    assert report["anchor"]["run_id"] == "run-new"


def test_retention_is_off_by_default(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    env = base_env(tmp_path)
    code, report = cli_json(
        ["results", "prune", "--json", "--results", str(results)], tmp_path, env=env,
        expect=0,
    )
    assert report["policy"]["enabled"] is False
    assert report["policy"]["older_than_seconds"] is None
    assert report["would_remove"] == []
    assert all(item["reason"] == "not-expired" for item in report["decisions"])
    assert len(list(results.iterdir())) >= 3


def test_retention_defaults_come_from_the_environment(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    env = base_env(tmp_path)
    env["HATCHERY_RESULTS_RETENTION_DAYS"] = "10"
    env["HATCHERY_RESULTS_KEEP_LAST"] = "2"
    code, report = cli_json(
        ["results", "prune", "--json", "--results", str(results)], tmp_path, env=env,
        expect=0,
    )
    assert report["policy"]["older_than_seconds"] == 10 * 86400
    assert report["policy"]["source"] == {"older_than": "env", "keep_last": "env"}
    assert report["would_remove"] == ["run-old"]


def test_an_unsealed_run_blocks_apply_and_nothing_is_deleted(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    legacy = make_run(results, "run-legacy", days_ago=60, sealed=False)

    code, report = cli_json(
        ["results", "prune", "--older-than", "10d", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
    )
    assert code == 2, "a policy that cannot be proven must fail closed"
    assert report["blocked"] is True
    assert [item["run_id"] for item in report["refused"]] == ["run-legacy"]
    assert report["refused"][0]["reason"] == "no-manifest"
    assert report["removed"] == []
    assert (results / "run-old").is_dir(), (
        "a refusal deletes none of the runs it could have deleted"
    )
    assert (results / "run-mid").is_dir()
    assert (legacy / "bundle" / "analysis.json").is_file()


def test_a_tampered_run_blocks_apply_and_names_the_break(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    broken = results / "run-old"
    (broken / "bundle" / "analysis.json").write_text("{}")

    code, report = cli_json(
        ["results", "prune", "--older-than", "10d", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
    )
    assert code == 2
    assert report["refused"][0]["run_id"] == "run-old"
    assert report["refused"][0]["reason"] == "manifest-invalid"
    assert report["refused"][0]["classification"] == "truncated"
    assert report["refused"][0]["path"] == "bundle/analysis.json"
    assert report["removed"] == []


def test_an_unparseable_bundle_blocks_apply(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    run = make_run(results, "run", days_ago=10)
    # A manifest can only be produced by seal(), which refuses to seal an
    # unparseable bundle. So simulate the state a rewrite would leave: garbage in
    # analysis.json with a manifest that matches those exact bytes. Verification
    # passes (the bytes are what the manifest records) and the retention decision
    # still refuses to reason about a bundle it cannot parse.
    garbage = b"{not json"
    (run / "bundle" / "analysis.json").write_bytes(garbage)
    document = json.loads((run / "manifest.json").read_bytes())
    for entry in document["files"]:
        if entry["path"] == "bundle/analysis.json":
            entry["size"] = len(garbage)
            entry["sha256"] = hashlib.sha256(garbage).hexdigest()
    from engine.results import serialize

    document["total_bytes"] = sum(entry["size"] for entry in document["files"])
    (run / "manifest.json").write_bytes(serialize(document))
    make_run(results, "run-new", days_ago=1)

    code, report = cli_json(
        ["results", "prune", "--older-than", "0s", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
    )
    assert code == 2
    assert report["refused"][0]["reason"] == "unparseable"
    assert report["removed"] == []


def test_a_directory_that_is_not_a_run_is_ignored(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    (results / "notes").mkdir()
    (results / "notes" / "todo.txt").write_text("not a run")
    code, report = cli_json(
        ["results", "prune", "--older-than", "10d", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert report["ignored"] == ["notes"]
    assert (results / "notes" / "todo.txt").is_file()


# ---------------------------------------------------------------------------
# 9. Rename-then-remove, the stray and crash-resume
# ---------------------------------------------------------------------------


def test_a_crashed_delete_is_reported_and_resumed(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-new", days_ago=1)
    victim = make_run(results, "run-old", days_ago=30)

    # Simulate the crash between the rename and the rmtree.
    renamed = victim.with_name(f"{victim.name}.deleting-20261121T000000Z")
    os.rename(victim, renamed)

    # Nothing reads the half-deleted tree as the run any more.
    assert not victim.exists()
    assert verify_run(victim)["state"] == "broken"
    missing = run_cli(["results", "verify", str(victim)], tmp_path)
    assert missing.returncode == 2
    assert "not-found" in missing.stderr

    code, status = cli_json(["results", "status", "--json", "--results", str(results)],
                            tmp_path, expect=0)
    assert [item["name"] for item in status["strays"]] == [renamed.name]
    assert status["strays"][0]["reason"] == "deleting-in-progress"
    assert status["runs"] == 1, "a stray is not a run"

    code, report = cli_json(
        ["results", "prune", "--older-than", "10d", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert report["resumed_strays"] == [renamed.name]
    assert not renamed.exists()
    assert report["bytes_freed"] >= 0
    assert (results / "run-new").is_dir()


def test_deletion_renames_before_it_removes(tmp_path: Path, monkeypatch) -> None:
    """A reader can never observe a partially removed run tree."""
    from engine.results import retention as retention_module

    results = tmp_path / "results"
    results.mkdir()
    make_run(results, "run-new", days_ago=1)
    make_run(results, "run-old", days_ago=30)
    observed: list[str] = []
    real_rmtree = retention_module.shutil.rmtree

    def spy(path, *args, **kwargs):
        # At the moment the tree is removed, the run's public name is already
        # gone and the only thing on disk is the .deleting- directory.
        observed.append(Path(path).name)
        assert not (results / "run-old").exists()
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(retention_module.shutil, "rmtree", spy)
    policy = resolve_policy(older_than="10d", keep_last=1)
    report = retention_module.prune_runs(results, policy=policy, apply=True)
    assert [item["run_id"] for item in report["removed"]] == ["run-old"]
    assert observed and observed[0].startswith("run-old.deleting-")
    assert not any(path.name.startswith("run-old") for path in results.iterdir())


# ---------------------------------------------------------------------------
# 8. Concurrency: a locked root, and a submission during a prune
# ---------------------------------------------------------------------------


def test_a_second_prune_reports_results_locked(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    lock_path = results / RESULTS_LOCK_FILENAME
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        code, report = cli_json(
            ["results", "prune", "--older-than", "10d", "--apply", "--json",
             "--results", str(results)],
            tmp_path,
        )
        assert code == 2
        assert report["locked"] is True
        assert report["reason"] == "results-locked"
        assert report["removed"] == []
        assert all((results / name).is_dir() for name in ("run-old", "run-mid", "run-new"))
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_a_concurrent_prune_loses_the_lock_cleanly(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    env = base_env(tmp_path)
    command = [
        sys.executable,
        "-m",
        "engine.cli",
        "results",
        "prune",
        "--older-than",
        "10d",
        "--apply",
        "--json",
        "--results",
        str(results),
    ]
    first = subprocess.Popen(
        command, cwd=tmp_path, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    second = subprocess.Popen(
        command, cwd=tmp_path, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )
    out_first = first.communicate(timeout=300)
    out_second = second.communicate(timeout=300)
    payloads = [json.loads(out) for out, _err in (out_first, out_second) if out.strip()]
    # Whatever the interleaving, exactly one prune removed the expired runs and
    # the other either found nothing to do or said the root was locked. No run is
    # ever half-deleted and the survivors still verify.
    removed = [
        item["run_id"] for payload in payloads for item in payload.get("removed", [])
    ]
    assert removed == ["run-old", "run-mid"]
    locked = [payload for payload in payloads if payload.get("locked")]
    if locked:
        assert locked[0]["reason"] == "results-locked"
    assert verify_run(results / "run-new")["state"] == "intact"
    assert [path.name for path in results.iterdir() if path.is_dir()] == ["run-new"]


def test_a_submission_during_a_prune_survives_and_seals(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    for index in range(3):
        make_run(results, f"expired-{index}", days_ago=30 + index)

    # In-flight work: a run directory that exists but has no manifest yet.
    inflight = results / "inflight"
    (inflight / "sandbox").mkdir(parents=True)
    (inflight / "sandbox" / "strace.log").write_text("partial")

    code, blocked = cli_json(
        ["results", "prune", "--older-than", "10d", "--apply", "--json",
         "--results", str(results)],
        tmp_path,
    )
    # `sandbox/` alone is not a run (no bundle), so this prune proceeds; a run
    # with a bundle and no manifest is the case that blocks (tested above).
    assert blocked["removed"]
    assert inflight.is_dir()

    # A burst of real submissions into the same root while a prune runs: a run
    # being written is either invisible (no bundle yet) or blocks the delete by
    # having no manifest — it is never deleted and never half-sealed.
    env = base_env(tmp_path)
    sample = (Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "eicar.com")
    # The burst is about one results root, not about one sample store: three
    # concurrent writers to a single SQLite index is D28's own (unsupported)
    # concurrency case, so each submitter gets its own store. The run directories
    # — what this test is about — are shared.
    submitters = [
        subprocess.Popen(
            [
                sys.executable, "-m", "engine.cli", "submit",
                str(sample), "--no-sandbox", "-o", str(results / f"fresh-{index}"),
            ],
            cwd=Path(__file__).resolve().parent.parent,
            env={**env, "HATCHERY_SAMPLE_STORE": str(tmp_path / f"samples-{index}")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for index in range(3)
    ]
    pruner = subprocess.Popen(
        [
            sys.executable, "-m", "engine.cli", "results", "prune",
            "--older-than", "10d", "--apply", "--json", "--results", str(results),
        ],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    prune_out, prune_err = pruner.communicate(timeout=300)
    assert prune_out.strip(), prune_err
    report = json.loads(prune_out)
    assert all(
        not str(item["run_id"]).startswith("fresh") for item in report.get("removed", [])
    )
    for index, submitter in enumerate(submitters):
        out, err = submitter.communicate(timeout=300)
        assert submitter.returncode == 0, out[-2000:] + err[-1000:]
        assert verify_run(results / f"fresh-{index}")["state"] == "intact"
    # Every manifest in the root parses and every run verifies: no half-written
    # manifest survived the race.
    for child in results.iterdir():
        if child.is_dir() and (child / "manifest.json").is_file():
            assert verify_run(child)["state"] == "intact"
    assert not any(path.name.startswith(".manifest.tmp-") for path in results.iterdir())


# ---------------------------------------------------------------------------
# 5. Status and the growth guard
# ---------------------------------------------------------------------------


def test_status_reports_oldest_newest_strays_and_never_deletes(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    make_run(results, "nested-parent", days_ago=2)
    nested = results / "nested-parent" / "replay-deadbeef"
    nested.mkdir()
    (nested / "bundle").mkdir()
    (nested / "bundle" / "analysis.json").write_text(
        json.dumps({"task_id": "replay", "sample": {}, "static": {}})
    )
    seal_at(nested, iso_days_ago(2))
    (results / "run-old.deleting-20261001T000000Z").mkdir()

    before = sorted(path.name for path in results.iterdir() if path.is_dir())
    code, status = cli_json(["results", "status", "--json", "--results", str(results)],
                            tmp_path, expect=0)
    assert status["runs"] == 4
    assert status["nested_replay_runs"] == 1
    assert status["oldest"]["run_id"] == "run-old"
    assert status["newest"]["run_id"] == "run-new"
    assert [item["name"] for item in status["strays"]] == [
        "run-old.deleting-20261001T000000Z"
    ]
    assert status["growth"]["enforced"] is False
    assert sorted(path.name for path in results.iterdir()) == before, (
        "status must never delete or create anything in the corpus"
    )


def test_status_reports_what_a_prune_would_remove(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    code, status = cli_json(
        ["results", "status", "--json", "--older-than", "10d", "--keep-last", "1",
         "--results", str(results)],
        tmp_path,
        expect=0,
    )
    assert sorted(status["would_remove"]) == ["run-mid", "run-old"]
    assert status["would_free_bytes"] > 0
    assert len([path for path in results.iterdir() if path.is_dir()]) == 3


def test_the_growth_guard_warns_and_never_deletes(tmp_path: Path, monkeypatch) -> None:
    results = _seeded(tmp_path)
    monkeypatch.setenv("HATCHERY_RESULTS_WARN_RUNS", "2")
    monkeypatch.setenv("HATCHERY_RESULTS_WARN_BYTES", "1")
    code, status = cli_json(["results", "status", "--json", "--results", str(results)],
                            tmp_path, expect=0)
    growth = status["growth"]
    assert growth["warned"] is True
    assert growth["enforced"] is False
    assert set(growth["crossed"]) == {"runs", "bytes"}
    assert len([path for path in results.iterdir() if path.is_dir()]) == 3, (
        "the guard warns; it never deletes"
    )
    human = run_cli(["results", "status", "--results", str(results)], tmp_path,
                    env={**base_env(tmp_path), "HATCHERY_RESULTS_WARN_RUNS": "2"})
    assert human.returncode == 0
    assert "threshold-crossed" in human.stdout


def test_zero_disables_a_growth_threshold(monkeypatch) -> None:
    monkeypatch.setenv("HATCHERY_RESULTS_WARN_RUNS", "0")
    monkeypatch.setenv("HATCHERY_RESULTS_WARN_BYTES", "0")
    report = growth_report(run_count=10**9, total_bytes=10**15)
    assert report["crossed"] == []
    assert report["warned"] is False


def test_durations_and_policy_parsing() -> None:
    assert parse_duration("30d") == 30 * 86400
    assert parse_duration("12h") == 12 * 3600
    assert parse_duration("90s") == 90
    assert parse_duration("2w") == 2 * 604800
    assert parse_duration("3600") == 3600
    assert parse_duration(None) is None
    policy = resolve_policy(older_than="30d", keep_last=3)
    assert policy["older_than_seconds"] == 30 * 86400
    assert policy["keep_last"] == 3
    assert policy["clamped_keep_last"] is False


def test_scan_root_separates_runs_strays_and_ignored(tmp_path: Path) -> None:
    results = _seeded(tmp_path)
    (results / ".results.lock").write_text("")
    (results / "stray.deleting-20261121T000000Z").mkdir()
    (results / "not-a-run").mkdir()
    scan = scan_root(results)
    assert sorted(run.run_id for run in scan["runs"]) == ["run-mid", "run-new", "run-old"]
    assert [item["name"] for item in scan["strays"]] == [
        "stray.deleting-20261121T000000Z"
    ]
    assert scan["ignored"] == ["not-a-run"]
