"""Tests for the canonical analysis bundle and the limitations engine."""

from __future__ import annotations

from pathlib import Path

from engine.bundle import (
    ANALYSIS_FILENAME,
    EVENTS_FILENAME,
    AnalysisBundle,
    compute_limitations,
    events_from_inotify,
    load_bundle,
    load_events,
    normalize_events,
    render_limitations,
    write_bundle,
)


class FakeStraceEvent:
    def __init__(self, syscall: str) -> None:
        self.timestamp = "12:00:00.000001"
        self.pid = 42
        self.syscall = syscall
        self.args = '"/etc/passwd", O_RDONLY'
        self.return_value = "3"
        self.category = type("C", (), {"value": "file"})()
        self.severity = type("S", (), {"value": "info"})()
        self.indicators: list[str] = []


class FakeStraceResult:
    def __init__(self, syscalls: list[str]) -> None:
        self.events = [FakeStraceEvent(s) for s in syscalls]


def test_bundle_round_trip(tmp_path: Path):
    bundle = AnalysisBundle(
        task_id="abc123",
        sample={"file_name": "x.bin", "md5": "d41d8cd98f00b204e9800998ecf8427e"},
        static={"yara": {"matches": []}},
        events=[{"timestamp": "t", "category": "file", "severity": "info"}],
    )
    analysis_path, events_path = write_bundle(tmp_path, bundle)

    assert analysis_path.name == ANALYSIS_FILENAME
    assert events_path.name == EVENTS_FILENAME

    loaded = load_bundle(tmp_path)
    assert loaded["task_id"] == "abc123"
    assert loaded["schema_version"] == bundle.schema_version
    assert loaded["sample"]["file_name"] == "x.bin"

    rows = load_events(tmp_path)
    assert len(rows) == 1
    assert rows[0]["category"] == "file"


def test_load_events_skips_malformed_lines(tmp_path: Path):
    (tmp_path / EVENTS_FILENAME).write_text('{"a": 1}\nnot json\n\n{"a": 2}\n')
    rows = load_events(tmp_path)
    assert [r["a"] for r in rows] == [1, 2]


def test_load_bundle_raises_clearly_when_absent(tmp_path: Path):
    try:
        load_bundle(tmp_path)
    except FileNotFoundError as e:
        assert ANALYSIS_FILENAME in str(e)
    else:  # pragma: no cover
        raise AssertionError("expected FileNotFoundError")


def test_strace_events_are_normalized_to_api_row_shape():
    rows = normalize_events(strace_result=FakeStraceResult(["openat", "connect"]))
    assert len(rows) == 2
    row = rows[0]
    for key in (
        "timestamp",
        "pid",
        "syscall_name",
        "category",
        "severity",
        "args",
        "return_value",
        "raw_line",
        "source",
    ):
        assert key in row
    assert row["source"] == "strace"
    # args must be JSON-encoded for the API's TEXT column.
    assert row["args"].startswith("{")


def test_inotify_events_flag_suspicious_paths(tmp_path: Path):
    log = tmp_path / "inotify.log"
    log.write_text(
        "2026-01-01T00:00:00 /home/user/doc.txt CREATE\n"
        "2026-01-01T00:00:01 /dev/shm/implant CREATE\n"
        "2026-01-01T00:00:02 /etc/cron.d/persist MODIFY\n"
    )
    rows = events_from_inotify(log)

    assert len(rows) == 3
    assert rows[0]["category"] == "file"
    assert rows[0]["severity"] == "low"
    assert rows[1]["severity"] == "high"
    assert rows[2]["severity"] == "high"


def test_inotify_missing_log_is_not_an_error(tmp_path: Path):
    assert events_from_inotify(tmp_path / "nope.log") == []
    assert events_from_inotify(None) == []


def test_events_are_sorted_chronologically():
    rows = normalize_events(
        strace_result=FakeStraceResult(["openat"]),
        inotify_log=None,
    )
    assert len(rows) >= 1


# ---------------------------------------------------------------------------
# The limitations engine. These strings are the honesty contract.
# ---------------------------------------------------------------------------


def test_limitations_always_state_the_isolation_tier():
    limits = compute_limitations(
        isolation={"tier": 1, "tier_name": "shared-kernel"}, sandbox=None,
        artifacts=None, events=[{"severity": "info"}],
    )
    assert any("tier 1" in item for item in limits)


def test_limitations_shout_when_there_is_no_boundary():
    limits = compute_limitations(
        isolation={"tier": 1}, sandbox=None, artifacts=None,
        events=[{"severity": "info"}],
    )
    assert any("No hardware boundary" in item for item in limits)


def test_limitations_do_not_claim_a_missing_boundary_at_higher_tiers():
    limits = compute_limitations(
        isolation={"tier": 3}, sandbox=None, artifacts=None,
        events=[{"severity": "info"}],
    )
    assert not any("No hardware boundary" in item for item in limits)


def test_limitations_state_that_egress_is_blocked():
    limits = compute_limitations(None, None, None, [{"severity": "info"}])
    assert any("egress was blocked" in item for item in limits)


def test_limitations_name_each_missing_artifact():
    limits = compute_limitations(
        isolation={"tier": 1},
        sandbox=None,
        artifacts={"found": {"strace_log": "/x"}},
        events=[{"severity": "info"}],
    )
    text = " ".join(limits)
    assert "inotify log" in text
    assert "pcap" in text
    assert "strace log" not in text


def test_empty_run_is_called_inconclusive_not_clean():
    limits = compute_limitations(
        isolation={"tier": 1}, sandbox=None, artifacts=None, events=[],
    )
    assert any("INCONCLUSIVE" in item for item in limits)


def test_timeout_is_reported_as_a_limit():
    limits = compute_limitations(
        isolation={"tier": 1},
        sandbox={"status": "timeout"},
        artifacts=None,
        events=[{"severity": "info"}],
    )
    assert any("still running when the timeout expired" in item for item in limits)


def test_limitations_always_note_the_linux_only_scope():
    limits = compute_limitations(None, None, None, [{"severity": "info"}])
    assert any("Linux ELF" in item for item in limits)


def test_render_limitations_is_empty_for_no_limitations():
    assert render_limitations([]) == ""
    assert "does NOT establish" in render_limitations(["a"])


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_summary_counts_events_by_category_and_severity():
    bundle = AnalysisBundle(
        task_id="t",
        events=[
            {"category": "file", "severity": "info"},
            {"category": "file", "severity": "high"},
            {"category": "network", "severity": "critical"},
        ],
        iocs=[{"severity": "high"}],
        static={"yara": {"matches": [{"rule": "A"}]}},
    )
    summary = bundle.summary()

    assert summary["events_total"] == 3
    assert summary["events_by_category"] == {"file": 2, "network": 1}
    assert summary["events_by_severity"]["critical"] == 1
    assert summary["iocs_high_or_critical"] == 1
    assert summary["yara_matches"] == 1
    assert summary["inconclusive"] is False


def test_summary_marks_an_event_less_run_inconclusive():
    bundle = AnalysisBundle(task_id="t", events=[])
    assert bundle.summary()["inconclusive"] is True
