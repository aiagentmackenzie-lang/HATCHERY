"""Hostile input is incomplete work, not a traceback (D39).

The corpus in ``hostile_corpus.py`` is one lie per fixture. Each row is driven
through the *real* stage that consumes those bytes, and the assertion is
threefold — **named** (the stage records why), **bounded** (children, bytes,
depth and time stay inside the documented caps) and **no escape** (no exception
reaches the caller except a documented parser error).

The last group drives a representative subset through the installed CLI, because
a guard that only works when a test calls the parser directly is not the claim.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hostile_corpus import (
    MAX_CHILDREN,
    MAX_DEPTH,
    MAX_ENTRY_BYTES,
    MAX_TOTAL_BYTES,
    corpus,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = corpus()
FIXTURE_NAMES = sorted(CORPUS)


def _run_delivery(path: Path, tmp_path: Path):
    from engine.intake.delivery import extract_delivery

    out = tmp_path / "extracted"
    result = extract_delivery(path, out)
    return result, out


def _delivery_reasons(result) -> str:
    return " | ".join(
        [*result.errors, *(entry["reason"] for entry in result.unsupported), *result.flags]
    )


def _assert_bounded_delivery(result, out: Path) -> None:
    assert len(result.children) <= MAX_CHILDREN
    assert sum(child.size for child in result.children) <= MAX_TOTAL_BYTES
    resolved_out = out.resolve()
    for child in result.children:
        assert child.depth <= MAX_DEPTH
        assert child.path.resolve().is_relative_to(resolved_out), child.name
        assert ".." not in child.path.parts
    assert sum(
        path.stat().st_size for path in resolved_out.rglob("*") if path.is_file()
    ) <= MAX_TOTAL_BYTES


def test_the_corpus_is_deterministic_and_large_enough():
    assert len(CORPUS) >= 20, "the slice promised a corpus of ~20 fixtures"
    again = corpus()
    assert set(again) == set(CORPUS)
    for name, fixture in CORPUS.items():
        assert again[name].data == fixture.data, f"{name} is not deterministic"
        assert fixture.lie and fixture.stage


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_each_fixture_is_named_bounded_and_fast(name: str, tmp_path: Path):
    fixture = CORPUS[name]
    path = tmp_path / name
    path.write_bytes(fixture.data)

    started = time.monotonic()
    if fixture.stage == "delivery":
        result, out = _run_delivery(path, tmp_path)
        reasons = _delivery_reasons(result)
        _assert_bounded_delivery(result, out)
    elif fixture.stage == "ole":
        from engine.intake.ole import CompoundFile, OleError

        try:
            cfb = CompoundFile(fixture.data)
        except OleError as exc:
            reasons = str(exc)
        else:
            reasons = ""
            assert len(cfb.streams) <= 4096
    elif fixture.stage == "rtf":
        from engine.intake.rtf import RtfError, parse_rtf

        options = fixture.options or {"max_object_bytes": MAX_ENTRY_BYTES}
        try:
            document = parse_rtf(fixture.data, max_objects=64, **options)
        except RtfError as exc:
            reasons = str(exc)
        else:
            reasons = ""
            assert len(document.objects) <= 64
    elif fixture.stage == "pe":
        from engine.intake.pe_analyzer import PEAnalyzer

        result = PEAnalyzer().analyze(path)
        reasons = result.error or ""
        assert len(result.sections) <= 96
    elif fixture.stage == "elf":
        from engine.intake.elf_analyzer import ELFAnalyzer

        result = ELFAnalyzer().analyze(path)
        reasons = result.error or ""
        assert len(result.sections) <= 4096
    elif fixture.stage == "strace":
        from engine.monitor.strace_parser import StraceParser

        result = StraceParser().parse_file(path)
        reasons = " | ".join(result.errors)
        assert result.parsed_events <= result.total_lines
    elif fixture.stage == "json":
        from engine.bundle import BundleReadError, load_bundle

        run = tmp_path / "run"
        run.mkdir()
        (run / "analysis.json").write_bytes(fixture.data)
        with pytest.raises(BundleReadError) as caught:
            load_bundle(run)
        reasons = str(caught.value)
    else:  # pragma: no cover - the corpus declares its stages
        raise AssertionError(f"{name} declares unknown stage {fixture.stage!r}")

    elapsed = time.monotonic() - started
    assert elapsed < 5.0, f"{name} took {elapsed:.1f}s; hostile input must be bounded"
    if fixture.expect:
        lowered = reasons.lower()
        assert any(needle.lower() in lowered for needle in fixture.expect), (
            f"{name}: nothing named the failure; recorded: {reasons!r}"
        )


def test_the_documented_parser_errors_are_the_only_ones(tmp_path: Path):
    """Every OLE/RTF fixture either parses or raises the module's own error."""

    from engine.intake.ole import CompoundFile, OleError
    from engine.intake.rtf import RtfError, parse_rtf

    for fixture in CORPUS.values():
        if fixture.stage == "ole":
            try:
                CompoundFile(fixture.data)
            except OleError:
                pass
            except Exception as exc:  # noqa: BLE001 - the point of the test
                pytest.fail(f"{fixture.name} raised {type(exc).__name__}: {exc}")
        elif fixture.stage == "rtf":
            try:
                parse_rtf(fixture.data, max_object_bytes=1024)
            except RtfError:
                pass
            except Exception as exc:  # noqa: BLE001 - the point of the test
                pytest.fail(f"{fixture.name} raised {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# The real CLI — a guard that only works in-process is not the claim
# ---------------------------------------------------------------------------

CLI_ROWS = [
    "zip_ratio_bomb",
    "zip_declared_size_lie",
    "tar_declared_size_lie",
    "pe_lfanew_past_eof",
    "ole_impossible_sector_shift",
    "rtf_bin_past_end",
]


def _cli_env(tmp_path: Path) -> dict[str, str]:
    import os

    env = dict(os.environ)
    env["HATCHERY_RESULTS_ROOT"] = str(tmp_path / "results")
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "samples")
    env.pop("HATCHERY_SAMPLE_KEY", None)
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    return env


@pytest.mark.parametrize("name", CLI_ROWS)
def test_the_cli_reports_a_hostile_sample_without_a_traceback(name: str, tmp_path: Path):
    fixture = CORPUS[name]
    path = tmp_path / name
    path.write_bytes(fixture.data)
    run_dir = tmp_path / "run"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "engine.cli",
            "submit",
            str(path),
            "--no-sandbox",
            "-o",
            str(run_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        env=_cli_env(tmp_path),
    )

    assert result.returncode in (0, 1, 2), result.stdout[-2000:] + result.stderr[-2000:]
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr

    bundle = run_dir / "bundle" / "analysis.json"
    assert bundle.is_file(), "a hostile sample must still produce a bundle"
    assert (run_dir / "manifest.json").is_file(), "and the run must still be sealed"

    analysis = json.loads(bundle.read_text(encoding="utf-8"))
    recorded = json.dumps(
        {
            "errors": analysis.get("errors"),
            "delivery": analysis.get("static", {}).get("delivery"),
            "pe": analysis.get("static", {}).get("pe"),
        }
    )
    assert any(
        needle.lower() in recorded.lower() for needle in fixture.expect
    ), f"{name}: the bundle does not name the failure; recorded {recorded[:800]}"


def test_a_hostile_document_does_not_stop_triage(tmp_path: Path):
    """A run directory is untrusted input too: a deep bundle is exit 1, not a crash."""

    run = tmp_path / "results" / "run"
    (run / "bundle").mkdir(parents=True)
    (run / "bundle" / "analysis.json").write_bytes(CORPUS["json_deep_nesting"].data)
    (run / "bundle" / "events.jsonl").write_text("", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "engine.cli", "triage", str(run)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env=_cli_env(tmp_path),
    )

    assert result.returncode == 1, result.stdout[-2000:] + result.stderr[-2000:]
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
    assert "not readable" in (result.stdout + result.stderr)
