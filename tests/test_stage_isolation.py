"""A parser bug is that stage's named failure, and a defect outside every stage
is exit 6 — never a traceback (D39).

These tests force each in-process parser to raise and then assert the run's own
artifact: the bundle exists, its ``errors`` names the stage and the exception,
and the manifest still verifies. The last row covers the backstop for a defect
in the pipeline driver: one line, exit 6, and no bundle claimed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.guard import DOCUMENTED, guarded
from engine.intake.ole import OleError

REPO_ROOT = Path(__file__).resolve().parent.parent
PE = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "benign_pe.exe"
ELF = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "hello.elf"
ZIP_CHILD = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "negative.txt"

SUBMIT_DEFAULTS: dict = {
    "from_store": None,
    "sample_hint": None,
    "timeout": 5,
    "no_sandbox": True,
    "emulate": False,
    "emulate_timeout": 5,
    "emulate_raw": False,
    "no_emulate_capa": True,
    "allow_host_emulation": False,
    "triage_enabled": False,
    "triage_model": None,
    "allow_remote_model": False,
    "enqueue": False,
    "queue_db": None,
    "job_id": None,
    "requeue": False,
}


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HATCHERY_RESULTS_ROOT", str(tmp_path / "results"))
    monkeypatch.setenv("HATCHERY_SAMPLE_STORE", str(tmp_path / "samples"))
    monkeypatch.delenv("HATCHERY_SAMPLE_KEY", raising=False)
    monkeypatch.delenv("HATCHERY_SAMPLE_KEY_FILE", raising=False)
    return tmp_path


def _submit(sample: Path, output: Path, **overrides) -> None:
    """Run the real ``submit`` body in-process (same code path, no subprocess)."""
    from engine.cli import submit

    kwargs = {**SUBMIT_DEFAULTS, "file": sample, "output": output, **overrides}
    submit.callback(**kwargs)


def _analysis(output: Path) -> dict:
    return json.loads(
        (output / "bundle" / "analysis.json").read_text(encoding="utf-8")
    )


def _assert_sealed(output: Path) -> None:
    from engine.results import verify_run

    assert (output / "manifest.json").is_file(), "the run must still be sealed"
    report = verify_run(output, _depth=1)
    assert report["ok"] is True, report


def test_a_pe_analyser_crash_is_named_and_the_run_still_seals(
    isolated: Path, monkeypatch, capsys
):
    from engine.intake.pe_analyzer import PEAnalyzer

    def explode(self, file_path):  # noqa: ANN001 - the signature under test
        raise RuntimeError("pefile tripped over a section table")

    monkeypatch.setattr(PEAnalyzer, "analyze", explode)

    output = isolated / "run"
    _submit(PE, output)

    analysis = _analysis(output)
    assert any(
        "PE analysis: unexpected RuntimeError: pefile tripped over a section table"
        in error
        for error in analysis["errors"]
    ), analysis["errors"]
    assert analysis["static"]["pe"] is None
    assert analysis["sample"]["sha256"], "the rest of the bundle must survive"
    _assert_sealed(output)

    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err


def test_a_yara_parse_crash_names_the_stage_and_keeps_the_bundle(
    isolated: Path, monkeypatch
):
    from engine.static.yara_scanner import YARAScanner

    def explode(self, file_path):  # noqa: ANN001
        raise IndexError("match table out of range")

    monkeypatch.setattr(YARAScanner, "scan", explode)

    output = isolated / "run"
    _submit(PE, output)

    analysis = _analysis(output)
    assert any("YARA scan: unexpected IndexError" in error for error in analysis["errors"])
    assert analysis["static"]["yara"]["rules_loaded"] == 0
    assert "see bundle errors" in (analysis["static"]["yara"]["error"] or "")
    _assert_sealed(output)


def test_a_delivery_crash_is_named_in_the_delivery_section(isolated: Path, monkeypatch):
    from engine.intake import delivery

    def explode(path, output_dir, **kwargs):  # noqa: ANN001
        raise RuntimeError("classifier exploded")

    monkeypatch.setattr(delivery, "extract_delivery", explode)

    output = isolated / "run"
    _submit(PE, output)

    analysis = _analysis(output)
    recorded = analysis["static"]["delivery"]["errors"]
    assert any("delivery intake: unexpected RuntimeError" in error for error in recorded), recorded
    _assert_sealed(output)


def test_a_child_static_failure_is_named_per_child(isolated: Path, monkeypatch):
    import zipfile

    from engine.static.packer_detect import PackerDetector

    def explode(self, file_path):  # noqa: ANN001
        raise RuntimeError("packer heuristic blew up")

    monkeypatch.setattr(PackerDetector, "detect", explode)

    archive = isolated / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("payload.bin", ZIP_CHILD.read_bytes())

    output = isolated / "run"
    _submit(archive, output)

    recorded = _analysis(output)["static"]["delivery"]["errors"]
    assert any("static analysis: unexpected RuntimeError" in error for error in recorded), recorded
    _assert_sealed(output)


def test_a_defect_outside_every_stage_is_exit_6_and_one_line(
    isolated: Path, monkeypatch, capsys
):
    import engine.cli as cli_module

    def explode(*args, **kwargs):  # noqa: ANN001
        raise RuntimeError("the bundle writer is broken")

    monkeypatch.setattr(cli_module, "write_bundle", explode)

    with pytest.raises(SystemExit) as caught:
        _submit(PE, isolated / "run")

    assert caught.value.code == 6
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "internal error (exit 6)" in text
    assert "RuntimeError: the bundle writer is broken" in text
    assert "Traceback" not in text


# ---------------------------------------------------------------------------
# The funnel itself
# ---------------------------------------------------------------------------


def test_guarded_records_the_stage_and_returns_the_fallback(capsys):
    errors: list[str] = []

    def parse():
        raise ValueError("hostile bytes")

    result = guarded("test stage", errors, parse, fallback_factory=dict)

    assert result == {}
    assert errors == ["test stage: unexpected ValueError: hostile bytes"]
    assert "test stage: unexpected ValueError" in capsys.readouterr().out


def test_guarded_returns_the_value_when_nothing_raises():
    errors: list[str] = []
    assert guarded("stage", errors, lambda: 41 + 1) == 42
    assert errors == []


def test_a_documented_parser_error_is_not_flattened():
    errors: list[str] = []

    def parse():
        raise OleError("CFB sector 9 out of range")

    with pytest.raises(OleError):
        guarded("OLE", errors, parse, fallback_factory=dict)
    assert errors == [], "a documented error already has a caller that reports it"
    assert OleError in DOCUMENTED

@pytest.mark.parametrize(
    "module_name,class_name,method,stage,sample",
    [
        ("engine.intake.elf_analyzer", "ELFAnalyzer", "analyze", "ELF analysis", ELF),
        ("engine.intake.strings", "StringExtractor", "extract", "string extraction", PE),
        ("engine.static.packer_detect", "PackerDetector", "detect", "packer detection", PE),
        ("engine.static.capa_scanner", "CapaScanner", "scan", "capa analysis", PE),
    ],
)
def test_every_in_process_parser_names_its_stage(
    module_name: str, class_name: str, method: str, stage: str, sample: Path,
    isolated: Path, monkeypatch,
):
    """One row per parser the sample pipeline runs in-process (D39)."""
    import importlib

    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)

    def explode(self, *args, **kwargs):  # noqa: ANN001
        raise RuntimeError(f"{class_name} lost its mind")

    monkeypatch.setattr(cls, method, explode)

    output = isolated / f"run-{class_name}"
    _submit(sample, output)

    errors = _analysis(output)["errors"]
    assert any(
        f"{stage}: unexpected RuntimeError: {class_name} lost its mind" in error
        for error in errors
    ), errors
    _assert_sealed(output)


def test_a_sandbox_log_parser_crash_keeps_the_sandbox_result(isolated: Path, monkeypatch):
    """The syscall parse is its own stage: a crash must not discard the run."""
    from types import SimpleNamespace

    from engine.cli import _parse_syscall_log
    from engine.monitor.strace_parser import StraceParser

    log = isolated / "strace.log"
    log.write_text("1234  execve(\"/bin/sh\", [\"sh\"], 0x0) = 0\n", encoding="utf-8")

    def explode(self, path):  # noqa: ANN001
        raise ValueError("strace line ate the parser")

    monkeypatch.setattr(StraceParser, "parse_file", explode)

    errors: list[str] = []
    fake = SimpleNamespace(
        gvisor_trace_log=None, strace_log=str(log), gvisor_trace_error=None
    )
    syscall_result, gvisor_result = _parse_syscall_log(fake, errors)

    assert syscall_result is None
    assert gvisor_result is None
    assert errors == ["strace parse: unexpected ValueError: strace line ate the parser"]
