"""Runner config/command builders and the analyze orchestrator."""

from __future__ import annotations

import json
from pathlib import Path

from engine.emulate import runner
from engine.emulate.report import EMULATOR_VERSION

FIXTURE = Path(__file__).parent / "fixtures" / "speakeasy-report-real.json"


def test_config_caps_are_data_not_flags() -> None:
    config = runner.speakeasy_config(timeout=42, max_api_count=123, max_instructions=99)
    assert config["timeout"] == 42.0
    assert config["max_api_count"] == 123
    assert config["max_instructions"] == 99
    assert config["snapshot_memory_regions"] is True


def test_args_pass_argv_list_never_a_shell_string() -> None:
    args = runner.speakeasy_args("/hatchery/sample/a b; rm -rf.exe")
    assert "-t" in args
    assert "/hatchery/sample/a b; rm -rf.exe" in args
    assert "--no-mp" in args
    assert args[-1] == "--no-mp"


def test_raw_mode_defaults_arch_to_x86() -> None:
    args = runner.speakeasy_args("/s.bin", raw=True)
    assert "--raw" in args
    assert args[args.index("--arch") + 1] == "x86"


def test_raw_mode_respects_explicit_arch() -> None:
    args = runner.speakeasy_args("/s.bin", raw=True, arch="x64")
    assert args[args.index("--arch") + 1] == "x64"


def test_unavailable_section_is_declared() -> None:
    section = runner.unavailable_section("no docker")
    assert section["available"] is False
    assert section["status"] == "unavailable"
    assert section["reason"] == "no docker"
    assert section["events_written"] == 0


def test_analyze_without_capa_still_extracts_config() -> None:
    raw = json.loads(FIXTURE.read_text())
    section, events = runner.analyze(raw, run_capa=False)
    assert section["emulator_version"] == EMULATOR_VERSION
    assert section["schema_hash"]
    assert section["config"]["network_endpoints"]
    assert len(events) == 5  # 4 API events + 1 net_http event
    assert all(row["source"] == "emulation" for row in events)


def test_flags_signal_config_and_network() -> None:
    raw = json.loads(FIXTURE.read_text())
    section, _ = runner.analyze(raw, run_capa=False)
    assert "emulation" in section["flags"]
    assert "emulation-config" in section["flags"]
    assert "emulation-network" in section["flags"]


def test_unavailable_section_has_its_flag() -> None:
    assert runner.unavailable_section("x")["flags"] == ["emulation-unavailable"]
