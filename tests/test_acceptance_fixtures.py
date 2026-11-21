"""Acceptance fixture tests: integrity and known outcomes.

These tests are intentionally runnable from a clean checkout with no Docker,
no network and no capa ruleset. Where today's behaviour is a recorded defect,
the test is marked ``xfail(strict=True)`` and names the owning slice: when the
slice is fixed the test fails loudly until the manifest and master plan are
updated, so the baseline cannot drift silently.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from engine.intake.elf_analyzer import ELFAnalyzer
from engine.intake.pe_analyzer import PEAnalyzer
from engine.intake.uploader import SampleUploader
from engine.monitor.file_watcher import FileWatcher
from engine.monitor.network_capture import NetworkCapture
from engine.monitor.strace_parser import StraceParser
from engine.static.capa_scanner import CapaScanner
from engine.static.yara_scanner import YARAScanner

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "manifest.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
FIXTURES = {entry["id"]: entry for entry in MANIFEST["fixtures"]}


def fixture_path(fixture_id: str) -> Path:
    return REPO_ROOT / FIXTURES[fixture_id]["path"]


@pytest.fixture(scope="module")
def yara_scanner() -> YARAScanner:
    scanner = YARAScanner()
    scanner.compile_rules()
    return scanner


class TestFixtureIntegrity:
    @pytest.mark.parametrize("fixture_id", sorted(FIXTURES))
    def test_file_matches_manifest(self, fixture_id: str) -> None:
        path = fixture_path(fixture_id)
        assert path.exists(), f"{fixture_id} is missing from the checkout"
        data = path.read_bytes()
        assert len(data) == FIXTURES[fixture_id]["size"]
        assert hashlib.sha256(data).hexdigest() == FIXTURES[fixture_id]["sha256"]


class TestStaticExpectations:
    def test_eicar_matches_expected_rule(self, yara_scanner: YARAScanner) -> None:
        result = yara_scanner.scan(fixture_path("eicar"))
        assert result.error is None
        assert result.rules_loaded > 0, "scanning must have rules loaded"
        assert [m.rule for m in result.matches] == ["HATCHERY_EICAR_TestFile"]

    def test_negative_control_runs_and_finds_nothing(self, yara_scanner: YARAScanner) -> None:
        result = yara_scanner.scan(fixture_path("negative_text"))
        assert result.error is None
        assert result.rules_loaded > 0
        assert result.matches == []

    @pytest.mark.xfail(
        strict=True,
        reason="every PE matches the MZ-header rule and any PE with <=2 "
               "sections matches the generic-packing rule",
    )
    def test_benign_pe_has_no_unsupported_matches(self, yara_scanner: YARAScanner) -> None:
        result = yara_scanner.scan(fixture_path("benign_pe"))
        assert [m.rule for m in result.matches] == []

    def test_benign_pe_structure(self) -> None:
        result = PEAnalyzer().analyze(fixture_path("benign_pe"))
        assert result.is_valid_pe, result.error
        assert result.machine_type == "x64 (AMD64)"
        assert result.subsystem.startswith("Windows CUI")

    def test_benign_elf_fixture_is_independently_valid(self) -> None:
        from elftools.elf.elffile import ELFFile

        with fixture_path("benign_elf").open("rb") as handle:
            elf = ELFFile(handle)
            assert elf.header.e_machine in (62, "EM_X86_64")
            assert elf.header.e_type in (2, "ET_EXEC")

    def test_uploader_classifies_formats_by_magic(self, tmp_path: Path) -> None:
        uploader = SampleUploader(samples_dir=tmp_path / "samples")
        assert uploader.upload(fixture_path("benign_pe")).file_type == "PE"
        assert uploader.upload(fixture_path("benign_elf")).file_type == "ELF"

    def test_capa_reports_status_rather_than_silent_zero(self) -> None:
        """A detector that could not run must not look like a clean result."""
        result = CapaScanner().scan(fixture_path("benign_pe"))
        if result.is_available:
            assert result.error is None
        else:
            assert result.error, "unavailable capa must preserve a reason"
            assert result.capabilities == []

    def test_packer_analysis_is_explicitly_inapplicable_to_elf(self) -> None:
        from engine.static.packer_detect import PackerDetector

        result = PackerDetector().detect(fixture_path("benign_elf"))
        assert result.error, "non-PE input must produce an explicit error, not a clean result"


class TestReplayExpectations:
    def test_timestamp_first_trace(self) -> None:
        expected = FIXTURES["trace_timestamp"]["expected"]["parse"]
        result = StraceParser().parse_file(fixture_path("trace_timestamp"))
        assert result.parsed_events == expected["parsed_events"]
        assert len(result.network_connections) == expected["network_connections"]
        assert {str(k): v for k, v in result.process_tree.items()} == expected["process_tree"]

    def test_file_event_log(self) -> None:
        expected = FIXTURES["file_events"]["expected"]["parse"]
        result = FileWatcher().parse_log(fixture_path("file_events"))
        assert result.total_events == expected["total_events"]
        assert len(result.created_files) == expected["created_files"]
        assert len(result.modified_files) == expected["modified_files"]
        assert len(result.deleted_files) == expected["deleted_files"]

    def test_one_packet_capture(self) -> None:
        import shutil

        if shutil.which("tshark") is None:
            pytest.skip("tshark not installed")
        expected = FIXTURES["pcap_one_packet"]["expected"]["parse"]
        result = NetworkCapture().analyze_pcap(fixture_path("pcap_one_packet"))
        assert result.total_packets == expected["total_packets"]
        assert len(result.connections) == expected["connections"]

    def test_empty_capture_is_a_zero_not_a_failure(self) -> None:
        import shutil

        if shutil.which("tshark") is None:
            pytest.skip("tshark not installed")
        result = NetworkCapture().analyze_pcap(fixture_path("pcap_empty"))
        assert result.total_packets == 0

    @pytest.mark.xfail(
        strict=True,
        reason="network_capture swallows tshark failures, so an unreadable "
               "capture is indistinguishable from an empty one",
    )
    def test_malformed_capture_is_reported(self) -> None:
        import shutil

        if shutil.which("tshark") is None:
            pytest.skip("tshark not installed")
        result = NetworkCapture().analyze_pcap(fixture_path("pcap_malformed"))
        assert result.errors, "unreadable PCAP must surface an error"

    def test_pid_first_trace_parses(self) -> None:
        expected = FIXTURES["trace_pid_first"]["expected"]["parse"]
        result = StraceParser().parse_file(fixture_path("trace_pid_first"))
        assert result.parsed_events == expected["parsed_events"]
        assert {str(k): v for k, v in result.process_tree.items()} == expected["process_tree"]

    @pytest.mark.xfail(
        strict=True,
        reason="ELFAnalyzer formats pyelftools enum strings with :x",
    )
    def test_elf_analyzer_parses_valid_elf(self) -> None:
        result = ELFAnalyzer().analyze(fixture_path("benign_elf"))
        assert result.is_valid_elf, result.error
