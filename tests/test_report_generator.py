"""Tests for HATCHERY report generator."""

import json
import pytest
from pathlib import Path

from engine.export.report import ReportGenerator


class TestReportGenerator:
    """Test analysis report generation."""

    def setup_method(self):
        self.gen = ReportGenerator()

    def test_generate_markdown_basic(self):
        """Test generating a basic Markdown report."""
        report = self.gen.generate_markdown(
            sample_name="suspicious.exe",
            sample_hash={"md5": "abc123", "sha1": "def456", "sha256": "ghi789", "file_size": 1024},
        )

        assert "# HATCHERY Analysis Report" in report
        assert "suspicious.exe" in report
        assert "abc123" in report
        assert "def456" in report
        assert "ghi789" in report
        assert "File Hashes" in report
        assert "Known Limitations" in report

    def test_generate_markdown_with_yara(self):
        """Test generating a Markdown report with YARA matches."""
        static_results = {
            "yara": {
                "matches": [
                    {
                        "rule": "HATCHERY_SandboxEvasion_Sleep",
                        "meta": {"description": "Sleep bomb detected"},
                    }
                ]
            },
            "capa": {"capabilities": []},
        }

        report = self.gen.generate_markdown(
            sample_name="malware.bin",
            sample_hash={"md5": "a", "sha1": "b", "sha256": "c", "file_size": 0},
            static_results=static_results,
        )

        assert "YARA Matches" in report
        assert "HATCHERY_SandboxEvasion_Sleep" in report

    def test_generate_markdown_with_iocs(self):
        """Test generating a Markdown report with IOCs."""
        ioc_report = {
            "summary": {"ip": 2, "domain": 1, "url": 1},
            "iocs": [
                {"type": "ip", "value": "1.2.3.4", "severity": "high", "context": "C2 connection"},
                {"type": "domain", "value": "evil.com", "severity": "high", "context": "C2 domain"},
                {"type": "url", "value": "http://evil.com/p", "severity": "critical", "context": "Payload download"},
            ],
        }

        report = self.gen.generate_markdown(
            sample_name="test.bin",
            sample_hash={"md5": "x", "sha1": "y", "sha256": "z", "file_size": 100},
            ioc_report=ioc_report,
        )

        assert "Indicators of Compromise" in report
        assert "1.2.3.4" in report
        assert "evil.com" in report
        assert "CRITICAL" in report

    def test_generate_json_report(self):
        """Test generating a JSON report."""
        report_json = self.gen.generate_json(
            sample_name="test.bin",
            sample_hash={"md5": "x", "sha1": "y", "sha256": "z", "file_size": 100},
        )

        data = json.loads(report_json)
        assert data["generator"] == "HATCHERY"
        assert data["version"] == "0.1.0"
        assert data["sample"]["name"] == "test.bin"
        assert data["limitations"] is not None

    def test_generate_json_with_static(self):
        """Test generating JSON with static analysis results."""
        static_results = {
            "yara": {"matches": []},
            "capa": {"capabilities": []},
        }

        report_json = self.gen.generate_json(
            sample_name="test.bin",
            sample_hash={"md5": "x", "sha1": "y", "sha256": "z", "file_size": 100},
            static_results=static_results,
        )

        data = json.loads(report_json)
        assert data["static_analysis"] is not None

    def test_write_report(self, tmp_path):
        """Test writing reports to files."""
        output_dir = self.gen.write_report(
            output_dir=tmp_path,
            sample_name="test.bin",
            sample_hash={"md5": "x", "sha1": "y", "sha256": "z", "file_size": 100},
        )

        assert (tmp_path / "report.md").exists()
        assert (tmp_path / "report.json").exists()

        md_content = (tmp_path / "report.md").read_text()
        assert "HATCHERY" in md_content

        json_data = json.loads((tmp_path / "report.json").read_text())
        assert json_data["sample"]["name"] == "test.bin"

    def test_write_report_creates_directory(self, tmp_path):
        """Test that write_report creates the output directory."""
        output_dir = tmp_path / "nested" / "dir"
        result = self.gen.write_report(
            output_dir=output_dir,
            sample_name="test.bin",
            sample_hash={"md5": "x", "sha1": "y", "sha256": "z", "file_size": 100},
        )

        assert output_dir.exists()
        assert (output_dir / "report.md").exists()
        assert (output_dir / "report.json").exists()

    def test_generate_markdown_with_sandbox(self):
        """Test generating Markdown with sandbox results."""
        sandbox_results = {
            "status": "completed",
            "duration_seconds": 45.2,
            "exit_code": 0,
            "strace": {
                "parsed_events": 150,
                "network_connections": [
                    {"ip": "1.2.3.4", "port": 443, "pid": 100},
                ],
                "process_operations": [
                    {"path": "/bin/sh", "pid": 100},
                ],
            },
        }

        report = self.gen.generate_markdown(
            sample_name="test.bin",
            sample_hash={"md5": "x", "sha1": "y", "sha256": "z", "file_size": 100},
            sandbox_results=sandbox_results,
        )

        assert "Behavioral Analysis" in report
        assert "45.2" in report
        assert "Network Connections" in report
        assert "1.2.3.4" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])