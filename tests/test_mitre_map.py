"""Tests for HATCHERY MITRE ATT&CK mapping."""

import pytest

from engine.export.mitre_map import MITREMapper, ATTCKTechnique, MITREMappingResult


class TestMITREMapper:
    """Test MITRE ATT&CK technique mapping."""

    def setup_method(self):
        self.mapper = MITREMapper()

    def test_empty_mapping(self):
        """Test mapping with no data."""
        result = self.mapper.map_all()
        assert result.technique_count == 0
        assert result.techniques == []

    def test_map_strace_data(self):
        """Test mapping strace behavioral data to ATT&CK."""
        strace_data = {
            "events": [
                {"syscall": "execve", "args": '"/bin/sh"', "category": "process"},
                {"syscall": "connect", "args": "..."},
                {"syscall": "openat", "args": "..."},
            ]
        }

        result = self.mapper.map_all(strace_data=strace_data)
        assert result.technique_count >= 1

        # execve should map to Command and Scripting Interpreter
        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1059" in technique_ids  # Command and Scripting Interpreter

    def test_map_file_watch_data(self):
        """Test mapping file watch events to ATT&CK."""
        file_watch_data = {
            "events": [
                {"path": "/home/user/.bashrc", "event_type": "modify"},
                {"path": "/etc/cron.d/backdoor", "event_type": "create"},
            ]
        }

        result = self.mapper.map_all(file_watch_data=file_watch_data)
        assert result.technique_count >= 1

        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1546.004" in technique_ids  # Unix Shell Config Modification

    def test_map_yara_data(self):
        """Test mapping YARA matches to ATT&CK."""
        yara_data = {
            "matches": [
                {
                    "rule": "HATCHERY_SandboxEvasion_Sleep",
                    "tags": ["sandbox_evasion"],
                    "meta": {"description": "Sleep bomb detected"},
                }
            ]
        }

        result = self.mapper.map_all(yara_data=yara_data)
        assert result.technique_count >= 1

        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1497" in technique_ids  # Virtualization/Sandbox Evasion

    def test_map_capa_data(self):
        """Test mapping capa capabilities to ATT&CK."""
        capa_data = {
            "attack_techniques": [
                {
                    "tactic": "Defense Evasion",
                    "id": "T1027",
                    "technique": "Obfuscated Files or Information",
                    "subtechnique": "",
                }
            ]
        }

        result = self.mapper.map_all(capa_data=capa_data)
        assert result.technique_count >= 1

        techniques = {t.technique_id: t for t in result.techniques}
        assert "T1027" in techniques
        assert techniques["T1027"].source == "capa"

    def test_deduplication_of_techniques(self):
        """Test that duplicate techniques are deduplicated."""
        # execve appears in both strace events
        strace_data = {
            "events": [
                {"syscall": "execve"},
                {"syscall": "execve"},
            ]
        }

        result = self.mapper.map_all(strace_data=strace_data)
        # Should have only one T1059 mapping, not two
        technique_ids = [t.technique_id for t in result.techniques]
        assert technique_ids.count("T1059") == 1

    def test_map_clone_as_process_injection(self):
        """Test that clone syscall maps to Process Injection."""
        strace_data = {
            "events": [
                {"syscall": "clone"},
            ]
        }

        result = self.mapper.map_all(strace_data=strace_data)
        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1055" in technique_ids  # Process Injection

    def test_map_connect_as_c2(self):
        """Test that connect syscall maps to C2 Application Layer Protocol."""
        strace_data = {
            "events": [
                {"syscall": "connect"},
            ]
        }

        result = self.mapper.map_all(strace_data=strace_data)
        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1071" in technique_ids  # Application Layer Protocol

    def test_map_mprotect_as_process_injection(self):
        """Test that mprotect syscall maps to Process Injection."""
        strace_data = {
            "events": [
                {"syscall": "mprotect"},
            ]
        }

        result = self.mapper.map_all(strace_data=strace_data)
        technique_ids = [t.technique_id for t in result.techniques]
        assert "T1055" in technique_ids  # Process Injection

    def test_attck_technique_to_dict(self):
        """Test ATTCKTechnique serialization."""
        tech = ATTCKTechnique(
            tactic="Execution",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            subtechnique_id="T1059.001",
            subtechnique_name="PowerShell",
            source="yara",
            confidence="high",
        )
        d = tech.to_dict()
        assert d["tactic"] == "Execution"
        assert d["technique_id"] == "T1059"
        assert d["technique_name"] == "Command and Scripting Interpreter"
        assert d["subtechnique_id"] == "T1059.001"
        assert d["source"] == "yara"
        assert d["confidence"] == "high"

    def test_mapping_result_to_dict(self):
        """Test MITREMappingResult serialization."""
        result = MITREMappingResult(
            techniques=[
                ATTCKTechnique(
                    tactic="Persistence",
                    technique_id="T1546.004",
                    technique_name="Unix Shell Configuration Modification",
                    source="file_watch",
                )
            ],
            tactics_covered=["Persistence"],
            technique_count=1,
        )
        d = result.to_dict()
        assert d["technique_count"] == 1
        assert "Persistence" in d["tactics_covered"]

    def test_comprehensive_mapping(self):
        """Test mapping from multiple data sources at once."""
        strace_data = {
            "events": [
                {"syscall": "execve"},
                {"syscall": "connect"},
            ]
        }
        yara_data = {
            "matches": [
                {"rule": "HATCHERY_SandboxEvasion_Sleep", "tags": ["sandbox_evasion"], "meta": {}},
            ]
        }

        result = self.mapper.map_all(strace_data=strace_data, yara_data=yara_data)
        assert result.technique_count >= 2

        tactics = set(result.tactics_covered)
        assert "Execution" in tactics or "Command and Control" in tactics or "Defense Evasion" in tactics


if __name__ == "__main__":
    pytest.main([__file__, "-v"])