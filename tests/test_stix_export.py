"""Tests for HATCHERY STIX 2.1 export."""

import json
import pytest

from engine.export.stix import STIXExporter, _stix_id


class TestSTIXExporter:
    """Test STIX 2.1 bundle generation from IOC reports."""

    def setup_method(self):
        self.exporter = STIXExporter()

    def test_export_empty_iocs(self):
        """Test exporting an empty IOC report."""
        report = {"iocs": []}
        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        assert data["type"] == "bundle"
        # Should have at least the identity object
        assert len(data["objects"]) >= 1
        assert data["objects"][0]["type"] == "identity"

    def test_export_ip_ioc(self):
        """Test exporting an IP address IOC."""
        report = {
            "iocs": [
                {
                    "type": "ip",
                    "value": "185.220.101.34",
                    "source": "static",
                    "severity": "high",
                    "context": "C2 server",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        # Should have identity + ipv4-addr object + indicator
        assert data["type"] == "bundle"
        types = [obj["type"] for obj in data["objects"]]
        assert "ipv4-addr" in types
        assert "indicator" in types

        # Find the IP object
        ip_obj = next(obj for obj in data["objects"] if obj["type"] == "ipv4-addr")
        assert ip_obj["value"] == "185.220.101.34"

    def test_export_domain_ioc(self):
        """Test exporting a domain IOC."""
        report = {
            "iocs": [
                {
                    "type": "domain",
                    "value": "evil.attacker.com",
                    "source": "static",
                    "severity": "medium",
                    "context": "C2 domain",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        domain_obj = next(obj for obj in data["objects"] if obj["type"] == "domain-name")
        assert domain_obj["value"] == "evil.attacker.com"

    def test_export_url_ioc(self):
        """Test exporting a URL IOC."""
        report = {
            "iocs": [
                {
                    "type": "url",
                    "value": "http://evil.com/payload",
                    "source": "static",
                    "severity": "high",
                    "context": "Download URL",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        url_obj = next(obj for obj in data["objects"] if obj["type"] == "url")
        assert url_obj["value"] == "http://evil.com/payload"

    def test_export_email_ioc(self):
        """Test exporting an email IOC."""
        report = {
            "iocs": [
                {
                    "type": "email",
                    "value": "exfil@attacker.com",
                    "source": "static",
                    "severity": "medium",
                    "context": "Exfil email",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        email_obj = next(obj for obj in data["objects"] if obj["type"] == "email-addr")
        assert email_obj["value"] == "exfil@attacker.com"

    def test_export_registry_key_ioc(self):
        """Test exporting a registry key IOC."""
        report = {
            "iocs": [
                {
                    "type": "registry_key",
                    "value": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    "source": "static",
                    "severity": "medium",
                    "context": "Persistence key",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        reg_obj = next(obj for obj in data["objects"] if obj["type"] == "windows-registry-key")
        assert "CurrentVersion" in reg_obj["key"]

    def test_export_hash_ioc(self):
        """Test exporting a file hash IOC (SHA256)."""
        sha256 = "a" * 64
        report = {
            "iocs": [
                {
                    "type": "hash",
                    "value": sha256,
                    "source": "file_watch",
                    "severity": "high",
                    "context": "Dropped file",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        file_obj = next(obj for obj in data["objects"] if obj["type"] == "file")
        assert file_obj["hashes"]["SHA-256"] == sha256

    def test_high_severity_creates_indicator(self):
        """Test that high/critical IOCs generate STIX indicators."""
        report = {
            "iocs": [
                {
                    "type": "ip",
                    "value": "1.2.3.4",
                    "source": "network",
                    "severity": "high",
                    "context": "C2 IP",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        indicator_objs = [obj for obj in data["objects"] if obj["type"] == "indicator"]
        assert len(indicator_objs) == 1
        assert "pattern" in indicator_objs[0]
        assert indicator_objs[0]["pattern_type"] == "stix"

    def test_low_severity_no_indicator(self):
        """Test that low-severity IOCs don't generate indicators."""
        report = {
            "iocs": [
                {
                    "type": "file_path",
                    "value": "/tmp/test",
                    "source": "strace",
                    "severity": "low",
                    "context": "File opened",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        indicator_objs = [obj for obj in data["objects"] if obj["type"] == "indicator"]
        assert len(indicator_objs) == 0

    def test_stix_id_deterministic(self):
        """Test that STIX IDs are deterministic (same input → same output)."""
        id1 = _stix_id("ipv4-addr", "1.2.3.4")
        id2 = _stix_id("ipv4-addr", "1.2.3.4")
        assert id1 == id2

    def test_stix_id_different_values(self):
        """Test that different values produce different STIX IDs."""
        id1 = _stix_id("ipv4-addr", "1.2.3.4")
        id2 = _stix_id("ipv4-addr", "5.6.7.8")
        assert id1 != id2

    def test_stix_id_format(self):
        """Test that STIX IDs have correct format."""
        stix_id = _stix_id("ipv4-addr", "1.2.3.4")
        assert stix_id.startswith("ipv4-addr--")

    def test_export_multiple_ioc_types(self):
        """Test exporting multiple IOC types in one report."""
        report = {
            "iocs": [
                {"type": "ip", "value": "1.2.3.4", "source": "static", "severity": "high", "context": "IP"},
                {"type": "domain", "value": "evil.com", "source": "static", "severity": "medium", "context": "Domain"},
                {"type": "url", "value": "http://evil.com/p", "source": "static", "severity": "high", "context": "URL"},
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        types = [obj["type"] for obj in data["objects"]]
        assert "ipv4-addr" in types
        assert "domain-name" in types
        assert "url" in types

    def test_c2_beacon_ioc_maps_to_ip(self):
        """Test that C2 beacon IOCs map to ipv4-addr STIX type."""
        report = {
            "iocs": [
                {
                    "type": "c2_beacon",
                    "value": "1.2.3.4:443",
                    "source": "network",
                    "severity": "critical",
                    "context": "C2 beacon detected",
                }
            ]
        }

        result = self.exporter.export_iocs(report)
        data = json.loads(result)

        # C2 beacon maps to ipv4-addr type
        ip_objs = [obj for obj in data["objects"] if obj["type"] == "ipv4-addr"]
        assert len(ip_objs) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])