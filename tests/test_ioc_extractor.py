"""Tests for HATCHERY IOC extractor."""

import pytest
from engine.ioc.extractor import IOCExtractor


class TestIOCExtractor:
    """Test IOC extraction from various data sources."""

    def setup_method(self):
        self.extractor = IOCExtractor()

    def test_extract_from_static_strings(self):
        """Test IOC extraction from static string analysis."""
        static_data = {
            "strings": {
                "urls": ["http://evil.com/payload"],
                "ips": ["185.1.2.3"],
                "domains": ["evil.com", "c2.evil.com"],
                "emails": ["exfil@evil.com"],
                "registry_keys": ["HKLM\\SOFTWARE\\Evil"],
            },
            "yara": {"matches": []},
            "capa": {"capabilities": []},
        }

        report = self.extractor.extract(static_data=static_data)

        assert report.total_count >= 5
        assert len(report.get_by_type("url")) == 1
        assert len(report.get_by_type("ip")) == 1
        assert len(report.get_by_type("domain")) == 2
        assert len(report.get_by_type("email")) == 1
        assert len(report.get_by_type("registry_key")) == 1

    def test_extract_from_yara(self):
        """Test IOC extraction from YARA matches."""
        static_data = {
            "strings": {"urls": [], "ips": [], "domains": [], "emails": [], "registry_keys": []},
            "yara": {
                "matches": [
                    {"rule": "HATCHERY_SandboxEvasion_Sleep", "meta": {"description": "Sleep evasion"}},
                    {"rule": "HATCHERY_Packing_UPX", "meta": {"description": "UPX packed"}},
                ]
            },
            "capa": {"capabilities": []},
        }

        report = self.extractor.extract(static_data=static_data)

        assert len(report.get_by_type("yara_match")) == 2

    def test_deduplication(self):
        """Test that duplicate IOCs are deduplicated."""
        static_data = {
            "strings": {
                "urls": ["http://evil.com/payload"],
                "ips": ["1.2.3.4"],
                "domains": [],
                "emails": [],
                "registry_keys": [],
            },
            "yara": {"matches": []},
            "capa": {"capabilities": []},
        }

        network_data = {
            "network_iocs": [
                {"type": "ip", "value": "1.2.3.4", "context": "Connection"},
                {"type": "ip", "value": "1.2.3.4", "context": "Duplicate"},
            ]
        }

        report = self.extractor.extract(static_data=static_data, network_data=network_data)

        # Same IP should appear only once
        ip_iocs = report.get_by_type("ip")
        assert len(ip_iocs) == 1
        assert ip_iocs[0].value == "1.2.3.4"

    def test_empty_data(self):
        """Test extraction with no data."""
        report = self.extractor.extract()
        assert report.total_count == 0

    def test_c2_beacon_severity(self):
        """Test that C2 beacons get critical severity."""
        network_data = {
            "network_iocs": [
                {"type": "c2_beacon", "value": "1.2.3.4:443", "context": "C2 detected"},
            ]
        }

        report = self.extractor.extract(network_data=network_data)
        c2_iocs = report.get_by_type("c2_beacon")
        assert len(c2_iocs) == 1
        assert c2_iocs[0].severity == "critical"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

def test_iocs_come_from_extracted_delivery_children():
    """A payload recovered from a container is the same static source."""
    static_data = {
        "strings": {},
        "yara": {"matches": []},
        "capa": {"capabilities": []},
        "delivery": {
            "format": "zip",
            "children": [
                {
                    "name": "payload.js",
                    "static": {
                        "strings": {
                            "urls": ["http://evil.example/c2"],
                            "ips": [], "domains": [], "emails": [], "registry_keys": [],
                        },
                        "yara": {"matches": [{"rule": "HATCHERY_Test_Rule", "meta": {}}]},
                    },
                }
            ],
        },
    }

    report = IOCExtractor().extract(static_data=static_data)

    urls = report.get_by_type("url")
    assert len(urls) == 1
    assert urls[0].source == "delivery"
    assert "payload.js" in urls[0].context
    assert report.get_by_type("yara_match")


def test_extract_from_emulation_preserves_source():
    emulation = {
        "iocs": [
            {"type": "domain", "value": "c2.example", "source": "emulation",
             "severity": "high", "context": "Emulated net_http", "confidence": "medium"},
            {"type": "mutex", "value": "HatcheryMutex", "source": "emulation",
             "severity": "medium", "context": "Mutex named during emulation", "confidence": "medium"},
        ]
    }
    report = IOCExtractor().extract(emulation_data=emulation)
    assert report.get_by_type("domain")[0].source == "emulation"
    assert report.get_by_type("domain")[0].severity == "high"
    assert report.get_by_type("mutex")[0].value == "HatcheryMutex"
    assert report.summary["domain"] == 1


def test_emulation_iocs_dedupe_against_static():
    static = {"strings": {"urls": ["http://c2.example/x"], "ips": [], "domains": ["c2.example"],
                          "emails": [], "registry_keys": []}}
    emulation = {"iocs": [
        {"type": "domain", "value": "c2.example", "source": "emulation", "severity": "high",
         "context": "", "confidence": "medium"},
    ]}
    report = IOCExtractor().extract(static_data=static, emulation_data=emulation)
    # The static row wins; the emulation row must not duplicate it.
    assert len(report.get_by_type("domain")) == 1
    assert report.get_by_type("domain")[0].source == "static"
