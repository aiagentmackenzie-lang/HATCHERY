"""Configuration and IOC extraction from emulated runs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.emulate.config import extract_config, extract_iocs
from engine.emulate.report import parse_report

FIXTURE = Path(__file__).parent / "fixtures" / "speakeasy-report-real.json"


@pytest.fixture(scope="module")
def benign_config() -> dict:
    report = parse_report(json.loads(FIXTURE.read_text()))
    return extract_config(report)


def test_endpoint_extracted_from_real_capture(benign_config: dict) -> None:
    servers = {endpoint["server"] for endpoint in benign_config["network_endpoints"]}
    assert "c2.example" in servers
    endpoint = next(e for e in benign_config["network_endpoints"] if e["server"] == "c2.example")
    assert endpoint["port"] == 80


def test_mutex_and_user_agent_from_api_args(benign_config: dict) -> None:
    assert benign_config["mutexes"] == ["HatcheryMutex"]
    assert benign_config["user_agents"] == ["HatcheryAgent"]


def test_embedded_url_from_api_reference(benign_config: dict) -> None:
    assert "http://c2.example/stage" in benign_config["embedded_urls"]


def test_iocs_are_sourced_to_emulation(benign_config: dict) -> None:
    iocs = extract_iocs(benign_config)
    assert all(ioc["source"] == "emulation" for ioc in iocs)
    kinds = {(ioc["type"], ioc["value"]) for ioc in iocs}
    assert ("domain", "c2.example") in kinds
    assert ("url", "http://c2.example/stage") in kinds
    assert ("mutex", "HatcheryMutex") in kinds


def _report_with_events(events: list[dict]) -> object:
    return parse_report(
        {"report_version": "4.0.0", "entry_points": [{"ep_type": "module_entry", "events": events}]}
    )


def test_registry_persistence_is_flagged() -> None:
    report = _report_with_events([
        {
            "event": "reg_write_value",
            "path": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "Updater",
        },
        {"event": "reg_write_value", "path": "HKEY_LOCAL_MACHINE\\Software\\Vendor", "value_name": "x"},
    ])
    config = extract_config(report)
    assert len(config["registry"]) == 2
    persistence = config["registry_persistence"]
    assert len(persistence) == 1
    assert persistence[0]["value_name"] == "Updater"
    iocs = extract_iocs(config)
    assert any(ioc["value"] == persistence[0]["path"] and ioc["severity"] == "high" for ioc in iocs)


def test_dropped_files_and_hash_ioc() -> None:
    report = parse_report(
        {
            "report_version": "4.0.0",
            "entry_points": [
                {
                    "ep_type": "module_entry",
                    "events": [],
                    "dropped_files": [{"path": "C:\\Temp\\payload.exe", "sha256": "a" * 64}],
                }
            ],
        }
    )
    config = extract_config(report)
    assert config["dropped_files"][0]["path"] == "C:\\Temp\\payload.exe"
    iocs = extract_iocs(config)
    assert any(ioc["type"] == "hash" and ioc["value"] == "a" * 64 for ioc in iocs)


def test_loopback_endpoints_are_not_reported() -> None:
    report = _report_with_events([
        {"event": "net_http", "server": "127.0.0.1", "port": 8080, "proto": "tcp.http"},
        {"event": "net_traffic", "server": "10.0.0.5", "port": 4444, "proto": "tcp"},
    ])
    config = extract_config(report)
    servers = {endpoint["server"] for endpoint in config["network_endpoints"]}
    assert servers == {"10.0.0.5"}


def test_no_events_is_declared_not_clean() -> None:
    report = parse_report({"report_version": "4.0.0", "entry_points": []})
    config = extract_config(report)
    assert config["network_endpoints"] == []
    assert any("no events" in note.lower() for note in config["notes"])


def test_unsupported_api_is_noted() -> None:
    report = parse_report(
        {
            "report_version": "4.0.0",
            "entry_points": [
                {
                    "ep_type": "module_entry",
                    "events": [{"event": "api", "api_name": "kernel32.Nope", "args": [], "ret_val": "0x0"}],
                    "error": {"type": "unsupported_api", "api_name": "kernel32.Nope"},
                }
            ],
        }
    )
    config = extract_config(report)
    assert any("does not implement" in note.lower() for note in config["notes"])
