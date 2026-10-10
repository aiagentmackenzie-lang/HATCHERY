"""Signal extraction: what is deterministic, what is volatile, what is unknown."""

from __future__ import annotations

from _replay_builder import bundle_with, dynamic_bundle_with

from engine.replay.signals import extract_signals


def test_deterministic_signals_are_extracted_as_sets() -> None:
    signals = extract_signals(bundle_with())
    assert signals.deterministic["sha256"] == bundle_with()["sample"]["sha256"]
    assert signals.deterministic["file_type"] == "Unknown"
    assert signals.deterministic["delivery_format"] == "unknown"
    assert signals.deterministic["yara_rules"] == {
        "HATCHERY_EICAR_TestFile",
        "suspicious_base64",
    }
    assert signals.deterministic["capa_capabilities"] == {"create process", "write file"}
    assert signals.deterministic["attack_techniques"] == {"T1059.001"}
    assert "domain:evil.example" in signals.deterministic["static_iocs"]
    assert signals.unknown == ()


def test_only_static_sources_are_in_the_static_ioc_set() -> None:
    bundle = bundle_with(
        iocs=[
            {"type": "domain", "value": "static.example", "source": "static"},
            {"type": "ip", "value": "10.0.0.1", "source": "network"},
            {"type": "file_path", "value": "/tmp/x", "source": "strace"},
        ]
    )
    signals = extract_signals(bundle)
    assert "domain:static.example" in signals.deterministic["static_iocs"]
    assert "ip:10.0.0.1" not in signals.deterministic["static_iocs"]
    # every IOC still counts towards the volatile total and ordering
    assert signals.volatile["iocs_total"] == 3


def test_delivery_children_are_content_hashes_not_names() -> None:
    bundle = bundle_with(
        static={
            "delivery": {
                "format": "zip",
                "children": [
                    {"name": "a.exe", "sha256": "a" * 64},
                    {"name": "b.exe", "sha256": "b" * 64},
                ],
            }
        }
    )
    signals = extract_signals(bundle)
    assert signals.deterministic["delivery_format"] == "zip"
    assert signals.deterministic["delivery_children"] == {"a" * 64, "b" * 64}


def test_volatile_signals_capture_counts_and_ordering() -> None:
    signals = extract_signals(dynamic_bundle_with())
    assert signals.volatile["events_total"] == 100
    assert signals.volatile["events_by_category"]["file"] == 60
    assert signals.volatile["sandbox_status"] == "completed"
    assert signals.volatile["sandbox_duration_seconds"] == 12.5
    assert isinstance(signals.volatile["ioc_value_order"], tuple)


def test_ioc_order_is_order_sensitive() -> None:
    first = extract_signals(
        bundle_with(
            iocs=[
                {"type": "domain", "value": "a.example", "source": "static"},
                {"type": "domain", "value": "b.example", "source": "static"},
            ]
        )
    )
    second = extract_signals(
        bundle_with(
            iocs=[
                {"type": "domain", "value": "b.example", "source": "static"},
                {"type": "domain", "value": "a.example", "source": "static"},
            ]
        )
    )
    # the set is identical; only the volatile ordering changed
    assert first.deterministic["static_iocs"] == second.deterministic["static_iocs"]
    assert first.volatile["ioc_value_order"] != second.volatile["ioc_value_order"]


def test_old_bundle_marks_missing_sections_unknown() -> None:
    bundle = bundle_with()
    del bundle["static"]["delivery"]
    del bundle["mitre"]
    signals = extract_signals(bundle)
    assert "delivery_format" in signals.unknown
    assert "delivery_children" in signals.unknown
    assert "attack_techniques" in signals.unknown


def test_empty_bundle_does_not_explode() -> None:
    signals = extract_signals({})
    # every deterministic signal's source section is absent -> all unknown
    assert set(signals.unknown) >= {"sha256", "yara_rules", "capa_capabilities", "static_iocs"}
