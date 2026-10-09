"""ATT&CK mapping tests — D15.

These tests fail on the exact defects the old hand-maintained lookup shipped:
wrong technique IDs, a hand-written tactic that no longer exists, a revoked
technique, and a YARA path that emitted ``tactic="Unknown"``. They run against
the **pinned** dataset and against real captured fixtures, not strings the
author invented.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from engine.export.attack_dataset import (
    ATTACK_SOURCE_SHA256,
    ATTACK_VERSION,
    AttackMappingError,
    default_dataset,
    load_dataset,
)
from engine.export.attack_navigator import (
    LAYER_VERSION,
    build_navigator_layer,
    validate_navigator_layer,
)
from engine.export.mitre_map import MITREMapper, ObservedTechnique

FIXTURES = Path(__file__).parent / "fixtures"
STRACE_REAL = FIXTURES / "strace-real.log"
GVISOR_REAL = FIXTURES / "gvisor-strace-real.log"


def event(syscall: str, args: str = "", pid: int = 42, ret: str = "0", paths=None):
    return SimpleNamespace(
        timestamp="12:00:00.000001",
        pid=pid,
        syscall=syscall,
        args=args,
        return_value=ret,
        paths=list(paths or []),
    )


def behavior(*events):
    return SimpleNamespace(events=list(events), source="strace")


# ---------------------------------------------------------------------------
# The pinned dataset
# ---------------------------------------------------------------------------


def test_dataset_is_pinned_to_the_recorded_version_and_hash():
    dataset = default_dataset()
    assert dataset.version == ATTACK_VERSION == "19.2"
    assert dataset.source_sha256 == ATTACK_SOURCE_SHA256
    assert dataset.spec_version.startswith("3.3")
    assert len(dataset) > 800


def test_dataset_tactic_split_was_verified_not_assumed():
    """D15 said to check v19's claims. In 19.2: Defense Evasion is gone, split
    into stealth and defense-impairment."""
    dataset = default_dataset()
    assert "defense-evasion" not in dataset.tactic_names
    assert "stealth" in dataset.tactic_names
    assert "defense-impairment" in dataset.tactic_names


def test_rootkit_and_modify_registry_are_active_in_19_2():
    """The handoff claimed v19 deleted T1014 and T1112. Verified false for the
    pinned 19.2 dataset, where both are active."""
    dataset = default_dataset()
    assert dataset.validate_technique("T1014") == []
    assert dataset.validate_technique("T1112") == []


def test_revoked_technique_is_rejected():
    """T1562.006 Indicator Blocking *is* revoked in 19.2 — the real deprecation
    marker in this dataset (there are no x_mitre_deprecated techniques)."""
    dataset = default_dataset()
    problems = dataset.validate_technique("T1562.006")
    assert problems and "revoked" in problems[0]


def test_unknown_technique_is_rejected():
    problems = default_dataset().validate_technique("T9999")
    assert problems and "not a technique" in problems[0]


def test_wrong_tactic_is_rejected():
    """T1055 is Stealth/Privilege-Escalation, never Execution."""
    problems = default_dataset().validate_technique("T1055", "execution")
    assert problems and "not in tactic" in problems[0]
    assert default_dataset().validate_technique("T1055", "stealth") == []


def test_loader_reports_a_missing_artifact_clearly(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_dataset(tmp_path / "missing.json")


# ---------------------------------------------------------------------------
# The mapper: the wrong IDs from the old lookup must stay fixed
# ---------------------------------------------------------------------------


def _map(events) -> list[str]:
    result = MITREMapper().map_all(behavior_result=behavior(*events))
    assert result.errors == []
    return [t.subtechnique_id or t.technique_id for t in result.techniques]


def test_clone_and_fork_are_not_process_injection_or_native_api():
    """Old: clone -> T1055 Process Injection, fork -> T1106 Native API."""
    ids = _map([event("clone"), event("fork"), event("clone3")])
    assert "T1055" not in ids
    assert "T1106" not in ids


def test_mmap_is_not_process_hollowing():
    ids = _map([event("mmap", "NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0")])
    assert "T1055.012" not in ids


def test_bind_does_not_claim_lateral_tool_transfer():
    """Old: bind -> T1570 'Non-Standard Port (Listen)' — both the ID and the
    label were wrong."""
    ids = _map([event("bind", "3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr(\"0.0.0.0\")}, 16")])
    assert "T1570" not in ids
    assert "T1571" in ids  # the real Non-Standard Port technique


def test_connect_is_port_aware_not_always_t1071():
    dns = _map([event("connect", '3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("1.1.1.1")}, 16')])
    web = _map([event("connect", '3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16')])
    odd = _map([event("connect", '3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("1.1.1.1")}, 16')])

    assert "T1071.004" in dns
    assert "T1071.001" in web
    assert "T1571" in odd
    # A generic T1071 must never be emitted for a specific port.
    assert "T1071" not in dns and "T1071" not in web and "T1071" not in odd


def test_af_unix_connect_is_not_network_c2():
    """glibc's nscd socket churn must not read as command-and-control."""
    ids = _map([event("connect", '3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110')])
    assert ids == []


def test_etc_hosts_no_longer_maps_to_modify_registry():
    mapper = MITREMapper()
    result = mapper.map_all(file_watch_data={"events": [{"path": "/etc/hosts", "event_type": "modify"}]})
    ids = [t.technique_id for t in result.techniques]
    assert "T1112" not in ids
    assert result.errors == []


def test_file_patterns_map_to_verified_tactics():
    mapper = MITREMapper()
    result = mapper.map_all(
        file_watch_data={
            "events": [
                {"path": "/home/user/.bashrc"},
                {"path": "/home/user/.ssh/authorized_keys"},
                {"path": "/etc/cron.d/backdoor"},
                {"path": "/etc/init.d/persist"},
            ]
        }
    )
    ids = {(t.subtechnique_id or t.technique_id): t for t in result.techniques}
    assert "T1546.004" in ids and ids["T1546.004"].tactic_id == "persistence"
    assert "T1098.004" in ids and ids["T1098.004"].tactic_id == "persistence"
    assert "T1053.003" in ids and ids["T1053.003"].tactic_id == "persistence"
    assert "T1037.004" in ids and ids["T1037.004"].tactic_id == "persistence"
    assert result.errors == []


def test_credential_file_read_is_credential_access():
    ids = _map([event("openat", 'AT_FDCWD, "/etc/shadow", O_RDONLY')])
    assert "T1003.008" in ids


def test_shell_exec_maps_to_unix_shell():
    ids = _map([event("execve", '"/bin/sh", ["sh", "-c", "id"], 0x0')])
    assert "T1059.004" in ids


def test_execve_of_an_arbitrary_binary_is_not_invented():
    """There is no generic 'process execution' technique; the old mapper
    over-mapped every execve. A plain ELF execution maps to nothing."""
    ids = _map([event("execve", '"/opt/acme/worker", ["worker"], 0x0')])
    assert ids == []


def test_yara_meta_uses_the_dataset_tactic_not_unknown():
    """Old: the YARA meta path emitted tactic='Unknown' with a truncated ID."""
    mapper = MITREMapper()
    result = mapper.map_all(
        yara_data={
            "matches": [
                {"rule": "R", "tags": [], "meta": {"mitre_attck": "T1622: Debugger Evasion"}},
                {"rule": "R", "tags": [], "meta": {"mitre_attck": "T1497.001: System Checks"}},
            ]
        }
    )
    assert result.errors == []
    for technique in result.techniques:
        assert technique.tactic != "Unknown"
        assert technique.tactic_id in default_dataset().tactics_for(technique.technique_id)


def test_capa_tactic_is_derived_from_the_dataset_not_from_capa():
    """capa 9.x still emits the pre-v19 'defense-evasion' tactic. The mapper
    must not trust it."""
    mapper = MITREMapper()
    result = mapper.map_all(
        capa_data={
            "attack_techniques": [
                {"tactic": "defense-evasion", "id": "T1055", "technique": "Process Injection", "subtechnique": ""}
            ]
        }
    )
    assert result.errors == []
    assert result.techniques[0].tactic_id == "stealth"


def test_capa_revoked_technique_is_an_error_not_a_silent_mapping():
    mapper = MITREMapper()
    result = mapper.map_all(
        capa_data={"attack_techniques": [{"id": "T1562.006", "technique": "Indicator Blocking"}]}
    )
    assert result.techniques == []
    assert result.errors and "revoked" in result.errors[0]


def test_emit_records_a_wrong_tactic_and_validate_raises():
    mapper = MITREMapper()
    mapper._emit(ObservedTechnique("T1055", "execution"), [], set(), "test")
    assert mapper.errors
    with pytest.raises(AttackMappingError):
        mapper.validate()


def test_emit_records_an_unknown_id_and_validate_raises():
    mapper = MITREMapper()
    mapper._emit(ObservedTechnique("T9999", "stealth"), [], set(), "test")
    assert mapper.errors
    with pytest.raises(AttackMappingError):
        mapper.validate()


def test_every_authored_mapping_id_exists_with_its_tactic():
    """A guard over the whole authored map: no table may introduce an ID that
    the pinned dataset does not know, or pair it with a tactic it does not have."""
    from engine.export import mitre_map
    from engine.export.sigma_candidates import SIGMA_TEMPLATES

    dataset = default_dataset()
    entries = list(mitre_map.SYSCALL_TECHNIQUE_MAP.values())
    entries += [mapping for _, mapping in mitre_map.FILE_PATTERN_MAP]
    entries += list(mitre_map.YARA_TAG_MAP.values())

    for mapping in entries:
        assert dataset.validate_technique(mapping.technique_id, mapping.tactic) == [], (
            mapping.technique_id,
            mapping.tactic,
        )
    for technique_id in SIGMA_TEMPLATES:
        assert dataset.validate_technique(technique_id) == [], technique_id


# ---------------------------------------------------------------------------
# Real observed probes
# ---------------------------------------------------------------------------


def test_real_strace_probe_maps_expected_techniques():
    from engine.monitor.strace_parser import StraceParser

    parsed = StraceParser().parse_file(STRACE_REAL)
    result = MITREMapper().map_all(behavior_result=parsed)
    ids = {t.subtechnique_id or t.technique_id for t in result.techniques}
    assert "T1003.008" in ids  # the probe reads /etc/passwd
    assert "T1071.004" in ids  # its DNS connect
    assert result.errors == []
    assert result.attack_version == "19.2"


def test_real_gvisor_probe_maps_expected_techniques():
    from engine.monitor.gvisor_strace import GvisorStraceParser

    parsed = GvisorStraceParser().parse_file(GVISOR_REAL)
    result = MITREMapper().map_all(behavior_result=parsed)
    ids = {t.subtechnique_id or t.technique_id for t in result.techniques}
    assert "T1003.008" in ids
    assert "T1497.001" in ids  # /proc/cpuinfo / hypervisor probes
    assert "T1622" in ids  # TracerPid / ptrace
    assert result.errors == []


# ---------------------------------------------------------------------------
# ATT&CK Navigator layer
# ---------------------------------------------------------------------------


def _layer() -> dict:
    mapper = MITREMapper()
    result = mapper.map_all(
        behavior_result=behavior(
            event("execve", '"/bin/sh", ["sh"], 0x0'),
            event("openat", 'AT_FDCWD, "/etc/shadow", O_RDONLY', pid=43),
        )
    )
    return build_navigator_layer(
        mitre=result.to_dict(), sample_name="probe.sh", task_id="abc123"
    )


def test_navigator_layer_has_the_pinned_versions_and_structure():
    layer = _layer()
    assert layer["versions"]["layer"] == LAYER_VERSION == "4.5"
    assert layer["versions"]["attack"] == ATTACK_VERSION
    assert layer["domain"] == "enterprise-attack"
    assert layer["gradient"]["colors"]
    assert layer["techniques"]


def test_navigator_layer_is_valid_and_every_technique_exists():
    assert validate_navigator_layer(_layer()) == []


def test_navigator_layer_rejects_an_unknown_technique():
    layer = _layer()
    layer["techniques"].append({"techniqueID": "T9999", "score": 50, "comment": "nope"})
    problems = validate_navigator_layer(layer)
    assert any("does not exist" in problem for problem in problems)


def test_navigator_layer_rejects_a_tactic_mismatch():
    layer = _layer()
    layer["techniques"][0]["tactic"] = "impact"
    problems = validate_navigator_layer(layer)
    assert any("disagrees" in problem for problem in problems)


def test_navigator_layer_round_trips_as_json():
    layer = _layer()
    assert json.loads(json.dumps(layer))["versions"]["attack"] == ATTACK_VERSION


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
