"""End-to-end emulation test — opt-in, starts a real container.

Enable with:

    HATCHERY_EMULATION_E2E=1 pytest tests/test_emulate_e2e.py -v

It is skipped otherwise so the fast unit suite never needs the emulation image
or the beta emulator. It builds a benign PE with tests/_pe_builder.py (no
compiler, no vendored binary), runs it through the containerized Speakeasy stage,
and asserts the API trace and extracted configuration really land in the result.

Folding into the existing E2E switch: setting HATCHERY_E2E=1 also enables it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from engine.emulate.manager import EmulationContainerConfig, EmulationManager
from _pe_builder import build_pe

pytestmark = pytest.mark.skipif(
    os.environ.get("HATCHERY_EMULATION_E2E") != "1" and os.environ.get("HATCHERY_E2E") != "1",
    reason="set HATCHERY_EMULATION_E2E=1 to run the container-based emulation test",
)


@pytest.fixture(scope="module")
def manager() -> EmulationManager:
    mgr = EmulationManager(EmulationContainerConfig(timeout=180, emulate_timeout=60))
    ready, problems = mgr.readiness()
    if not ready:
        pytest.skip("emulation not ready: " + "; ".join(problems))
    return mgr


@pytest.fixture(scope="module")
def sample(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_pe(tmp_path_factory.mktemp("emu-sample") / "benign.exe")


def test_emulation_container_produces_trace_and_config(manager: EmulationManager, sample: Path, tmp_path_factory) -> None:
    run_dir = tmp_path_factory.mktemp("emu-run")
    result = manager.execute(sample, run_dir, sample_name="benign.exe")

    assert result.status == "completed", result.error
    assert result.section is not None
    section = result.section
    assert section["available"] is True
    assert section["schema_hash"]
    assert section["emulator_version"] == "2.0.0b6"

    # A non-empty API trace is the whole point.
    assert section["api_calls"] >= 3
    assert result.events, "the API trace must not be empty"
    assert all(row["source"] == "emulation" for row in result.events)

    # The known configuration of the fixture must be extracted.
    config = section["config"]
    servers = {endpoint["server"] for endpoint in config["network_endpoints"]}
    assert "c2.example" in servers
    assert "HatcheryMutex" in config["mutexes"]
    assert "HatcheryAgent" in config["user_agents"]

    # The report was recovered copy-based and parsed.
    assert result.report_path is not None and result.report_path.exists()
    snapshots = section["snapshots"]
    assert snapshots["regions_decoded"] > 0


def test_emulation_report_schema_hash_is_present(manager: EmulationManager, sample: Path, tmp_path_factory) -> None:
    run_dir = tmp_path_factory.mktemp("emu-run-2")
    result = manager.execute(sample, run_dir)
    assert result.section is not None
    assert len(result.section["schema_hash"]) == 64
