"""Tier-2 container wiring: gVisor annotations must actually reach the daemon.

docker-py 7.2.0 has no typed ``annotations`` argument anywhere, so HATCHERY
builds the create config explicitly and sets ``HostConfig.Annotations``. This
suite fails if that forwarding is ever dropped, because then gVisor silently
stops emitting the Sentry trace.
"""

from __future__ import annotations

from typing import Any, Optional

from engine.sandbox.container import ContainerConfig, ContainerManager
from engine.sandbox.isolation import IsolationTier


class FakeContainer:
    id = "f" * 64

    def __init__(self, annotations: Optional[dict] = None) -> None:
        self.attrs = {"HostConfig": {"Annotations": annotations or {}}}


class FakeContainers:
    def __init__(self, container: FakeContainer) -> None:
        self._container = container

    def get(self, container_id: str) -> FakeContainer:
        return self._container


class FakeAPI:
    """Records the config handed to create_container_from_config."""

    def __init__(self) -> None:
        self.config: Optional[dict] = None

    def create_host_config(self, **kwargs: Any) -> dict:
        return dict(kwargs)

    def create_container_config(self, **kwargs: Any) -> dict:
        return {"config": kwargs}

    def create_container_from_config(self, config: dict) -> dict:
        self.config = config
        return {"Id": "f" * 64}


class FakeClient:
    def __init__(self, annotations: Optional[dict] = None) -> None:
        self.api = FakeAPI()
        self.containers = FakeContainers(FakeContainer(annotations))


def _manager(annotations: Optional[dict] = None) -> ContainerManager:
    manager = ContainerManager(ContainerConfig())
    manager._client = FakeClient(annotations)  # type: ignore[assignment]
    return manager


def test_gvisor_annotation_keys_are_the_allow_listed_flags():
    assert ContainerManager.GVISOR_ANNOTATIONS == {
        "dev.gvisor.flag.debug": "true",
        "dev.gvisor.flag.strace": "true",
        "dev.gvisor.flag.strace-log-size": "1024",
        "dev.gvisor.flag.debug-to-user-log": "true",
    }


def test_annotations_are_requested_only_at_tier_two():
    manager = _manager()
    assert manager._annotations_for_tier(IsolationTier.SANDBOXED_KERNEL) == (
        ContainerManager.GVISOR_ANNOTATIONS
    )
    assert manager._annotations_for_tier(IsolationTier.SHARED_KERNEL) == {}
    assert manager._annotations_for_tier(IsolationTier.HARDWARE_VM) == {}


def test_annotations_are_forwarded_as_host_config_annotations():
    """The failing test for the forwarding bug: without
    ``host_config['Annotations']`` the daemon never sees them and the Sentry
    trace is never emitted."""
    manager = _manager()
    manager._create_container_with_annotations(
        target_name="probe.sh",
        runtime="runsc-hatchery",
        env_list=["HATCHERY_TIER=2"],
        security_opt=["no-new-privileges:true"],
        annotations=dict(ContainerManager.GVISOR_ANNOTATIONS),
    )
    assert manager._client.api.config is not None  # type: ignore[union-attr]
    host_config = manager._client.api.config["config"]["host_config"]  # type: ignore[union-attr]
    assert host_config["Annotations"] == ContainerManager.GVISOR_ANNOTATIONS
    assert host_config["runtime"] == "runsc-hatchery"
    assert host_config["network_mode"] == ContainerConfig().network_name
    assert host_config["security_opt"] == ["no-new-privileges:true"]


def test_missing_annotations_are_a_test_visible_regression():
    """If the annotations are absent from the host_config the assertion above
    is what fails; this pins the negative case explicitly."""
    manager = _manager()
    manager._create_container_with_annotations(
        target_name="probe.sh",
        runtime="runsc-hatchery",
        env_list=[],
        security_opt=[],
        annotations={},
    )
    host_config = manager._client.api.config["config"]["host_config"]  # type: ignore[union-attr]
    assert host_config["Annotations"] == {}


def test_tier_two_output_volume_is_mounted_into_the_sandbox():
    """D17: the named volume is how tier-2 in-guest artifacts survive the gVisor
    sandbox exiting. If the bind is dropped the artifacts silently vanish."""
    manager = _manager()
    manager._create_container_with_annotations(
        target_name="probe.sh",
        runtime="runsc-hatchery",
        env_list=[],
        security_opt=[],
        annotations=dict(ContainerManager.GVISOR_ANNOTATIONS),
        binds=["hatchery-output-abc:/hatchery/output:rw"],
    )
    host_config = manager._client.api.config["config"]["host_config"]  # type: ignore[union-attr]
    assert host_config["binds"] == ["hatchery-output-abc:/hatchery/output:rw"]
    assert manager._client.api.config["config"]["host_config"]["runtime"] == "runsc-hatchery"
