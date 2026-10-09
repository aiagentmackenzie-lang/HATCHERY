"""Run Speakeasy in a container at the probed tier, then parse its report.

Lifecycle: probe isolation -> ensure image -> create a named output volume ->
copy the sample and config in over the Docker API -> run with a wall-clock cap
-> recover the report copy-based (never a host bind mount, D5) -> parse it ->
destroy. Nothing here runs on the bare host unless the operator explicitly asked
for the off-by-default ``--allow-host-emulation`` escape hatch, which is loudly
labelled.

Why the report is recovered through a **named volume**: at tier 2 gVisor keeps
the container rootfs overlay in memory, so ``get_archive`` cannot read a file the
emulation container just wrote (this bit us during the gVisor probe — ``docker
cp`` returned "Could not find the file"). The named volume is host-backed and
survives the sandbox; a short ``runc`` sidecar reads it back. The same route
works at tier 1, so there is one code path rather than a tier split.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tarfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Optional

from engine.emulate import runner
from engine.emulate.report import EmulationReport, parse_report
from engine.sandbox.isolation import (
    IsolationProbe,
    IsolationTier,
    probe_isolation,
)

logger = logging.getLogger(__name__)

try:
    import docker as docker_sdk
    from docker.models.containers import Container
    HAS_DOCKER = True
except ImportError:  # pragma: no cover - docker is a core dependency
    HAS_DOCKER = False
    Container = object  # type: ignore[misc,assignment]
    logger.warning("docker SDK not available — container emulation disabled")

DEFAULT_TIMEOUT = 180
DEFAULT_EMULATE_TIMEOUT = 60
DEFAULT_CPU_LIMIT = 1.0
DEFAULT_MEMORY_LIMIT = "1g"
DEFAULT_PIDS_LIMIT = 128
OUTPUT_VOLUME_PATH = "/hatchery/output"
SIDECAR_TIMEOUT = 60


@dataclass
class EmulationContainerConfig:
    """Configuration for the emulation container and the emulated run."""

    image: str = runner.EMULATION_IMAGE
    timeout: int = DEFAULT_TIMEOUT
    emulate_timeout: int = DEFAULT_EMULATE_TIMEOUT
    max_api_count: int = runner.DEFAULT_MAX_API_COUNT
    max_instructions: int = runner.DEFAULT_MAX_INSTRUCTIONS
    snapshot_memory_regions: bool = True
    cpu_limit: float = DEFAULT_CPU_LIMIT
    memory_limit: str = DEFAULT_MEMORY_LIMIT
    pids_limit: int = DEFAULT_PIDS_LIMIT
    raw: bool = False
    arch: Optional[str] = None
    run_capa: bool = True
    preferred_runtime: Optional[str] = None
    allow_host_emulation: bool = False

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "timeout": self.timeout,
            "emulate_timeout": self.emulate_timeout,
            "max_api_count": self.max_api_count,
            "max_instructions": self.max_instructions,
            "snapshot_memory_regions": self.snapshot_memory_regions,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "raw": self.raw,
            "arch": self.arch,
            "run_capa": self.run_capa,
            "allow_host_emulation": self.allow_host_emulation,
        }


@dataclass
class EmulationResult:
    """Outcome of one emulation run, successful or not."""

    status: str = ""
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    container_id: str = ""
    isolation: Optional[dict] = None
    report_path: Optional[Path] = None
    log_path: Optional[Path] = None
    runtime_seconds: float = 0.0
    section: Optional[dict] = None
    events: list[dict] = field(default_factory=list)
    error: Optional[str] = None
    ran_on_host: bool = False

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "container_id": self.container_id,
            "isolation": self.isolation,
            "report_path": str(self.report_path) if self.report_path else None,
            "log_path": str(self.log_path) if self.log_path else None,
            "error": self.error,
            "ran_on_host": self.ran_on_host,
            "emulation": self.section,
        }


class EmulationManager:
    """Manage the containerized Speakeasy stage."""

    def __init__(
        self,
        config: Optional[EmulationContainerConfig] = None,
        client: Optional[Any] = None,
    ) -> None:
        self.config = config or EmulationContainerConfig()
        self._client = client
        self._isolation: Optional[IsolationProbe] = None

    # ------------------------------------------------------------------ setup

    @property
    def client(self) -> Any:
        if self._client is None:
            if not HAS_DOCKER:
                raise RuntimeError("docker SDK not installed")
            self._client = docker_sdk.from_env()
        return self._client

    @property
    def isolation(self) -> IsolationProbe:
        if self._isolation is None:
            try:
                self._isolation = probe_isolation(
                    client=self.client,
                    preferred_runtime=self.config.preferred_runtime,
                )
            except Exception as exc:  # noqa: BLE001
                probe = IsolationProbe(probed=True)
                probe.errors.append(f"Isolation probe failed: {exc}")
                self._isolation = probe
        return self._isolation

    def readiness(self) -> tuple[bool, list[str]]:
        """Whether a containerized emulation can actually run, and why not."""
        if not HAS_DOCKER:
            return False, ["docker SDK is not installed (pip install docker)"]
        try:
            self.client.ping()
        except Exception as exc:  # noqa: BLE001
            return False, [f"Docker daemon unreachable: {exc}"]

        problems: list[str] = []
        try:
            self.client.images.get(self.config.image)
        except docker_sdk.errors.ImageNotFound:
            problems.append(
                f"Emulation image {self.config.image!r} not built — run: "
                "hatchery build --emulation"
            )
        except Exception as exc:  # noqa: BLE001
            problems.append(f"Could not inspect emulation image: {exc}")

        probe = self.isolation
        if probe.runtime is None:
            problems.append("No usable container runtime reported by the daemon")
        return (not problems), problems

    def emulation_available(self) -> tuple[bool, str]:
        """A one-line availability answer for ``hatchery doctor``."""
        if self.config.allow_host_emulation and shutil.which("speakeasy"):
            return True, "host escape hatch enabled (NOT containerized — unsupported)"
        if not HAS_DOCKER:
            return False, "docker SDK not installed"
        try:
            self.client.ping()
        except Exception as exc:  # noqa: BLE001
            return False, f"Docker daemon unreachable: {exc}"
        try:
            self.client.images.get(self.config.image)
        except Exception:  # noqa: BLE001
            return False, f"emulation image {self.config.image!r} not built"
        probe = self.isolation
        if probe.tier == IsolationTier.STATIC_ONLY:
            return False, "no container runtime available"
        return True, f"containerized at {probe.runtime} (tier {int(probe.tier)})"

    # ------------------------------------------------------------------- image

    def build_image(self, docker_dir: Optional[Path] = None) -> str:
        """Build the emulation image, returning its tag."""
        if docker_dir is None:
            docker_dir = Path(__file__).parent / "docker"
        if not docker_dir.exists():
            raise FileNotFoundError(f"Emulation docker dir not found: {docker_dir}")

        logger.info("Building emulation image from %s", docker_dir)
        image, build_logs = self.client.images.build(path=str(docker_dir), tag=self.config.image, rm=True)
        for entry in build_logs:
            if "stream" in entry:
                logger.debug("docker build: %s", entry["stream"].strip())
        logger.info("Built emulation image: %s", image.id)
        return self.config.image

    # ---------------------------------------------------------------- copying

    @staticmethod
    def _tar_bytes(name: str, data: bytes, mode: int = 0o644) -> BytesIO:
        stream = BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, BytesIO(data))
        stream.seek(0)
        return stream

    def _copy_in(self, container: Any, sample_path: Path, target_name: str) -> None:
        config = runner.speakeasy_config(
            timeout=self.config.emulate_timeout,
            max_api_count=self.config.max_api_count,
            max_instructions=self.config.max_instructions,
            snapshot_memory_regions=self.config.snapshot_memory_regions,
        )
        if not container.put_archive("/hatchery/", self._tar_bytes("emu-config.json", json.dumps(config).encode())):
            raise RuntimeError("failed to copy emulation config into container")
        sample = sample_path.read_bytes()
        if not container.put_archive("/hatchery/sample/", self._tar_bytes(target_name, sample, mode=0o644)):
            raise RuntimeError(f"failed to copy sample into container: {sample_path}")

    # ---------------------------------------------------------------- recover

    def _recover_outputs(self, volume_name: str, run_dir: Path) -> dict[str, Path]:
        """Copy the container's output files out through a runc sidecar.

        The named volume is host-backed, so this works after a gVisor sandbox
        exits — unlike ``get_archive`` on the sandbox container itself.
        """
        run_dir.mkdir(parents=True, exist_ok=True)
        recovered: dict[str, Path] = {}
        sidecar = None
        try:
            sidecar = self.client.containers.create(
                image=self.config.image,
                entrypoint=["/bin/true"],
                runtime="runc",
                volumes={volume_name: {"bind": OUTPUT_VOLUME_PATH, "mode": "rw"}},
                detach=True,
                network_mode="none",
            )
            sidecar.start()
            sidecar.wait(timeout=SIDECAR_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            if sidecar is not None:
                self._remove_quietly(sidecar)
            raise RuntimeError(f"could not read emulation output volume: {exc}") from exc

        try:
            for fname, dest_name in (
                ("report.json", "report.json"),
                ("emulation.log", "emulation.log"),
                ("emulation.exit", "emulation.exit"),
            ):
                path = self._pull_file(sidecar, f"{OUTPUT_VOLUME_PATH}/{fname}", run_dir / dest_name)
                if path is not None:
                    recovered[fname] = path
        finally:
            self._remove_quietly(sidecar)
        return recovered

    @staticmethod
    def _pull_file(container: Any, container_path: str, dest: Path) -> Optional[Path]:
        from docker.errors import NotFound

        try:
            stream, _ = container.get_archive(container_path)
        except NotFound:
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not copy %s out of sidecar: %s", container_path, exc)
            return None

        buffer = BytesIO()
        for chunk in stream:
            buffer.write(chunk)
        buffer.seek(0)
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(fileobj=buffer, mode="r") as tar:
                for member in tar.getmembers():
                    if not member.isfile():
                        continue
                    name = Path(member.name).name
                    if ".." in Path(name).parts:
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    dest.write_bytes(extracted.read())
                    return dest
        except tarfile.TarError as exc:
            logger.warning("Bad tar while copying %s: %s", container_path, exc)
            return None
        return None

    @staticmethod
    def _remove_quietly(container: Any) -> None:
        try:
            container.remove(force=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sidecar cleanup failed: %s", exc)

    # ---------------------------------------------------------------- execute

    def execute(
        self,
        sample_path: Path,
        results_dir: Path,
        sample_name: Optional[str] = None,
    ) -> EmulationResult:
        """Emulate a sample and return its parsed report."""
        result = EmulationResult(
            isolation=self.isolation.to_dict() if self._isolation else None
        )

        if not sample_path.exists():
            result.status = "error"
            result.error = f"Sample not found: {sample_path}"
            result.section = runner.unavailable_section(result.error)
            result.section["status"] = "error"
            return result

        ready, problems = self.readiness()
        if not ready:
            if self.config.allow_host_emulation:
                return self._execute_on_host(sample_path, results_dir, result, sample_name)
            result.status = "unavailable"
            result.error = "; ".join(problems)
            result.section = runner.unavailable_section(result.error)
            return result

        probe = self.isolation
        runtime = probe.runtime
        results_dir.mkdir(parents=True, exist_ok=True)
        target_name = sample_name or sample_path.name
        volume_name = f"hatchery-emu-{uuid.uuid4().hex[:12]}"
        container = None
        started = datetime.now(timezone.utc)

        try:
            self.client.volumes.create(name=volume_name)
            container = self.client.containers.create(
                image=self.config.image,
                command=runner.speakeasy_args(
                    sample_container_path=f"{runner.SAMPLE_CONTAINER_DIR}/{target_name}",
                    raw=self.config.raw,
                    arch=self.config.arch,
                ),
                network_mode="none",
                mem_limit=self.config.memory_limit,
                nano_cpus=int(self.config.cpu_limit * 1e9),
                pids_limit=self.config.pids_limit,
                security_opt=["no-new-privileges:true"],
                cap_drop=["ALL"],
                user="1000:1000",
                runtime=runtime,
                volumes={volume_name: {"bind": OUTPUT_VOLUME_PATH, "mode": "rw"}},
                detach=True,
            )
            result.container_id = container.id
            self._copy_in(container, sample_path, target_name)
            container.start()
            logger.info(
                "Emulation container %s started (runtime=%s, tier=%d, sample=%s)",
                container.id[:12], runtime, int(probe.tier), target_name,
            )
            try:
                wait_result = container.wait(timeout=self.config.timeout)
                result.exit_code = (
                    wait_result.get("StatusCode")
                    if isinstance(wait_result, dict)
                    else wait_result
                )
                result.status = "completed"
            except Exception:  # noqa: BLE001 - Docker raises on wait timeout
                logger.warning(
                    "Emulation container %s exceeded %ds — killing",
                    container.id[:12], self.config.timeout,
                )
                container.kill()
                result.status = "timeout"
        except docker_sdk.errors.ImageNotFound:
            result.status = "unavailable"
            result.error = f"Emulation image {self.config.image!r} not found — run: hatchery build --emulation"
            result.section = runner.unavailable_section(result.error)
            self._cleanup(container, volume_name)
            return result
        except Exception as exc:  # noqa: BLE001
            result.status = "error"
            result.error = f"Emulation container failed: {exc}"
            logger.exception("Emulation container failed")
            result.section = runner.unavailable_section(result.error)
            result.section["status"] = "error"
            self._cleanup(container, volume_name)
            return result

        result.duration_seconds = (datetime.now(timezone.utc) - started).total_seconds()

        # Recover outputs before cleanup destroys the volume.
        recovered: dict[str, Path] = {}
        try:
            recovered = self._recover_outputs(volume_name, results_dir)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Output recovery failed: %s", exc)
            result.error = f"output recovery failed: {exc}"

        self._cleanup(container, volume_name)

        result.report_path = recovered.get("report.json")
        result.log_path = recovered.get("emulation.log")
        exit_file = recovered.get("emulation.exit")
        if exit_file is not None:
            try:
                result.exit_code = int(exit_file.read_text().strip())
            except (ValueError, OSError):
                pass

        self._finalise(result, recovered, "container")
        return result

    def _cleanup(self, container: Any, volume_name: str) -> None:
        if container is not None:
            self._remove_quietly(container)
        try:
            self.client.volumes.get(volume_name).remove(force=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not remove emulation volume %s: %s", volume_name, exc)

    # ------------------------------------------------------------- host escape

    def _execute_on_host(
        self,
        sample_path: Path,
        results_dir: Path,
        result: EmulationResult,
        sample_name: Optional[str],
    ) -> EmulationResult:
        """Off-by-default escape hatch. Loudly not containerized."""
        logger.warning(
            "Running emulation on the BARE HOST via --allow-host-emulation. "
            "This bypasses the container boundary and is not supported."
        )
        result.ran_on_host = True
        exe = shutil.which("speakeasy")
        if not exe:
            result.status = "unavailable"
            result.error = (
                "allow_host_emulation is set but the speakeasy CLI is not on "
                "PATH; install the [emulation] extra or do not use the escape hatch"
            )
            result.section = runner.unavailable_section(result.error)
            return result

        results_dir.mkdir(parents=True, exist_ok=True)
        config_path = results_dir / "emu-config.json"
        config_path.write_text(
            json.dumps(
                runner.speakeasy_config(
                    timeout=self.config.emulate_timeout,
                    max_api_count=self.config.max_api_count,
                    max_instructions=self.config.max_instructions,
                    snapshot_memory_regions=self.config.snapshot_memory_regions,
                )
            )
        )
        report_path = results_dir / "report.json"
        started = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(
                [exe] + runner.speakeasy_args(
                    sample_container_path=str(sample_path),
                    report_container_path=str(report_path),
                    config_container_path=str(config_path),
                    raw=self.config.raw,
                    arch=self.config.arch,
                ),
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            result.status = "completed" if proc.returncode == 0 else "error"
            result.exit_code = proc.returncode
            (results_dir / "emulation.log").write_text(proc.stdout + proc.stderr)
            result.log_path = results_dir / "emulation.log"
            if proc.returncode != 0:
                result.error = f"host speakeasy exited {proc.returncode}"
        except subprocess.TimeoutExpired:
            result.status = "timeout"
            result.error = f"host emulation exceeded {self.config.timeout}s"
        result.duration_seconds = (datetime.now(timezone.utc) - started).total_seconds()
        result.report_path = report_path if report_path.exists() else None
        self._finalise(result, {"report.json": report_path} if report_path.exists() else {}, "host")
        return result

    # --------------------------------------------------------------- finalise

    def _finalise(self, result: EmulationResult, recovered: dict, where: str) -> None:
        report_path = result.report_path
        if report_path is None or not report_path.exists():
            reason = result.error or (
                f"the emulator produced no report ({where}); the run is "
                "INCONCLUSIVE, not evidence of benign behaviour"
            )
            if result.status == "completed":
                result.status = "error"
            result.error = reason
            result.section = runner.unavailable_section(reason)
            result.section["status"] = result.status
            return

        try:
            raw = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            reason = f"emulation report was not valid JSON: {exc}"
            result.status = "error"
            result.error = reason
            result.section = runner.unavailable_section(reason)
            result.section["status"] = "error"
            return

        section, events = runner.analyze(raw, run_capa=self.config.run_capa)
        if result.status == "timeout":
            section["status"] = "timeout"
            section["timeout_seconds"] = self.config.timeout
            section.setdefault("flags", []).append("emulation-timeout")
        result.section = section
        result.events = events
        parsed: EmulationReport = parse_report(raw)
        result.runtime_seconds = parsed.runtime_seconds
