"""Docker container lifecycle management for malware detonation.

Creates a container at the strongest isolation tier the host can provide,
executes the sample under syscall tracing, enforces a timeout, and recovers
behavioral artifacts.

The manager reports the isolation tier it used on every run. See
:mod:`engine.sandbox.isolation` for why that matters.
"""

from __future__ import annotations

import json
import logging
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional

from engine.sandbox.artifacts import ArtifactSet, collect_artifacts
from engine.sandbox.isolation import IsolationProbe, probe_isolation
from engine.sandbox.network import DEFAULT_NETWORK_NAME

logger = logging.getLogger(__name__)

try:
    import docker as docker_sdk
    from docker.models.containers import Container
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    logger.warning("docker SDK not available — sandbox disabled")

# Default configuration
DEFAULT_TIMEOUT = 120          # seconds
DEFAULT_CPU_LIMIT = 1.0       # 1 core
DEFAULT_MEMORY_LIMIT = "1g"
DEFAULT_PIDS_LIMIT = 256      # bound fork bombs
SANDBOX_IMAGE = "hatchery-sandbox:latest"
SECCOMP_PATH = Path(__file__).parent / "seccomp.json"


@dataclass
class ContainerConfig:
    """Configuration for a sandbox container."""
    image: str = SANDBOX_IMAGE
    timeout: int = DEFAULT_TIMEOUT
    cpu_limit: float = DEFAULT_CPU_LIMIT
    memory_limit: str = DEFAULT_MEMORY_LIMIT
    pids_limit: int = DEFAULT_PIDS_LIMIT
    network_name: str = DEFAULT_NETWORK_NAME
    seccomp_profile: Optional[dict] = None
    hostname: str = "workstation"
    preferred_runtime: Optional[str] = None
    extra_env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "timeout": self.timeout,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "pids_limit": self.pids_limit,
            "network_name": self.network_name,
            "hostname": self.hostname,
            "preferred_runtime": self.preferred_runtime,
        }


@dataclass
class ContainerResult:
    """Result of a sandbox container execution."""

    container_id: str = ""
    status: str = ""  # completed, timeout, error, crashed
    exit_code: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    container_logs: str = ""
    artifacts: Optional[ArtifactSet] = None
    isolation: Optional[dict] = None
    error: Optional[str] = None

    @property
    def strace_log(self) -> str:
        """Path to the syscall log, or "" when none was captured."""
        if self.artifacts and self.artifacts.strace_log:
            return str(self.artifacts.strace_log)
        return ""

    @property
    def tcpdump_pcap(self) -> str:
        if self.artifacts and self.artifacts.pcap:
            return str(self.artifacts.pcap)
        return ""

    @property
    def inotify_log(self) -> str:
        if self.artifacts and self.artifacts.inotify_log:
            return str(self.artifacts.inotify_log)
        return ""

    def to_dict(self) -> dict:
        return {
            "container_id": self.container_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "strace_log": self.strace_log,
            "tcpdump_pcap": self.tcpdump_pcap,
            "inotify_log": self.inotify_log,
            "container_logs": self.container_logs[:5000],
            "artifacts": self.artifacts.to_dict() if self.artifacts else None,
            "isolation": self.isolation,
            "error": self.error,
        }


class ContainerManager:
    """Manage Docker containers for malware sandboxing.

    Full lifecycle: probe isolation -> ensure network -> create container ->
    copy sample in -> execute under the tracer -> enforce timeout -> pull
    artifacts -> destroy container.
    """

    def __init__(self, config: Optional[ContainerConfig] = None) -> None:
        self.config = config or ContainerConfig()
        self._client: Optional[docker_sdk.DockerClient] = None
        self._isolation: Optional[IsolationProbe] = None

    # ------------------------------------------------------------------ setup

    @property
    def client(self) -> docker_sdk.DockerClient:
        """Lazy-initialized Docker client."""
        if self._client is None:
            if not HAS_DOCKER:
                raise RuntimeError("docker SDK not installed")
            self._client = docker_sdk.from_env()
        return self._client

    @property
    def isolation(self) -> IsolationProbe:
        """Cached isolation probe for this host."""
        if self._isolation is None:
            try:
                self._isolation = probe_isolation(
                    client=self.client,
                    preferred_runtime=self.config.preferred_runtime,
                )
            except Exception as e:  # noqa: BLE001
                probe = IsolationProbe(probed=True)
                probe.errors.append(f"Isolation probe failed: {e}")
                self._isolation = probe
        return self._isolation

    def readiness(self) -> tuple[bool, list[str]]:
        """Check whether a detonation can actually run, and say why not.

        This is deliberately stricter than "the image exists". Every previous
        silent failure in this class started with a readiness check that
        answered a narrower question than the one that mattered.
        """
        problems: list[str] = []

        if not HAS_DOCKER:
            return False, ["docker SDK is not installed (pip install docker)"]

        try:
            self.client.ping()
        except Exception as e:  # noqa: BLE001
            return False, [f"Docker daemon unreachable: {e}"]

        try:
            self.client.images.get(self.config.image)
        except docker_sdk.errors.ImageNotFound:
            problems.append(
                f"Sandbox image {self.config.image!r} not built — run: hatchery build"
            )
        except Exception as e:  # noqa: BLE001
            problems.append(f"Could not inspect sandbox image: {e}")

        probe = self.isolation
        if probe.runtime is None:
            problems.append("No usable container runtime reported by the daemon")

        if not probe.is_security_boundary and probe.selected is not None:
            # Not a blocker — but the operator must know.
            logger.warning(
                "Running at isolation tier %d (%s): %s",
                int(probe.tier), probe.selected.name, probe.selected.boundary,
            )

        return (not problems), problems

    def is_available(self) -> bool:
        """True when a detonation can actually run end to end."""
        ok, _ = self.readiness()
        return ok

    # ------------------------------------------------------------------- image

    def build_image(self, docker_dir: Optional[Path] = None) -> str:
        """Build the sandbox Docker image.

        Args:
            docker_dir: Directory containing the Dockerfile.
                Defaults to engine/sandbox/docker/.

        Returns:
            Image tag string.
        """
        if docker_dir is None:
            docker_dir = Path(__file__).parent / "docker"

        if not docker_dir.exists():
            raise FileNotFoundError(f"Docker directory not found: {docker_dir}")

        logger.info("Building sandbox image from %s", docker_dir)
        try:
            image, build_logs = self.client.images.build(
                path=str(docker_dir),
                tag=SANDBOX_IMAGE,
                rm=True,
            )
            for log_entry in build_logs:
                if "stream" in log_entry:
                    logger.debug("docker build: %s", log_entry["stream"].strip())
            logger.info("Built sandbox image: %s", image.id)
            return SANDBOX_IMAGE
        except docker_sdk.errors.BuildError as e:
            logger.error("Docker build failed: %s", e)
            raise
        except docker_sdk.errors.APIError as e:
            logger.error("Docker API error: %s", e)
            raise

    # -------------------------------------------------------------- internals

    def _load_seccomp(self) -> Optional[dict]:
        """Load the seccomp profile.

        Note: this profile is *guest hardening*, not the sample/host boundary.
        At isolation tier 1 the boundary does not exist regardless of seccomp,
        and the profile must permit ``ptrace`` or the tracer cannot attach.
        """
        if SECCOMP_PATH.exists():
            try:
                return json.loads(SECCOMP_PATH.read_text())
            except json.JSONDecodeError as e:
                logger.error("Failed to parse seccomp profile: %s", e)
                return None
        return None

    def _ensure_network(self) -> None:
        """Create the sandbox network if it is missing.

        Previously the network was referenced but never created, so container
        creation failed on every fresh install. The name comes from the config
        so the network created and the network requested cannot drift apart.
        """
        from engine.sandbox.network import NetworkConfig, NetworkIsolator

        isolator = NetworkIsolator(NetworkConfig(name=self.config.network_name))
        isolator.ensure_network()

    def _prepare_sample_in_container(
        self, container: Container, sample_path: Path, target_name: str
    ) -> None:
        """Copy the sample into the container as a non-executable-by-default blob."""
        sample_data = sample_path.read_bytes()

        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=target_name)
            info.size = len(sample_data)
            info.mode = 0o755
            tar.addfile(info, BytesIO(sample_data))
        tar_stream.seek(0)

        if not container.put_archive("/hatchery/sample/", tar_stream):
            raise RuntimeError(f"Failed to copy sample into container: {sample_path}")

        logger.info("Copied sample %s into container", target_name)

    # ---------------------------------------------------------------- execute

    def execute(
        self,
        sample_path: Path,
        results_dir: Path,
        sample_name: Optional[str] = None,
    ) -> ContainerResult:
        """Detonate a sample in the sandbox container.

        Args:
            sample_path: Path to the sample on the host.
            results_dir: Directory to write behavioral artifacts into.
            sample_name: Override filename in container.

        Returns:
            ContainerResult, including the isolation tier used and a complete
            account of which artifacts were and were not recovered.
        """
        result = ContainerResult()

        ready, problems = self.readiness()
        result.isolation = self.isolation.to_dict()
        if not ready:
            result.status = "error"
            result.error = "Sandbox not ready: " + "; ".join(problems)
            return result

        if not sample_path.exists():
            result.status = "error"
            result.error = f"Sample not found: {sample_path}"
            return result

        results_dir.mkdir(parents=True, exist_ok=True)
        target_name = sample_name or sample_path.name

        probe = self.isolation
        runtime = probe.runtime
        seccomp = self.config.seccomp_profile or self._load_seccomp()

        # docker-py dropped `seccomp=` as a create() kwarg; the profile now has to
        # travel through `security_opt` as inline JSON, which is what the Docker
        # API's SecurityOpt field expects.
        security_opt = ["no-new-privileges:true"]
        if seccomp is not None:
            security_opt.append(f"seccomp={json.dumps(seccomp)}")

        # A Linux guest gets a Linux-looking environment. Faking Windows
        # artifacts inside a Linux kernel is a stronger tell than faking
        # nothing: the sample sees uname/KVM and a Windows env in one breath.
        env_vars = {
            "HISTFILE": "/home/user/.bash_history",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "HATCHERY_TIER": str(int(probe.tier)),
            "HATCHERY_TIMEOUT": str(self.config.timeout),
        }
        env_vars.update(self.config.extra_env)
        env_list = [f"{k}={v}" for k, v in env_vars.items()]

        container: Optional[Container] = None
        try:
            self._ensure_network()

            logger.info(
                "Creating sandbox container for %s (runtime=%s, tier=%d)",
                target_name, runtime, int(probe.tier),
            )
            container = self.client.containers.create(
                image=self.config.image,
                command=f"/hatchery/sample/{target_name}",
                hostname=self.config.hostname,
                environment=env_list,
                mem_limit=self.config.memory_limit,
                nano_cpus=int(self.config.cpu_limit * 1e9),
                pids_limit=self.config.pids_limit,
                network=self.config.network_name,
                runtime=runtime,
                # tcpdump needs a raw socket; nothing else here does.
                cap_add=["NET_RAW"],
                security_opt=security_opt,
                detach=True,
                stdin_open=False,
                tty=False,
            )

            result.container_id = container.id
            result.start_time = datetime.now(timezone.utc)

            self._prepare_sample_in_container(container, sample_path, target_name)

            container.start()
            logger.info(
                "Container %s started — detonating %s", container.id[:12], target_name
            )

            try:
                return_code = container.wait(timeout=self.config.timeout)
                result.exit_code = (
                    return_code.get("StatusCode")
                    if isinstance(return_code, dict)
                    else return_code
                )
                result.status = "completed"
                logger.info(
                    "Container %s exited with code %s",
                    container.id[:12], result.exit_code,
                )
            except Exception:  # noqa: BLE001 - Docker raises on wait timeout
                logger.warning(
                    "Container %s timed out after %ds — killing",
                    container.id[:12], self.config.timeout,
                )
                container.kill()
                result.status = "timeout"

            result.end_time = datetime.now(timezone.utc)
            if result.start_time and result.end_time:
                result.duration_seconds = (
                    result.end_time - result.start_time
                ).total_seconds()

            try:
                result.container_logs = container.logs().decode("utf-8", errors="replace")
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to read container logs: %s", e)

            # Recover artifacts while the container still exists. A missing
            # or empty behavioral source is a finding, not a warning to bury.
            try:
                result.artifacts = collect_artifacts(container, results_dir)
                if result.artifacts.errors:
                    for problem in result.artifacts.errors:
                        logger.warning("Artifact problem: %s", problem)
                            # Only fatal when we got nothing at all.
                if not result.artifacts.has_any_behavior:
                    result.error = (
                        "No behavioral data was recovered from this run — "
                        "treat the result as inconclusive, not clean."
                    )
            except Exception as e:  # noqa: BLE001
                result.status = "error"
                result.error = f"Artifact collection failed: {e}"
                logger.exception("Artifact collection failed")

        except docker_sdk.errors.ImageNotFound:
            result.status = "error"
            result.error = (
                f"Sandbox image {self.config.image!r} not found — run: hatchery build"
            )
        except docker_sdk.errors.APIError as e:
            result.status = "error"
            result.error = f"Docker API error: {e}"
            logger.error("Docker API error during detonation: %s", e)
        except Exception as e:  # noqa: BLE001
            result.status = "error"
            result.error = f"Unexpected error: {e}"
            logger.exception("Sandbox execution failed")

        finally:
            # `container` may still be None if creation itself failed. Guard it
            # so cleanup can never mask the real exception.
            if container is not None:
                try:
                    container.remove(force=True)
                    logger.info("Container %s removed", container.id[:12])
                except Exception as e:  # noqa: BLE001
                    logger.warning("Container cleanup failed: %s", e)

        return result
