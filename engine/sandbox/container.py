"""Docker container lifecycle management for malware detonation.

Creates isolated containers, executes samples under strace supervision,
enforces timeouts, and captures behavioral artifacts after execution.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional

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
DEFAULT_CPU_LIMIT = 0.5       # 50% of one core
DEFAULT_MEMORY_LIMIT = "512m" # 512MB RAM
SANDBOX_IMAGE = "hatchery-sandbox:latest"
SECCOMP_PATH = Path(__file__).parent / "seccomp.json"

# Artifact subdirectory names in the results directory
ARTIFACT_DIRS = ["strace", "tcpdump", "inotify", "filesystem", "dropped"]


@dataclass
class ContainerConfig:
    """Configuration for a sandbox container."""
    image: str = SANDBOX_IMAGE
    timeout: int = DEFAULT_TIMEOUT
    cpu_limit: float = DEFAULT_CPU_LIMIT
    memory_limit: str = DEFAULT_MEMORY_LIMIT
    network_name: str = "hatchery-fake"
    seccomp_profile: Optional[dict] = None
    hostname: str = "DESKTOP-WIN10"
    extra_env: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "image": self.image,
            "timeout": self.timeout,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "network_name": self.network_name,
            "hostname": self.hostname,
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
    strace_log: str = ""
    tcpdump_pcap: str = ""
    inotify_log: str = ""
    container_logs: str = ""
    artifacts_path: Optional[Path] = None
    error: Optional[str] = None

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
            "container_logs": self.container_logs[:5000],  # Cap log size
            "artifacts_path": str(self.artifacts_path) if self.artifacts_path else None,
            "error": self.error,
        }


class ContainerManager:
    """Manage Docker containers for malware sandboxing.

    Handles the full lifecycle: build image → create container → execute
    sample → enforce timeout → capture artifacts → cleanup.
    """

    def __init__(self, config: Optional[ContainerConfig] = None) -> None:
        self.config = config or ContainerConfig()
        self._client: Optional[docker_sdk.DockerClient] = None

    @property
    def client(self) -> docker_sdk.DockerClient:
        """Lazy-initialized Docker client."""
        if self._client is None:
            if not HAS_DOCKER:
                raise RuntimeError("docker SDK not installed")
            self._client = docker_sdk.from_env()
        return self._client

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

    def _load_seccomp(self) -> Optional[dict]:
        """Load the seccomp profile for container isolation."""
        seccomp_path = SECCOMP_PATH
        if seccomp_path.exists():
            try:
                return json.loads(seccomp_path.read_text())
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse seccomp profile: %s", e)
        return None

    def _prepare_sample_in_container(
        self, container: Container, sample_path: Path, target_name: str
    ) -> None:
        """Copy the sample file into the container.

        Args:
            container: Running Docker container.
            sample_path: Path to the sample on the host.
            target_name: Filename inside the container.
        """
        sample_data = sample_path.read_bytes()

        # Create a tar archive in memory (Docker API requires tar for put_archive)
        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=target_name)
            info.size = len(sample_data)
            info.mode = 0o755
            tar.addfile(info, BytesIO(sample_data))
        tar_stream.seek(0)

        success = container.put_archive(
            "/hatchery/sample/",
            tar_stream,
        )
        if not success:
            raise RuntimeError(f"Failed to copy sample into container: {sample_path}")

        logger.info("Copied sample %s into container", target_name)

    def _extract_artifacts(
        self, container: Container, results_dir: Path
    ) -> dict[str, str]:
        """Extract behavioral artifacts from a completed container.

        Pulls strace logs, pcap files, inotify logs, and dropped files.

        Args:
            container: The (stopped) container.
            results_dir: Directory to store artifacts on the host.

        Returns:
            Dict mapping artifact type to file path.
        """
        artifacts: dict[str, str] = {}

        for subdir in ARTIFACT_DIRS:
            (results_dir / subdir).mkdir(parents=True, exist_ok=True)

        # Extract strace log
        try:
            strm, stat = container.get_archive("/hatchery/output/strace.log")
            if strm:
                with open(results_dir / "strace" / "strace.log", "wb") as f:
                    for chunk in strm:
                        f.write(chunk)
                artifacts["strace_log"] = str(results_dir / "strace" / "strace.log")
                logger.info("Extracted strace log")
        except Exception as e:
            logger.warning("Failed to extract strace log: %s", e)

        # Extract tcpdump pcap
        try:
            strm, stat = container.get_archive("/hatchery/output/capture.pcap")
            if strm:
                with open(results_dir / "tcpdump" / "capture.pcap", "wb") as f:
                    for chunk in strm:
                        f.write(chunk)
                artifacts["tcpdump_pcap"] = str(results_dir / "tcpdump" / "capture.pcap")
                logger.info("Extracted PCAP")
        except Exception as e:
            logger.warning("Failed to extract PCAP: %s", e)

        # Extract inotify log
        try:
            strm, stat = container.get_archive("/hatchery/output/inotify.log")
            if strm:
                with open(results_dir / "inotify" / "inotify.log", "wb") as f:
                    for chunk in strm:
                        f.write(chunk)
                artifacts["inotify_log"] = str(results_dir / "inotify" / "inotify.log")
                logger.info("Extracted inotify log")
        except Exception as e:
            logger.warning("Failed to extract inotify log: %s", e)

        # Extract dropped files directory
        try:
            strm, stat = container.get_archive("/hatchery/output/dropped/")
            if strm:
                with open(results_dir / "dropped" / "dropped.tar", "wb") as f:
                    for chunk in strm:
                        f.write(chunk)
                artifacts["dropped_files"] = str(results_dir / "dropped" / "dropped.tar")
                logger.info("Extracted dropped files")
        except Exception as e:
            logger.warning("Failed to extract dropped files: %s", e)

        return artifacts

    def execute(
        self,
        sample_path: Path,
        results_dir: Path,
        sample_name: Optional[str] = None,
    ) -> ContainerResult:
        """Execute a sample in the sandbox container.

        Full lifecycle: create container → copy sample → run with strace
        → enforce timeout → capture artifacts → cleanup.

        Args:
            sample_path: Path to the malware sample on the host.
            results_dir: Directory to store behavioral artifacts.
            sample_name: Override filename in container (defaults to original name).

        Returns:
            ContainerResult with execution details and artifact paths.
        """
        if not HAS_DOCKER:
            return ContainerResult(
                status="error",
                error="docker SDK not installed — cannot run sandbox",
            )

        if not sample_path.exists():
            return ContainerResult(
                status="error",
                error=f"Sample not found: {sample_path}",
            )

        results_dir.mkdir(parents=True, exist_ok=True)
        target_name = sample_name or sample_path.name
        result = ContainerResult()

        # Load seccomp profile
        seccomp = self.config.seccomp_profile or self._load_seccomp()

        # Anti-evasion environment variables
        env_vars = {
            "COMPUTERNAME": "DESKTOP-WIN10",
            "USERNAME": "user",
            "USERPROFILE": "C:\\Users\\user",
            "HOMEPATH": "C:\\Users\\user",
            "TEMP": "C:\\Users\\user\\AppData\\Local\\Temp",
            "TMP": "C:\\Users\\user\\AppData\\Local\\Temp",
            "PROGRAMFILES": "C:\\Program Files",
            "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
            "SYSTEMROOT": "C:\\Windows",
            "OS": "Windows_NT",
            "NUMBER_OF_PROCESSORS": "4",
        }
        env_vars.update(self.config.extra_env)

        # Convert to Docker env format
        env_list = [f"{k}={v}" for k, v in env_vars.items()]

        try:
            # Create and start container
            logger.info("Creating sandbox container for %s", target_name)
            container = self.client.containers.create(
                image=self.config.image,
                command=f"/hatchery/entrypoint.sh /hatchery/sample/{target_name}",
                hostname=self.config.hostname,
                environment=env_list,
                mem_limit=self.config.memory_limit,
                nano_cpus=int(self.config.cpu_limit * 1e9),
                network=self.config.network_name,
                seccomp=seccomp,
                detach=True,
                stdin_open=False,
                tty=False,
                volumes={
                    str(results_dir.resolve()): {
                        "bind": "/hatchery/output",
                        "mode": "rw",
                    },
                },
            )

            result.container_id = container.id
            result.start_time = datetime.now(timezone.utc)

            # Copy sample into container
            self._prepare_sample_in_container(container, sample_path, target_name)

            # Start the container
            container.start()
            logger.info("Container %s started — detonating %s", container.id[:12], target_name)

            # Wait for completion or timeout
            try:
                return_code = container.wait(timeout=self.config.timeout)
                # Docker SDK returns a dict with 'StatusCode'
                if isinstance(return_code, dict):
                    result.exit_code = return_code.get("StatusCode")
                else:
                    result.exit_code = return_code

                result.status = "completed"
                logger.info("Container %s exited with code %s", container.id[:12], result.exit_code)

            except Exception:
                # Timeout — kill the container
                logger.warning("Container %s timed out after %ds — killing", container.id[:12], self.config.timeout)
                container.kill()
                result.status = "timeout"

            result.end_time = datetime.now(timezone.utc)
            if result.start_time and result.end_time:
                result.duration_seconds = (result.end_time - result.start_time).total_seconds()

            # Get container logs
            try:
                result.container_logs = container.logs().decode("utf-8", errors="replace")
            except Exception as e:
                logger.warning("Failed to get container logs: %s", e)

            # Extract artifacts
            try:
                artifacts = self._extract_artifacts(container, results_dir)
                result.strace_log = artifacts.get("strace_log", "")
                result.tcpdump_pcap = artifacts.get("tcpdump_pcap", "")
                result.inotify_log = artifacts.get("inotify_log", "")
            except Exception as e:
                logger.warning("Artifact extraction failed: %s", e)

            result.artifacts_path = results_dir

        except docker_sdk.errors.ImageNotFound:
            result.status = "error"
            result.error = f"Sandbox image '{self.config.image}' not found — run build_image() first"
        except docker_sdk.errors.APIError as e:
            result.status = "error"
            result.error = f"Docker API error: {e}"
        except Exception as e:
            result.status = "error"
            result.error = f"Unexpected error: {e}"
            logger.exception("Sandbox execution failed")

        finally:
            # Always clean up the container
            try:
                container.remove(force=True)
                logger.info("Container %s removed", container.id[:12])
            except Exception:
                pass

        return result

    def is_available(self) -> bool:
        """Check if Docker is available and the sandbox image exists."""
        if not HAS_DOCKER:
            return False
        try:
            self.client.images.get(self.config.image)
            return True
        except docker_sdk.errors.ImageNotFound:
            return False
        except Exception:
            return False