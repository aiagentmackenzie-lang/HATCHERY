"""Behavioral artifact collection — copy-based, host-agnostic.

The sandbox writes its artifacts inside the container filesystem. This
module pulls them out over the Docker API and unpacks them into the run
directory, then reports precisely what was found and what was missing.

Why copy-based rather than a bind mount: a bind mount assumes the Docker
daemon can see a path on *this* machine. That silently breaks for remote
daemons, Docker-in-Docker, and microVM-backed runtimes. Copying works
everywhere and gives us one place to verify the artifacts exist.

Why the extraction is explicit about the tar layer: ``Container.get_archive``
returns a **tar stream**, not a file. Writing those bytes straight to
``strace.log`` produces a tar archive with a misleading name — which is
exactly the class of bug that makes a sandbox look like it works while every
downstream parser reads nothing.
"""

from __future__ import annotations

import logging
import tarfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArtifactSpec:
    """One artifact the sandbox is expected to produce."""

    key: str
    container_path: str
    relative_target: str
    required: bool
    is_dir: bool = False


# Container paths must match engine/sandbox/docker/entrypoint.sh exactly.
# Both sides reference these via ARTIFACT_SPECS / the same literal paths.
ARTIFACT_SPECS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec("strace_log", "/hatchery/output/strace/strace.log", "strace/strace.log", True),
    ArtifactSpec("inotify_log", "/hatchery/output/inotify/inotify.log", "inotify/inotify.log", False),
    ArtifactSpec("pcap", "/hatchery/output/tcpdump/capture.pcap", "tcpdump/capture.pcap", False),
    ArtifactSpec("dropped_dir", "/hatchery/output/dropped", "dropped", False, is_dir=True),
    ArtifactSpec("exec_log", "/hatchery/output/exec/exec.log", "exec/exec.log", False),
)


@dataclass
class ArtifactSet:
    """What was actually recovered from a sandbox run."""

    root: Path
    found: dict[str, Path] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def strace_log(self) -> Optional[Path]:
        return self.found.get("strace_log")

    @property
    def pcap(self) -> Optional[Path]:
        return self.found.get("pcap")

    @property
    def inotify_log(self) -> Optional[Path]:
        return self.found.get("inotify_log")

    @property
    def dropped_dir(self) -> Optional[Path]:
        return self.found.get("dropped_dir")

    @property
    def dropped_files(self) -> list[Path]:
        dropped = self.dropped_dir
        if not dropped or not dropped.exists():
            return []
        return sorted(p for p in dropped.rglob("*") if p.is_file())

    @property
    def has_any_behavior(self) -> bool:
        """True when at least one behavioral source produced content."""
        for path in (self.strace_log, self.inotify_log, self.pcap):
            if path and path.exists() and path.stat().st_size > 0:
                return True
        return bool(self.dropped_files)

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "found": {k: str(v) for k, v in self.found.items()},
            "missing": list(self.missing),
            "errors": list(self.errors),
            "dropped_files": [str(p) for p in self.dropped_files],
            "has_any_behavior": self.has_any_behavior,
        }

    def describe(self) -> str:
        if not self.missing and not self.errors:
            return f"{len(self.found)} artifact(s) recovered"
        parts = [f"{len(self.found)} artifact(s) recovered"]
        if self.missing:
            parts.append(f"missing: {', '.join(self.missing)}")
        if self.errors:
            parts.append(f"errors: {'; '.join(self.errors)}")
        return "; ".join(parts)


def extract_tar_stream(chunks, dest_dir: Path) -> list[Path]:
    """Unpack a Docker ``get_archive`` tar stream into ``dest_dir``.

    Member names are sanitised and extraction uses the ``data`` filter, so a
    hostile archive cannot write outside ``dest_dir``.

    Args:
        chunks: Iterable of bytes chunks as returned by the Docker SDK.
        dest_dir: Directory to extract into.

    Returns:
        Paths written.
    """
    buffer = BytesIO()
    for chunk in chunks:
        buffer.write(chunk)
    buffer.seek(0)

    dest_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    with tarfile.open(fileobj=buffer, mode="r") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            # Never trust a member name: strip anchors and traversal.
            name = member.name.lstrip("/")
            if ".." in Path(name).parts:
                logger.warning("Refusing tar member with traversal: %r", member.name)
                continue
            member.name = name
            tar.extract(member, path=dest_dir, filter="data")
            written.append(dest_dir / name)

    return written


def pull_artifact(container, spec: ArtifactSpec, run_dir: Path) -> tuple[Optional[Path], Optional[str]]:
    """Copy one artifact out of a stopped container.

    Returns:
        ``(path, None)`` on success, ``(None, reason)`` when absent or failed.
    """
    from docker.errors import NotFound

    target = run_dir / spec.relative_target
    try:
        stream, _stat = container.get_archive(spec.container_path)
    except NotFound:
        return None, f"{spec.container_path} not present in container"
    except Exception as e:  # noqa: BLE001
        return None, f"{spec.container_path}: {e}"

    try:
        written = extract_tar_stream(stream, target if spec.is_dir else target.parent)
    except tarfile.TarError as e:
        return None, f"{spec.container_path}: not a readable archive ({e})"

    if spec.is_dir:
        if not written:
            return None, f"{spec.container_path}: empty"
        return target, None

    if target.exists():
        return target, None
    # The archive's member name should match the basename; fall back to it.
    candidates = [p for p in written if p.name == Path(spec.container_path).name]
    if candidates:
        return candidates[0], None
    return None, f"{spec.container_path}: extracted but final path not found"


def collect_artifacts(container, run_dir: Path) -> ArtifactSet:
    """Pull every expected artifact out of a container into ``run_dir``.

    Args:
        container: A stopped ``docker.models.containers.Container``.
        run_dir: Directory to write artifacts into.

    Returns:
        An :class:`ArtifactSet` describing what was recovered.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    result = ArtifactSet(root=run_dir)

    for spec in ARTIFACT_SPECS:
        path, reason = pull_artifact(container, spec, run_dir)
        if path is None:
            result.missing.append(spec.key)
            if spec.required and reason:
                result.errors.append(reason)
            logger.warning("Artifact %s not recovered: %s", spec.key, reason)
            continue
        result.found[spec.key] = path

        # An empty file is as good as missing for a behavioral source.
        if not spec.is_dir and path.stat().st_size == 0:
            result.errors.append(f"{spec.key} recovered but empty")

    if not result.has_any_behavior:
        result.errors.append(
            "No behavioral data recovered from the run: the container produced "
            "no syscall log, no filesystem events and no network capture."
        )

    return result


def collect_artifacts_via_volume(
    client,
    volume_name: str,
    run_dir: Path,
    image: str,
    helper_runtime: str = "runc",
    timeout: int = 60,
) -> ArtifactSet:
    """Recover artifacts from a named Docker volume through a short sidecar.

    Why this route (docs/DECISIONS.md D17): at tier 2 gVisor keeps the container
    rootfs overlay in memory, so ``get_archive`` on the sandbox container cannot
    see files the sample wrote. A **named volume** mounted at
    ``/hatchery/output`` is a real host-backed mount proxied by gVisor's gofer,
    so its contents survive the sandbox exiting. A short ``runc`` sidecar mounts
    the same volume and ``get_archive`` copies the files out — still copy-based,
    never a host bind mount (D5).

    ``runsc tar rootfs-upper`` was tested first and works **only while the
    sandbox is alive**; it fails with "file does not exist" once the container
    has exited, which is exactly when the engine recovers artifacts. This route
    is the one that works after exit.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    result = ArtifactSet(root=run_dir)

    sidecar = None
    try:
        sidecar = client.containers.create(
            image=image,
            entrypoint=["/bin/true"],
            runtime=helper_runtime,
            volumes={volume_name: {"bind": "/hatchery/output", "mode": "rw"}},
            detach=True,
            network_mode="none",
        )
        sidecar.start()
        sidecar.wait(timeout=timeout)
    except Exception as e:  # noqa: BLE001 - any failure is reported, not hidden
        result.errors.append(
            f"could not read the tier-2 output volume {volume_name!r} through a "
            f"{helper_runtime} sidecar: {e}"
        )
        for spec in ARTIFACT_SPECS:
            result.missing.append(spec.key)
        if sidecar is not None:
            _remove_quietly(sidecar)
        return result

    try:
        result = collect_artifacts(sidecar, run_dir)
    finally:
        _remove_quietly(sidecar)

    return result


def _remove_quietly(container) -> None:
    try:
        container.remove(force=True)
    except Exception as e:  # noqa: BLE001 - cleanup must not mask the real result
        logger.warning("Sidecar cleanup failed: %s", e)
