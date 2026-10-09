"""Tests for behavioral artifact collection."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from engine.sandbox.artifacts import (
    ARTIFACT_SPECS,
    ArtifactSet,
    collect_artifacts,
    extract_tar_stream,
)


def _tar_bytes(members: dict[str, bytes]) -> list[bytes]:
    """Build a tar archive in memory and return it as one chunk."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return [buffer.getvalue()]


def test_extract_unpacks_tar_rather_than_writing_the_archive(tmp_path: Path):
    """get_archive returns a tar stream; writing those bytes to `strace.log`
    yields a tar file with a misleading name, which every downstream parser
    then reads as garbage. The extraction must actually unpack."""
    written = extract_tar_stream(
        _tar_bytes({"strace.log": b"execve(...) = 0\n"}), tmp_path
    )
    target = tmp_path / "strace.log"
    assert target.exists()
    assert target.read_bytes() == b"execve(...) = 0\n"
    assert target in written
    # And it must not be a tar archive itself.
    assert not tarfile.is_tarfile(target)


def test_extract_refuses_path_traversal(tmp_path: Path):
    """A hostile archive must not be able to write outside the target dir."""
    escape_target = tmp_path.parent / "escaped.txt"
    if escape_target.exists():
        escape_target.unlink()

    extract_tar_stream(_tar_bytes({"../../escaped.txt": b"pwned"}), tmp_path / "sub")

    assert not escape_target.exists()


def test_extract_creates_dest_if_missing(tmp_path: Path):
    dest = tmp_path / "a" / "b"
    extract_tar_stream(_tar_bytes({"f.txt": b"x"}), dest)
    assert (dest / "f.txt").exists()


def test_artifact_specs_paths_are_absolute_and_distinct():
    paths = [spec.container_path for spec in ARTIFACT_SPECS]
    assert len(paths) == len(set(paths))
    for spec in ARTIFACT_SPECS:
        assert spec.container_path.startswith("/hatchery/output")


def test_artifact_specs_match_the_entrypoint():
    """The container paths here are a contract with entrypoint.sh. If someone
    renames a directory in one place, this test is the thing that notices."""
    entrypoint = (
        Path(__file__).resolve().parents[1]
        / "engine"
        / "sandbox"
        / "docker"
        / "entrypoint.sh"
    ).read_text()
    for spec in ARTIFACT_SPECS:
        # entrypoint.sh writes through $OUTPUT_DIR, so compare against that form.
        expected = spec.container_path.replace("/hatchery/output/", "$OUTPUT_DIR/")
        assert expected in entrypoint, f"{expected} not referenced by entrypoint.sh"


class FakeContainer:
    """Stand-in whose get_archive behaves like the Docker SDK."""

    def __init__(self, files: dict[str, bytes] | None = None) -> None:
        self.files = files or {}

    def get_archive(self, path: str):  # noqa: ANN201
        from docker.errors import NotFound

        if path in self.files:
            return iter(_tar_bytes({Path(path).name: self.files[path]})), {"name": path}
        if any(k.startswith(path.rstrip("/") + "/") for k in self.files):
            members = {
                k[len(path.rstrip("/")) + 1:]: v
                for k, v in self.files.items()
                if k.startswith(path.rstrip("/") + "/")
            }
            return iter(_tar_bytes(members)), {"name": path}
        raise NotFound(f"no such path {path}")


def test_collect_artifacts_reports_what_was_found(tmp_path: Path):
    container = FakeContainer(
        {
            "/hatchery/output/strace/strace.log": b"execve() = 0\n",
            "/hatchery/output/inotify/inotify.log": b"2026-01-01T00:00:00 /tmp/x CREATE\n",
        }
    )
    result = collect_artifacts(container, tmp_path)

    assert isinstance(result, ArtifactSet)
    assert result.strace_log is not None
    assert result.strace_log.read_bytes() == b"execve() = 0\n"
    assert result.inotify_log is not None
    assert result.has_any_behavior


def test_collect_artifacts_flags_an_empty_behavioral_source(tmp_path: Path):
    container = FakeContainer({"/hatchery/output/strace/strace.log": b""})
    result = collect_artifacts(container, tmp_path)

    assert "strace_log" in result.found
    assert any("empty" in e for e in result.errors)
    assert not result.has_any_behavior


def test_collect_artifacts_says_inconclusive_when_nothing_is_recovered(tmp_path: Path):
    result = collect_artifacts(FakeContainer({}), tmp_path)

    assert not result.has_any_behavior
    assert set(result.missing) == {spec.key for spec in ARTIFACT_SPECS}
    assert any("No behavioral data recovered" in e for e in result.errors)


def test_artifact_set_serializes_for_the_bundle(tmp_path: Path):
    container = FakeContainer({"/hatchery/output/strace/strace.log": b"x"})
    result = collect_artifacts(container, tmp_path)
    data = result.to_dict()

    assert "found" in data
    assert "missing" in data
    assert data["has_any_behavior"] is True
    assert isinstance(data["dropped_files"], list)


def test_dropped_files_reads_from_the_recovered_directory(tmp_path: Path):
    dropped = tmp_path / "dropped"
    dropped.mkdir()
    (dropped / "evil.sh").write_text("#!/bin/sh\n")
    result = ArtifactSet(root=tmp_path, found={"dropped_dir": dropped})

    assert [p.name for p in result.dropped_files] == ["evil.sh"]
