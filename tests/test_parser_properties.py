"""What each parser promises about hostile input, as a property (D39).

Hypothesis is a **dev extra only**: the runtime never imports it. The properties
are the contract the funnel relies on:

* only the parser's own documented error escapes it;
* a bounded reader's window stays inside the artifact and inside its caps;
* nothing allocates or iterates in proportion to a *declared* size;
* a document loader raises only its documented error.

The examples are deliberately small (``max_examples``) so the suite stays a
minute, not an afternoon. The point is a shape that fails the old behaviour by a
wide margin, not a coverage number.
"""

from __future__ import annotations

import json
import tempfile
from contextlib import contextmanager
import zipfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from engine.guard import DOCUMENTED, guarded  # noqa: E402
from engine.intake.delivery import (  # noqa: E402
    MAX_CHILDREN,
    MAX_DEPTH,
    MAX_TOTAL_BYTES,
    _safe_member_name,
    extract_delivery,
)
from engine.intake.elf_analyzer import ELFAnalyzer, ELFResult  # noqa: E402
from engine.intake.ole import CompoundFile, OleError  # noqa: E402
from engine.intake.pe_analyzer import PEAnalyzer, PEResult  # noqa: E402
from engine.intake.rtf import MAX_GROUP_DEPTH, RtfError, parse_rtf  # noqa: E402
from engine.intake.strings import StringClassification, StringExtractor  # noqa: E402
from engine.monitor.strace_parser import StraceParser  # noqa: E402

#: ``@given`` tests below take **no pytest fixtures**. pytest 9 reads a wrapped
#: function's signature through ``__wrapped__``, so a fixture parameter reappears
#: beside the generated ones and is looked up as a fixture. A temporary
#: directory created inside the body is both simpler and version-proof.
SETTINGS = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)

OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


@contextmanager
def temporary_directory():
    with tempfile.TemporaryDirectory(prefix="hatchery-property-") as name:
        yield Path(name)


# ---------------------------------------------------------------------------
# The funnel
# ---------------------------------------------------------------------------


@SETTINGS
@given(st.text(max_size=120))
def test_guarded_turns_any_unexpected_exception_into_one_named_entry(message: str):
    errors: list[str] = []

    def parse():
        raise RuntimeError(message)

    assert guarded("stage", errors, parse, fallback_factory=dict) == {}
    assert errors == [f"stage: unexpected RuntimeError: {message}"]


@SETTINGS
@given(st.text(max_size=60))
def test_guarded_never_flattens_a_documented_error(message: str):
    errors: list[str] = []

    def parse():
        raise OleError(message)

    with pytest.raises(OleError):
        guarded("stage", errors, parse, fallback_factory=dict)
    assert errors == []
    assert OleError in DOCUMENTED


# ---------------------------------------------------------------------------
# Binary analysers — only their own result, never an escape
# ---------------------------------------------------------------------------


@SETTINGS
@given(st.binary(max_size=4096))
def test_the_pe_analyser_returns_a_result_for_any_bytes(blob: bytes):
    with temporary_directory() as tmp_path:
        path = _write(tmp_path, "sample.bin", b"MZ" + blob)
        result = PEAnalyzer().analyze(path)

    assert isinstance(result, PEResult)
    json.dumps(result.to_dict())  # a section that cannot be serialised is not a section


@SETTINGS
@given(st.binary(max_size=4096))
def test_the_elf_analyser_returns_a_result_for_any_bytes(blob: bytes):
    with temporary_directory() as tmp_path:
        path = _write(tmp_path, "sample.bin", b"\x7fELF" + blob)
        result = ELFAnalyzer().analyze(path)

    assert isinstance(result, ELFResult)
    json.dumps(result.to_dict())


# ---------------------------------------------------------------------------
# Readers with their own error type
# ---------------------------------------------------------------------------


@SETTINGS
@given(st.binary(max_size=4096))
def test_the_ole_reader_raises_only_ole_error(body: bytes):
    data = OLE_MAGIC + body
    try:
        cfb = CompoundFile(data, max_streams=32, max_stream_bytes=1024)
    except OleError:
        return
    assert len(cfb.streams) <= 32
    assert sum(entry.size for entry in cfb.streams) <= 32 * 1024


@SETTINGS
@given(st.text(alphabet="{}abcdef\\* 0123456789\n", max_size=2048))
def test_the_rtf_reader_raises_only_rtf_error(text: str):
    data = ("{\\rtf1" + text).encode("ascii")
    try:
        document = parse_rtf(data, max_objects=4, max_object_bytes=256)
    except RtfError:
        return
    assert len(document.objects) <= 4
    assert sum(len(obj.data) for obj in document.objects) <= 4 * 256


@SETTINGS
@given(st.text(alphabet="{", min_size=MAX_GROUP_DEPTH + 2, max_size=MAX_GROUP_DEPTH + 40))
def test_the_rtf_reader_refuses_deeper_nesting_than_its_cap(braces: str):
    data = ("{\\rtf1" + braces).encode("ascii")
    with pytest.raises(RtfError, match="nesting"):
        parse_rtf(data)


@SETTINGS
@given(st.lists(
    st.text(max_size=40),
    min_size=0,
    max_size=6,
))
def test_a_saved_bundle_raises_only_its_documented_error(texts: list[str]):
    from engine.bundle import BundleReadError, load_bundle

    with temporary_directory() as tmp_path:
        run = tmp_path / "run"
        run.mkdir()
        payload = "".join(texts).encode("utf-8", errors="replace")
        (run / "analysis.json").write_bytes(payload)

        try:
            load_bundle(run)
        except BundleReadError:
            return
        except Exception as exc:  # noqa: BLE001 - the property is the point
            pytest.fail(f"load_bundle raised {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Delivery extraction — a hostile container cannot leave its root or its caps
# ---------------------------------------------------------------------------


@SETTINGS
@given(st.dictionaries(
    keys=st.text(alphabet="ab/..\\\x00: \t", max_size=12),
    values=st.binary(max_size=64),
    max_size=6,
))
def test_a_zip_never_escapes_the_output_root_or_the_caps(members: dict[str, bytes]):
    with temporary_directory() as tmp_path:
        archive_path = tmp_path / "sample.zip"
        try:
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name, payload in members.items():
                    archive.writestr(name, payload)
        except (ValueError, OSError):
            return  # a name zipfile itself refuses is not our property to state

        out = tmp_path / "out"
        result = extract_delivery(archive_path, out)
        root = out.resolve()
        children = list(result.children)

    assert len(children) <= MAX_CHILDREN
    assert sum(child.size for child in children) <= MAX_TOTAL_BYTES
    for child in children:
        assert child.depth <= MAX_DEPTH
        assert child.path.resolve().is_relative_to(root)


@SETTINGS
@given(st.text(max_size=80))
def test_a_member_name_is_always_below_the_extraction_root(name: str):
    safe = _safe_member_name(name)
    if safe is None:
        return
    assert "\x00" not in safe
    assert not safe.startswith("/")
    assert not safe.startswith("//")
    assert all(part not in ("", ".", "..") for part in safe.split("/"))
    with temporary_directory() as tmp_path:
        root = (tmp_path / "out").resolve()
        assert (root / safe).resolve().is_relative_to(root)


# ---------------------------------------------------------------------------
# Readers that must simply survive
# ---------------------------------------------------------------------------


@SETTINGS
@given(st.binary(max_size=8192))
def test_the_string_extractor_returns_a_classification_for_any_bytes(blob: bytes):
    result = StringExtractor().extract_from_bytes(blob)
    assert isinstance(result, StringClassification)
    assert result.to_dict()["total_strings"] == len(result.all_strings)


@SETTINGS
@given(st.text(max_size=1024))
def test_one_strace_line_never_raises(line: str):
    result = StraceParser().parse_stream(line)
    assert result is None or result.syscall
