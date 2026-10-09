"""Tests for OLE/CFB delivery intake (D19 extension).

Fixtures are built by ``tests/_ole_builder.py`` and then cross-checked against
independent implementations: ``olefile`` for the compound-file structure and
``oletools`` for the MS-OVBA VBA extraction. A committed ``.xls`` written by
``xlwt`` — a real compound file from a third-party library — covers the case
where the file was not produced by HATCHERY's own writer.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from _ole_builder import (
    build_cfb,
    build_macro_doc,
    build_ole10native,
    compress_ovba,
)
from engine.intake import ole
from engine.intake.delivery import DeliveryFormat, classify_delivery, extract_delivery

FIXTURES = Path(__file__).parent / "fixtures"


def _stream_paths(cfb: ole.CompoundFile) -> set[str]:
    return {entry.path for entry in cfb.streams}


# ---------------------------------------------------------------------------
# MS-OVBA decompression
# ---------------------------------------------------------------------------


def test_ovba_literals_round_trip():
    source = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nEnd Sub\r\n"
    assert ole.decompress_ovba(compress_ovba(source)) == source


def test_ovba_copy_token_is_decoded():
    """A hand-built copy token, confirmed against oletools before committing.

    The chunk is: three literal bytes ``ABC`` then a copy token of offset 3,
    length 3, which must reproduce ``ABCABC``.
    """

    vector = b"\x01" + struct.pack("<H", 0xB005) + bytes([0x08]) + b"ABC" + b"\x00\x20"
    assert ole.decompress_ovba(vector) == b"ABCABC"


def test_ovba_raw_chunk_is_decoded():
    vector = b"\x01" + struct.pack("<H", 0x3FFF) + b"X" * 4096
    assert ole.decompress_ovba(vector) == b"X" * 4096


def test_ovba_rejects_a_bad_signature():
    with pytest.raises(ole.OleError):
        ole.decompress_ovba(b"\x02\x00\x00")


def test_ovba_output_is_bounded():
    with pytest.raises(ole.OleError):
        # A copy token that runs away would exceed the cap; the decoder must
        # stop rather than allocate without limit.
        blob = b"\x01" + struct.pack("<H", 0x3FFF) + b"A" * 4096
        ole.decompress_ovba(blob, max_output=100)


# ---------------------------------------------------------------------------
# Compound-file structure, cross-checked with olefile
# ---------------------------------------------------------------------------


def test_cfb_round_trips_through_olefile():
    olefile = pytest.importorskip("olefile")
    blob = build_cfb(
        {
            "WordDocument": b"\xec\xa5\xc1\x00" + b"D" * 5000,
            "mini": b"small stream",
            "nested/storage/stream": b"nested value",
        }
    )
    with olefile.OleFileIO(io.BytesIO(blob)) as of:
        reference = {"/".join(parts) for parts in of.listdir(streams=True, storages=False)}
        assert of.get_size("WordDocument") == 5004
        assert of.openstream("mini").read() == b"small stream"
        assert of.openstream(["nested", "storage", "stream"]).read() == b"nested value"

    cfb = ole.CompoundFile(blob)
    mine = _stream_paths(cfb)
    assert mine == reference
    assert cfb.read_path("WordDocument") == b"\xec\xa5\xc1\x00" + b"D" * 5000
    assert cfb.read_path("mini") == b"small stream"


def test_cfb_read_is_capped_by_max_stream_bytes():
    blob = build_cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"D" * 5000})
    cfb = ole.CompoundFile(blob, max_stream_bytes=64)
    entry = next(e for e in cfb.streams if e.path == "WordDocument")
    assert len(cfb.read_stream(entry)) == 64


def test_cfb_rejects_a_non_compound_file():
    with pytest.raises(ole.OleError):
        ole.CompoundFile(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 64)


# ---------------------------------------------------------------------------
# \x01Ole10Native carving
# ---------------------------------------------------------------------------


def test_ole10native_payload_is_carved():
    parsed = ole.parse_ole10native(build_ole10native(b"MZ\x90\x00PAYLOAD", filename="dropped.exe"))
    assert parsed is not None
    assert parsed.filename == "dropped.exe"
    assert parsed.payload == b"MZ\x90\x00PAYLOAD"


def test_ole10native_malformed_returns_none():
    assert ole.parse_ole10native(b"\x01\x02") is None


# ---------------------------------------------------------------------------
# Full delivery intake
# ---------------------------------------------------------------------------


def test_macro_document_extracts_decompressed_vba_source(tmp_path: Path):
    path = tmp_path / "invoice.doc"
    path.write_bytes(build_macro_doc())
    result = extract_delivery(path, tmp_path / "out")

    assert result.format is DeliveryFormat.OLE
    assert "ole" in result.flags
    assert "ole-vba-macro" in result.flags
    assert "ole-legacy-office" in result.flags
    assert result.errors == []

    vba_children = [c for c in result.children if c.extractor == "ole-vba"]
    names = {c.name for c in vba_children}
    assert names == {"Module1.bas", "ThisDocument.cls"}
    module = next(c for c in vba_children if c.name == "Module1.bas")
    assert b"AutoOpen" in module.path.read_bytes()
    assert b"powershell.exe" in module.path.read_bytes()


def test_macro_document_matches_oletools_extraction(tmp_path: Path):
    """The macro source must match an independent MS-OVBA implementation."""

    oletools = pytest.importorskip("oletools.olevba")
    blob = build_macro_doc()
    path = tmp_path / "invoice.doc"
    path.write_bytes(blob)
    result = extract_delivery(path, tmp_path / "out")
    mine = {
        c.name: c.path.read_bytes().decode("utf-8")
        for c in result.children
        if c.extractor == "ole-vba"
    }

    parser = oletools.VBA_Parser("invoice.doc", data=blob)
    theirs = {}
    for _filename, _stream, vba_filename, code in parser.extract_all_macros():
        if vba_filename:
            theirs[vba_filename] = code

    assert theirs, "oletools found no macros in a fixture that claims to contain them"
    assert set(mine) == set(theirs)
    for name, source in theirs.items():
        assert mine[name] == source


def test_embedded_ole_package_is_carved_from_the_document(tmp_path: Path):
    path = tmp_path / "invoice.doc"
    path.write_bytes(build_macro_doc(native_payload=b"MZ\x90\x00SECRET", native_filename="dropped.exe"))
    result = extract_delivery(path, tmp_path / "out")

    assert "ole-embedded-native" in result.flags
    carved = [c for c in result.children if c.extractor == "ole-native"]
    assert carved and carved[0].name == "dropped.exe"
    assert carved[0].path.read_bytes() == b"MZ\x90\x00SECRET"
    assert carved[0].format == "pe"
    # The embedded-package detail must live inside the per-context entry, not
    # be flattened onto the ``ole`` mapping (a bug caught by the CLI smoke run).
    ole_details = result.details["ole"]
    assert all(isinstance(info, dict) for info in ole_details.values())
    assert any(
        "dropped.exe" in (info.get("embedded") or [])
        for info in ole_details.values()
    )


def test_raw_streams_are_extracted_and_flagged(tmp_path: Path):
    path = tmp_path / "invoice.doc"
    path.write_bytes(build_macro_doc())
    result = extract_delivery(path, tmp_path / "out")
    raw = {c.name for c in result.children if c.extractor == "ole"}
    assert "WordDocument" in raw
    assert "Macros/VBA/_VBA_PROJECT" in raw
    word = next(c for c in result.children if c.name == "WordDocument")
    assert "ole-legacy-office" in word.flags
    project = next(c for c in result.children if c.name == "Macros/VBA/dir")
    assert "ole-vba" in project.flags


def test_malformed_ole_is_reported_not_silently_empty(tmp_path: Path):
    """A file that claims to be OLE but is not must produce an error, loudly."""

    path = tmp_path / "broken.doc"
    path.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 64)
    result = extract_delivery(path, tmp_path / "out")
    assert result.format is DeliveryFormat.OLE
    assert result.children == []
    assert result.errors, "a corrupt compound file must be an error, not an empty result"


def test_ole_nested_in_a_zip_is_extracted_recursively(tmp_path: Path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("invoice.doc", build_macro_doc())
    result = extract_delivery(path, tmp_path / "out")
    assert "ole-vba-macro" in result.flags
    assert any(c.extractor == "ole-vba" for c in result.children)


def test_ole_child_budget_is_enforced(tmp_path: Path):
    path = tmp_path / "invoice.doc"
    path.write_bytes(build_macro_doc())
    result = extract_delivery(path, tmp_path / "out", max_children=2)
    assert result.truncated is True
    assert "child-limit-reached" in result.flags
    # The security-relevant VBA source is written first, so a tiny budget still
    # surfaces the macro rather than a pile of raw streams.
    assert any(c.extractor == "ole-vba" for c in result.children)


# ---------------------------------------------------------------------------
# A real compound file from an independent library
# ---------------------------------------------------------------------------


def test_real_xlwt_capture_is_extracted(tmp_path: Path):
    fixture = FIXTURES / "ole-xlwt-real.xls"
    assert fixture.exists(), "the committed xlwt .xls fixture is missing"
    result = extract_delivery(fixture, tmp_path / "out")
    assert result.format is DeliveryFormat.OLE
    assert classify_delivery(fixture).detail.startswith("legacy Office")
    assert any(c.name == "Workbook" for c in result.children if c.extractor == "ole")


def test_cli_delivery_printer_handles_ole_details(tmp_path: Path, capsys):
    """The terminal printer must render OLE details without raising."""

    from engine.cli import _print_delivery

    path = tmp_path / "invoice.doc"
    path.write_bytes(build_macro_doc(native_payload=b"MZ\x90\x00X", native_filename="dropped.exe"))
    result = extract_delivery(path, tmp_path / "out")
    _print_delivery(result)
    captured = capsys.readouterr()
    assert "dropped.exe" in (captured.out + captured.err)
