"""Tests for RTF delivery intake (D19 extension).

RTF wraps an embedded object in a ``{\\*\\objdata ...}`` destination; for a
``Package`` object the decoded bytes are an OLE/CFB compound file that the OLE
parser (``engine/intake/ole.py``) already knows how to finish. Fixtures are
built by ``tests/_rtf_builder.py`` and cross-checked against ``oletools.rtfobj``
— an independent RTF OLE-object extractor — so HATCHERY's decoder cannot be
validated against its own writer.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from _ole_builder import build_macro_doc
from _rtf_builder import build_rtf_embedded, build_rtf_objects
from engine.intake import rtf
from engine.intake.delivery import DeliveryFormat, classify_delivery, extract_delivery


# ---------------------------------------------------------------------------
# Classification and parsing
# ---------------------------------------------------------------------------


def test_classify_rtf(tmp_path: Path):
    path = tmp_path / "invoice.rtf"
    path.write_bytes(b"{\\rtf1\\ansi\\deff0 hello}")
    result = classify_delivery(path)
    assert result.format is DeliveryFormat.RTF
    assert result.is_container is True


def test_parse_rtf_decodes_hex_object():
    document = rtf.parse_rtf(build_rtf_embedded(b"HELLO WORLD"))
    assert len(document.objects) == 1
    obj = document.objects[0]
    assert obj.data == b"HELLO WORLD"
    assert obj.objclass == "Package"
    assert obj.objname == "invoice.doc"
    assert obj.used_bin is False


def test_parse_rtf_decodes_bin_object():
    payload = b"A{B}C" * 100  # braces in binary data must not break group tracking
    document = rtf.parse_rtf(build_rtf_embedded(payload, use_bin=True))
    assert len(document.objects) == 1
    assert document.objects[0].data == payload
    assert document.objects[0].used_bin is True


def test_parse_rtf_trims_an_odd_trailing_nibble():
    raw = build_rtf_embedded(b"HI")
    document = rtf.parse_rtf(raw.replace(b"4849", b"4849F"))
    assert document.objects[0].data == b"HI"
    assert document.objects[0].odd_nibble is True


def test_parse_rtf_without_object_is_empty_not_an_error():
    document = rtf.parse_rtf(b"{\\rtf1\\ansi just some text}")
    assert document.objects == []
    assert document.unterminated is False


def test_parse_rtf_rejects_a_non_rtf_document():
    with pytest.raises(rtf.RtfError):
        rtf.parse_rtf(b"not an rtf document")


def test_parse_rtf_reports_an_unterminated_group():
    # The objdata group is never closed; the document must say so.
    document = rtf.parse_rtf(b"{\\rtf1{\\*\\objdata 4849")
    assert document.unterminated is True


def test_parse_rtf_rejects_a_bin_region_that_overruns_the_file():
    with pytest.raises(rtf.RtfError):
        rtf.parse_rtf(b"{\\rtf1{\\*\\objdata \\bin999999999 X}}")


def test_parse_rtf_rejects_a_negative_bin_length():
    with pytest.raises(rtf.RtfError):
        rtf.parse_rtf(b"{\\rtf1{\\*\\objdata \\bin-5 X}}")


def test_parse_rtf_multiple_objects():
    document = rtf.parse_rtf(
        build_rtf_objects(
            [
                {"payload": b"first", "objname": "one.bin"},
                {"payload": b"second", "objname": "two.bin", "objclass": "Excel.Sheet.8"},
            ]
        )
    )
    payloads = [obj.data for obj in document.objects]
    assert payloads == [b"first", b"second"]
    assert document.objects[1].objclass == "Excel.Sheet.8"


# ---------------------------------------------------------------------------
# Independent validation: the decoded object matches oletools
# ---------------------------------------------------------------------------


def test_parsed_object_matches_oletools_extraction():
    oletools_rtfobj = pytest.importorskip("oletools.rtfobj")
    blob = build_macro_doc()
    raw = build_rtf_embedded(blob)

    mine = rtf.parse_rtf(raw).objects[0].data
    parser = oletools_rtfobj.RtfObjParser(raw)
    parser.parse()
    assert parser.objects, "oletools found no object in a fixture that contains one"
    assert mine == parser.objects[0].rawdata


# ---------------------------------------------------------------------------
# Full delivery intake
# ---------------------------------------------------------------------------


def test_rtf_embedded_ole_is_extracted_and_vba_recovered(tmp_path: Path):
    """The headline case: an RTF Package wraps a macro document end to end."""

    path = tmp_path / "invoice.rtf"
    path.write_bytes(
        build_rtf_embedded(build_macro_doc(native_payload=b"MZ\x90\x00RTF-PAYLOAD"))
    )
    result = extract_delivery(path, tmp_path / "out")

    assert result.format is DeliveryFormat.RTF
    assert result.errors == []
    assert {"rtf", "rtf-embedded-object", "rtf-objclass-package"} <= set(result.flags)
    # Recursion reached the OLE parser: decompressed VBA and carved package.
    assert "ole-vba-macro" in result.flags
    assert "ole-embedded-native" in result.flags

    embedded = [c for c in result.children if c.extractor == "rtf"]
    assert embedded and embedded[0].name == "invoice.doc"
    assert embedded[0].format == "ole"

    vba = [c for c in result.children if c.extractor == "ole-vba"]
    assert any(b"powershell.exe" in c.path.read_bytes() for c in vba)
    carved = [c for c in result.children if c.extractor == "ole-native"]
    assert carved and carved[0].path.read_bytes() == b"MZ\x90\x00RTF-PAYLOAD"


def test_rtf_without_an_object_is_flagged_but_not_unsupported(tmp_path: Path):
    path = tmp_path / "plain.rtf"
    path.write_bytes(b"{\\rtf1\\ansi just some text}")
    result = extract_delivery(path, tmp_path / "out")
    assert result.format is DeliveryFormat.RTF
    assert result.children == []
    assert result.unsupported == []
    assert result.errors == []
    assert "rtf" in result.flags
    assert result.details["rtf"]["objects"] == 0


def test_rtf_ole2link_is_flagged(tmp_path: Path):
    path = tmp_path / "cve-2017-0199.rtf"
    path.write_bytes(
        build_rtf_embedded(
            b"http://evil.example/payload.sct", objclass="OLE2Link", objname="link"
        )
    )
    result = extract_delivery(path, tmp_path / "out")
    assert "rtf-ole2link" in result.flags
    assert any(b"evil.example" in c.path.read_bytes() for c in result.children)


def test_rtf_child_budget_prioritises_the_embedded_object(tmp_path: Path):
    path = tmp_path / "invoice.rtf"
    path.write_bytes(build_rtf_embedded(build_macro_doc()))
    result = extract_delivery(path, tmp_path / "out", max_children=2)
    assert result.truncated is True
    assert "child-limit-reached" in result.flags
    # The embedded object is written first, so a tiny budget still surfaces it
    # (and the VBA source its recursion finds) rather than nothing at all.
    assert any(c.extractor == "rtf" for c in result.children)
    assert any(c.extractor == "ole-vba" for c in result.children)


def test_rtf_nested_in_a_zip_is_extracted(tmp_path: Path):
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "invoice.rtf", build_rtf_embedded(b"MZ\x90\x00NESTED", objname="dropped.exe")
        )
    result = extract_delivery(path, tmp_path / "out")
    assert "rtf-embedded-object" in result.flags
    assert any(c.path.read_bytes() == b"MZ\x90\x00NESTED" for c in result.children)


def test_truncated_rtf_read_is_flagged(tmp_path: Path, monkeypatch):
    path = tmp_path / "big.rtf"
    path.write_bytes(build_rtf_embedded(b"X" * 2048))
    # Force the cap below the file size without writing a huge fixture.
    from engine.intake import delivery

    monkeypatch.setattr(delivery, "MAX_ENTRY_BYTES", 128)
    result = extract_delivery(path, tmp_path / "out")
    assert "rtf-truncated-read" in result.flags or result.truncated


def test_cli_delivery_printer_handles_rtf_details(tmp_path: Path, capsys):
    from engine.cli import _print_delivery

    path = tmp_path / "invoice.rtf"
    path.write_bytes(build_rtf_embedded(build_macro_doc(), objname="dropped.exe"))
    result = extract_delivery(path, tmp_path / "out")
    _print_delivery(result)
    captured = capsys.readouterr()
    assert "RTF embedded objects" in (captured.out + captured.err)
