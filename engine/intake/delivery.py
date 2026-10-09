"""Delivery-format intake — open the container before static analysis.

Most malware does not arrive as a bare ELF. It arrives as a delivery format:
a ZIP, an Office document (OOXML or OLE/CFB), a PDF, a shell-link, an
ISO/IMG, a one-file archive, or an HTML/SVG page. Before this module existed
HATCHERY classified those as ``Unknown``, ran YARA and a string scan over the
raw bytes, and reported nothing else. A document that contained an embedded
executable therefore looked like a clean run — the exact silent "no findings"
the rest of this project exists to eliminate (D3).

This is the single intake path for delivery formats. It is the one place the
intake can fail, and it is *loud* about what it did and did not do:

* Supported container extraction: ZIP (including OOXML Office / JAR / APK),
  tar, gzip, bzip2, xz, HTML/HTA, SVG script blocks, Windows shell links
  (MS-SHLLINK), ISO9660/IMG images, PDF embedded files + JavaScript, and
  legacy Office OLE/CFB compound files — whose streams are enumerated and
  whose embedded VBA macros are decompressed to source and whose
  ``\x01Ole10Native`` packages are carved out (see ``engine/intake/ole.py``).
* Formats that are *detected but not extracted* in this revision (RTF, 7z,
  RAR, CAB) are reported as unsupported, with a reason, and still reach the
  string extractor as raw bytes. They never silently produce "no findings".
* Every extracted child is hashed, classified, and (at a higher level) run
  through the static pipeline. Extraction is bounded: depth, child count,
  per-entry size, total size and compression ratio are all capped, names are
  flattened under the output directory, and symlinks/devices are refused.

Stdlib only. Nothing here parses a file *and* decides it is safe: extraction
never executes anything.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import logging
import lzma
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional

from engine.intake import ole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bounds — bounded everything. A delivery format is untrusted input.
# ---------------------------------------------------------------------------

MAX_DEPTH = 3
MAX_CHILDREN = 64
MAX_ENTRY_BYTES = 64 * 1024 * 1024          # 64 MiB per extracted member
MAX_TOTAL_BYTES = 256 * 1024 * 1024         # 256 MiB uncompressed per run
MAX_COMPRESSION_RATIO = 200                 # declared/stored; zip-bomb guard
MIN_ZIP_BOMB_BYTES = 1024 * 1024            # ratio applies only above 1 MiB
MAX_HTML_SCRIPTS = 32

# ISO9660 places the "CD001" identifier at byte 0x8001 of the image.
ISO_PRIMARY_VOLUME_OFFSET = 0x8001

LINK_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
SEVEN_ZIP_MAGIC = bytes.fromhex("377abcaf271c")
RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
CAB_MAGIC = b"MSCF"

# Formats that are delivered to a victim and may carry another file.
DELIVERY_FORMATS: set[str] = {
    "zip", "ooxml", "ole", "pdf", "lnk", "iso", "gzip", "bzip2", "xz", "tar",
    "7z", "rar", "rtf", "html", "svg", "cab",
}


class DeliveryFormat(str, Enum):
    """Coarse classification of the delivery container."""

    ZIP = "zip"
    OOXML = "ooxml"
    OLE = "ole"
    PDF = "pdf"
    LNK = "lnk"
    ISO = "iso"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    XZ = "xz"
    TAR = "tar"
    SEVEN_ZIP = "7z"
    RAR = "rar"
    RTF = "rtf"
    HTML = "html"
    SVG = "svg"
    CAB = "cab"
    MACHO = "macho"
    UNKNOWN = "unknown"


@dataclass
class DeliveryClassification:
    """What a file *is*, as far as its delivery format goes."""

    format: DeliveryFormat
    detail: str = ""
    is_container: bool = False

    @property
    def label(self) -> str:
        return self.format.value


@dataclass
class ExtractedChild:
    """One file recovered from a delivery container."""

    name: str                       # original member name inside the container
    path: Path                      # where it landed on disk
    rel_path: str                   # run-relative path, for the bundle
    size: int
    sha256: str
    format: str                     # classified child format
    extractor: str                  # which extractor produced it
    reason: str                     # why it was kept
    depth: int
    flags: list[str] = field(default_factory=list)
    static: dict = field(default_factory=dict)   # filled by the caller

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "rel_path": self.rel_path,
            "size": self.size,
            "sha256": self.sha256,
            "format": self.format,
            "extractor": self.extractor,
            "reason": self.reason,
            "depth": self.depth,
            "flags": list(self.flags),
            "static": self.static,
        }


@dataclass
class DeliveryIntakeResult:
    """The outcome of one delivery-intake pass, successful or not."""

    classification: DeliveryClassification
    children: list[ExtractedChild] = field(default_factory=list)
    unsupported: list[dict] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    details: dict = field(default_factory=dict)

    @property
    def format(self) -> DeliveryFormat:
        return self.classification.format

    def to_dict(self) -> dict:
        return {
            "format": self.classification.format.value,
            "format_detail": self.classification.detail,
            "is_container": self.classification.is_container,
            "children": [child.to_dict() for child in self.children],
            "unsupported": list(self.unsupported),
            "flags": sorted(set(self.flags)),
            "errors": list(self.errors),
            "truncated": self.truncated,
            "details": dict(self.details),
        }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _head(path: Path, size: int = 0x9000) -> bytes:
    """Read a bounded prefix for magic sniffing (ISO needs 0x8002 bytes)."""
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError as exc:  # pragma: no cover - unreadable file
        logger.warning("Could not read %s for classification: %s", path, exc)
        return b""


def _extension(path: Path) -> str:
    return path.suffix.lower()


def _looks_like_text_html(head: bytes, ext: str) -> Optional[DeliveryFormat]:
    """Distinguish HTML from SVG from arbitrary text, cheaply and bounded."""
    if ext in (".svg",):
        return DeliveryFormat.SVG
    if ext in (".htm", ".html", ".hta", ".xht", ".xhtml"):
        return DeliveryFormat.HTML

    sample = head[:4096].lstrip()
    lowered = sample.lower()
    if lowered.startswith(b"<?xml") or b"<svg" in lowered[:2048]:
        # An XML prolog alone is ambiguous; require an SVG root element.
        if b"<svg" in lowered[:4096]:
            return DeliveryFormat.SVG
        return None
    if lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html"):
        return DeliveryFormat.HTML
    if b"<html" in lowered[:2048] or b"<script" in lowered[:2048]:
        return DeliveryFormat.HTML
    return None


def _is_ooxml(path: Path) -> bool:
    """True when a ZIP is an OOXML package ([Content_Types].xml present)."""
    try:
        with zipfile.ZipFile(path) as archive:
            names = {name.replace("\\", "/") for name in archive.namelist()}
            return "[Content_Types].xml" in names
    except (zipfile.BadZipFile, OSError):
        return False


def classify_delivery(path: Path) -> DeliveryClassification:
    """Classify a file by delivery format, magic first and extension second.

    Extension is only consulted to disambiguate formats whose magic bytes are
    shared (OOXML vs plain ZIP, HTML vs SVG) or absent (plain tar has a header
    checksum, not a true magic). A file's bytes always win.
    """
    ext = _extension(path)
    head = _head(path)

    if head.startswith(b"%PDF-"):
        return DeliveryClassification(DeliveryFormat.PDF, "PDF document", True)
    if head.startswith(LINK_MAGIC):
        return DeliveryClassification(DeliveryFormat.LNK, "Windows shell link", True)
    if head.startswith(OLE_MAGIC):
        detail = "OLE/CFB compound file"
        if ext in (".doc", ".xls", ".ppt"):
            detail = f"legacy Office ({ext.lstrip('.')}) compound file"
        return DeliveryClassification(DeliveryFormat.OLE, detail, True)
    if head.startswith(SEVEN_ZIP_MAGIC):
        return DeliveryClassification(DeliveryFormat.SEVEN_ZIP, "7-Zip archive", True)
    if head.startswith(RAR4_MAGIC) or head.startswith(RAR5_MAGIC):
        return DeliveryClassification(DeliveryFormat.RAR, "RAR archive", True)
    if head.startswith(CAB_MAGIC):
        return DeliveryClassification(DeliveryFormat.CAB, "Microsoft Cabinet archive", True)
    if head.startswith(b"{\\rtf"):
        return DeliveryClassification(DeliveryFormat.RTF, "Rich Text Format", True)
    if head.startswith(b"\x1f\x8b"):
        return DeliveryClassification(DeliveryFormat.GZIP, "gzip stream", True)
    if head.startswith(b"BZh"):
        return DeliveryClassification(DeliveryFormat.BZIP2, "bzip2 stream", True)
    if head.startswith(b"\xfd7zXZ\x00"):
        return DeliveryClassification(DeliveryFormat.XZ, "xz stream", True)
    if head.startswith(b"\xfe\xed\xfa\xce") or head.startswith(b"\xfe\xed\xfa\xcf") \
            or head.startswith(b"\xce\xfa\xed\xfe") or head.startswith(b"\xcf\xfa\xed\xfe") \
            or head.startswith(b"\xca\xfe\xba\xbe"):
        return DeliveryClassification(DeliveryFormat.MACHO, "Mach-O binary", False)

    # ZIP is a family: plain archive, OOXML Office, JAR, APK. zipfile is the
    # authoritative check because the local-header magic can appear mid-file.
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08") or zipfile.is_zipfile(path):
        if _is_ooxml(path):
            suffix = f" ({ext.lstrip('.')})" if ext else ""
            return DeliveryClassification(
                DeliveryFormat.OOXML, f"OOXML package{suffix}", True
            )
        return DeliveryClassification(DeliveryFormat.ZIP, "ZIP archive", True)

    if len(head) >= ISO_PRIMARY_VOLUME_OFFSET + 5 and \
            head[ISO_PRIMARY_VOLUME_OFFSET:ISO_PRIMARY_VOLUME_OFFSET + 5] == b"CD001":
        return DeliveryClassification(DeliveryFormat.ISO, "ISO 9660 / IMG image", True)

    if head[257:262] == b"ustar":
        return DeliveryClassification(DeliveryFormat.TAR, "tar archive", True)

    text_format = _looks_like_text_html(head, ext)
    if text_format is not None:
        return DeliveryClassification(
            text_format, f"{text_format.value.upper()} document", True
        )

    return DeliveryClassification(DeliveryFormat.UNKNOWN, "", False)


# ---------------------------------------------------------------------------
# Name safety — never trust a member name from an untrusted archive
# ---------------------------------------------------------------------------


def _safe_member_name(name: str) -> Optional[str]:
    """Reduce an archive member name to a safe relative path.

    Backslashes become slashes, drive letters and UNC prefixes are dropped,
    and ``.``/``..``/empty components are removed. The result is therefore
    always below the extraction root, even for ``../../etc/passwd``.
    """
    name = name.replace("\\", "/").replace("\x00", "")
    if name.startswith("//"):
        name = name.lstrip("/")
    if len(name) >= 2 and name[1] == ":":
        name = name[2:]
    parts = []
    for part in name.split("/"):
        if part in ("", ".", ".."):
            continue
        cleaned = "".join(ch for ch in part if ch >= " ")
        if cleaned:
            parts.append(cleaned)
    if not parts:
        return None
    return "/".join(parts)


def _flatten(rel_name: str) -> str:
    """Turn a member path into a single filesystem component."""
    flat = rel_name.replace("/", "__")
    return flat[:160] or "member"


_SCRIPT_EXTS = {
    ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd",
    ".hta", ".sh", ".py", ".rb", ".pl", ".scr", ".wsf", ".lnk",
}
_TEXT_EXTS = {
    ".txt", ".xml", ".rels", ".json", ".csv", ".ini", ".cfg", ".log",
    ".html", ".htm", ".css", ".md",
}


def _coarse_label(data: bytes, path: Path) -> str:
    """A coarse, honest type for a child that is not a delivery container.

    The delivery classifier only knows delivery formats; an extracted
    ``vbaProject.bin`` or ``document.xml`` would otherwise read as ``unknown``.
    This does not guess a malware family — only whether the bytes are an
    executable, a script or text.
    """
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"#!":
        return "script"
    ext = path.suffix.lower()
    if ext in _SCRIPT_EXTS:
        return "script"
    if ext in _TEXT_EXTS:
        return "text"
    sample = data[:2048]
    if sample:
        printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
        if printable / len(sample) > 0.9:
            return "text"
    return "bin"


# ---------------------------------------------------------------------------
# Extraction state
# ---------------------------------------------------------------------------


@dataclass
class _State:
    out_root: Path
    max_depth: int = MAX_DEPTH
    max_children: int = MAX_CHILDREN
    children: list[ExtractedChild] = field(default_factory=list)
    unsupported: list[dict] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    total_bytes: int = 0
    details: dict = field(default_factory=dict)

    def add_flag(self, flag: str) -> None:
        if flag not in self.flags:
            self.flags.append(flag)

    def budget_left(self) -> bool:
        return len(self.children) < self.max_children and self.total_bytes <= MAX_TOTAL_BYTES

    def place(self, index: int, rel_name: str) -> Path:
        target = self.out_root / f"{index:04d}_{_flatten(rel_name)}"
        target.parent.mkdir(parents=True, exist_ok=True)
        return target


def _write_child(
    state: _State,
    index: int,
    member_name: str,
    data: bytes,
    *,
    extractor: str,
    reason: str,
    depth: int,
    child_format: Optional[DeliveryClassification] = None,
    flags: Optional[list[str]] = None,
) -> ExtractedChild:
    target = state.place(index, member_name)
    target.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    classification = child_format or classify_delivery(target)
    child_type = classification.format.value
    if child_type == "unknown":
        child_type = _coarse_label(data, target)
    try:
        rel_path = str(target.relative_to(state.out_root.parent))
    except ValueError:  # pragma: no cover - defensive
        rel_path = target.name
    child = ExtractedChild(
        name=member_name,
        path=target,
        rel_path=rel_path,
        size=len(data),
        sha256=sha256,
        format=child_type,
        extractor=extractor,
        reason=reason,
        depth=depth,
        flags=list(flags or []),
    )
    state.children.append(child)
    state.total_bytes += len(data)
    return child


# ---------------------------------------------------------------------------
# ZIP / OOXML
# ---------------------------------------------------------------------------


def _extract_zip(path: Path, state: _State, depth: int, context: str) -> None:
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        state.errors.append(f"{context}: could not open ZIP: {exc}")
        return

    with archive:
        members = archive.infolist()
        if len(members) > state.max_children * 4:
            state.add_flag("zip-many-members")
        names = {m.filename.replace("\\", "/"): m for m in members}

        if "[Content_Types].xml" in names:
            state.add_flag("ooxml-package")
            _inspect_ooxml(archive, names, state)

        index = len(state.children)
        for info in members:
            if not state.budget_left():
                state.truncated = True
                state.add_flag("child-limit-reached")
                break
            safe = _safe_member_name(info.filename)
            if safe is None:
                continue
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                state.unsupported.append({
                    "path": f"{context}!/{safe}",
                    "format": "symlink",
                    "reason": "symlink member refused; not extracted",
                })
                continue
            if info.flag_bits & 0x1:
                state.unsupported.append({
                    "path": f"{context}!/{safe}",
                    "format": "encrypted",
                    "reason": "encrypted ZIP member; no password support",
                })
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                state.unsupported.append({
                    "path": f"{context}!/{safe}",
                    "format": "oversize",
                    "reason": f"declared size {info.file_size} exceeds {MAX_ENTRY_BYTES} byte cap",
                })
                state.add_flag("oversize-member")
                continue
            if (
                info.compress_size > 0
                and info.file_size >= MIN_ZIP_BOMB_BYTES
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                state.unsupported.append({
                    "path": f"{context}!/{safe}",
                    "format": "compression-ratio",
                    "reason": (
                        f"compression ratio {info.file_size // max(info.compress_size, 1)}:1 "
                        "exceeds the zip-bomb guard"
                    ),
                })
                state.add_flag("zip-suspicious-ratio")
                continue

            try:
                with archive.open(info) as handle:
                    data = handle.read(MAX_ENTRY_BYTES + 1)
            except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                state.errors.append(f"{context}!/{safe}: read failed: {exc}")
                continue
            if len(data) > MAX_ENTRY_BYTES:
                state.unsupported.append({
                    "path": f"{context}!/{safe}",
                    "format": "oversize",
                    "reason": "member grew past the size cap while reading; truncated",
                })
                state.truncated = True
                continue

            child_flags = _member_flags(safe)
            child = _write_child(
                state, index, safe, data,
                extractor="zip", reason="ZIP member", depth=depth,
                flags=child_flags,
            )
            index += 1
            for flag in child_flags:
                state.add_flag(flag)
            if depth < state.max_depth and state.budget_left():
                _recurse(child, state, depth)


def _member_flags(safe_name: str) -> list[str]:
    lowered = safe_name.lower()
    flags: list[str] = []
    if lowered.endswith("vbaproject.bin"):
        flags.append("ooxml-macro")
    if "/embeddings/" in f"/{lowered}":
        flags.append("ooxml-embedded-object")
    if lowered.endswith((".exe", ".dll", ".scr", ".lnk", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".iso", ".img")):
        flags.append("risky-member-extension")
    return flags


def _inspect_ooxml(archive: zipfile.ZipFile, names: dict, state: _State) -> None:
    """Detect macro-enabled parts and external relationships in an OOXML zip."""
    for member_name in names:
        lowered = member_name.lower()
        if lowered.endswith("vbaproject.bin"):
            state.add_flag("ooxml-macro")
        if "/embeddings/" in f"/{lowered}":
            state.add_flag("ooxml-embedded-object")
        if lowered.endswith(".rels"):
            try:
                with archive.open(names[member_name]) as handle:
                    payload = handle.read(256 * 1024)
            except (zipfile.BadZipFile, RuntimeError, OSError):
                continue
            if b'TargetMode="External"' in payload or b"TargetMode='External'" in payload:
                state.add_flag("ooxml-external-relationship")
    content_types = names.get("[Content_Types].xml")
    if content_types is not None:
        try:
            with archive.open(content_types) as handle:
                payload = handle.read(256 * 1024)
            if b"macroEnabled" in payload:
                state.add_flag("ooxml-macro-enabled")
        except (zipfile.BadZipFile, RuntimeError, OSError):
            pass


# ---------------------------------------------------------------------------
# Single-stream compression and tar
# ---------------------------------------------------------------------------


def _decompress_stream(path: Path, opener) -> bytes:
    with opener(path, "rb") as handle:
        return handle.read(MAX_ENTRY_BYTES + 1)


def _extract_stream(path: Path, state: _State, depth: int, context: str, kind: str) -> None:
    opener = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}[kind]
    try:
        data = _decompress_stream(path, opener)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        state.errors.append(f"{context}: {kind} decompression failed: {exc}")
        return
    if len(data) > MAX_ENTRY_BYTES:
        state.unsupported.append({
            "path": context,
            "format": kind,
            "reason": "decompressed past the size cap; output truncated",
        })
        state.truncated = True
        return
    inner_name = path.name
    for suffix in (".gz", ".gzip", ".bz2", ".xz", ".tgz", ".txz"):
        if inner_name.lower().endswith(suffix):
            inner_name = inner_name[: -len(suffix)]
            break
    if not inner_name:
        inner_name = f"{path.name}.out"
    child = _write_child(
        state, len(state.children), inner_name, data,
        extractor=kind, reason=f"{kind}-compressed member", depth=depth,
    )
    state.add_flag(f"{kind}-stream")
    if depth < state.max_depth and state.budget_left():
        _recurse(child, state, depth)


def _extract_tar(path: Path, state: _State, depth: int, context: str) -> None:
    try:
        archive = tarfile.open(path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        state.errors.append(f"{context}: could not open tar: {exc}")
        return

    index = len(state.children)
    with archive:
        for member in archive.getmembers():
            if not state.budget_left():
                state.truncated = True
                state.add_flag("child-limit-reached")
                break
            if not member.isfile():
                if member.issym() or member.islnk() or member.isdev():
                    state.unsupported.append({
                        "path": f"{context}!/{member.name}",
                        "format": "special-member",
                        "reason": f"tar member is {member.type!r}; refused",
                    })
                continue
            safe = _safe_member_name(member.name)
            if safe is None:
                continue
            if member.size > MAX_ENTRY_BYTES:
                state.unsupported.append({
                    "path": f"{context}!/{safe}",
                    "format": "oversize",
                    "reason": f"declared size {member.size} exceeds the cap",
                })
                continue
            try:
                extracted = archive.extractfile(member)
                data = extracted.read(MAX_ENTRY_BYTES + 1) if extracted else b""
            except (tarfile.TarError, OSError) as exc:
                state.errors.append(f"{context}!/{safe}: read failed: {exc}")
                continue
            if len(data) > MAX_ENTRY_BYTES:
                state.truncated = True
                continue
            child = _write_child(
                state, index, safe, data,
                extractor="tar", reason="tar member", depth=depth,
                flags=_member_flags(safe),
            )
            index += 1
            if depth < state.max_depth and state.budget_left():
                _recurse(child, state, depth)


# ---------------------------------------------------------------------------
# HTML / SVG — extract script blocks so YARA and strings can see them
# ---------------------------------------------------------------------------

_JS_ESCAPE = re.compile(rb"\\x([0-9a-fA-F]{2})")
_JS_UNICODE = re.compile(rb"\\u([0-9a-fA-F]{4})")


def decode_js_escapes(data: bytes) -> bytes:
    """Decode simple JS hex/unicode escapes so obfuscated script is scannable.

    This is a best-effort de-obfuscation, not a JavaScript interpreter: it
    turns ``\\x41`` and ``\\u0041`` into their bytes. It cannot and does not
    resolve string concatenation, ``atob``, or runtime decoding.
    """
    def _hex(match: "re.Match[bytes]") -> bytes:
        return bytes([int(match.group(1), 16)])

    out = _JS_ESCAPE.sub(_hex, data)
    return _JS_UNICODE.sub(_hex, out)


class _ScriptCollector(HTMLParser):
    """Collect script text, inline handlers and remote references."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.handlers: list[str] = []
        self.references: list[str] = []
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attrs_map = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            self._in_script = True
            self._buf = []
            if attrs_map.get("src"):
                self.references.append(attrs_map["src"])
        for name, value in attrs:
            if name.lower().startswith("on") and value:
                self.handlers.append(f"{name}={value}")
        if tag in ("iframe", "embed", "object", "image", "use") and attrs_map.get("src"):
            self.references.append(attrs_map["src"])
        if tag == "object" and attrs_map.get("data"):
            self.references.append(attrs_map["data"])
        if tag == "meta" and attrs_map.get("http-equiv", "").lower() == "refresh":
            self.references.append(attrs_map.get("content", ""))

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self._in_script = False
            text = "".join(self._buf).strip()
            if text:
                self.scripts.append(text)
            self._buf = []


def _extract_markup(path: Path, state: _State, depth: int, kind: str) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        state.errors.append(f"{path.name}: could not read markup: {exc}")
        return

    collector = _ScriptCollector()
    try:
        collector.feed(text)
        collector.close()
    except Exception as exc:  # HTMLParser raises on malformed input
        state.errors.append(f"{path.name}: HTML parse error: {exc}")

    flag = "svg-script" if kind == "svg" else "html-script"
    for i, script in enumerate(collector.scripts[:MAX_HTML_SCRIPTS]):
        decoded = decode_js_escapes(script.encode("utf-8", errors="replace"))
        member = f"{path.name}.script-{i}.js"
        _write_child(
            state, len(state.children), member, decoded,
            extractor=f"{kind}-script",
            reason=f"<script> block #{i} from {kind.upper()}",
            depth=depth,
            flags=[flag, "decoded-escapes"] if decoded != script.encode("utf-8", errors="replace") else [flag],
        )
        state.add_flag(flag)
    if len(collector.scripts) > MAX_HTML_SCRIPTS:
        state.truncated = True
        state.add_flag("script-limit-reached")
    if collector.handlers:
        state.add_flag(f"{kind}-inline-handler")
    if collector.references:
        state.add_flag(f"{kind}-remote-reference")


# ---------------------------------------------------------------------------
# Shell link (LNK) — MS-SHLLINK
# ---------------------------------------------------------------------------

_LNK_ROOT = 0x1F
_LNK_DRIVE = 0x2F
_LNK_PATH_TYPES = {0x31, 0x32, 0x35, 0x36}
_LNK_EXECUTABLE_SUFFIXES = (
    ".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1",
    ".bat", ".cmd", ".hta", ".msi", ".iso", ".img", ".lnk",
)


def _u16le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _cstring(data: bytes, offset: int, encoding: str = "utf-8") -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode(encoding, "replace")


def _lnk_string(data: bytes, offset: int, unicode: bool) -> tuple[str, int]:
    """Read a counted-string from a shell link; return (text, next offset)."""
    count = _u16le(data, offset)
    offset += 2
    if unicode:
        raw = data[offset:offset + count * 2]
        return raw.decode("utf-16-le", "replace"), offset + count * 2
    raw = data[offset:offset + count]
    return raw.decode("cp1252", "replace"), offset + count


def _lnk_idlist_path(idlist: bytes) -> str:
    """Best-effort target path from a LinkTargetIDList (shell item list).

    The item list is the form ``WScript.Shell.CreateShortcut`` writes when only
    ``TargetPath`` is set. Only the short (8.3) segment names are decoded here;
    LinkInfo, when present, is authoritative and is preferred by the caller.
    """
    items: list[bytes] = []
    pos = 0
    while pos + 2 <= len(idlist):
        size = _u16le(idlist, pos)
        if size < 2:
            break
        items.append(idlist[pos + 2:pos + size])
        pos += size

    segments: list[str] = []
    for item in items:
        if len(item) < 2:
            continue
        if item[0] == _LNK_DRIVE and len(item) >= 4:
            segments.append(item[1:3].decode("ascii", "replace"))
            continue
        if item[0] == _LNK_ROOT:
            continue
        item_type = _u16le(item, 0)
        if item_type not in _LNK_PATH_TYPES or len(item) <= 12:
            continue
        if item_type in (0x35, 0x36):
            end = 12
            while end + 1 < len(item) and item[end:end + 2] != b"\x00\x00":
                end += 2
            name = item[12:end].decode("utf-16-le", "replace")
        else:
            end = item.find(b"\x00", 12)
            if end < 0:
                end = len(item)
            name = item[12:end].decode("ascii", "replace")
        if name:
            segments.append(name)
    return "\\".join(segments)


def _lnk_link_info(data: bytes, pos: int) -> tuple[dict, int]:
    """Parse a LinkInfo structure. Returns (fields, structure size)."""
    size = _u32le(data, pos)
    if size < 0x1C or pos + size > len(data):
        return {}, max(size, 0x1C)
    header_size = _u32le(data, pos + 4)
    flags = _u32le(data, pos + 8)
    volume_off = _u32le(data, pos + 12)
    local_base_off = _u32le(data, pos + 16)
    network_off = _u32le(data, pos + 20)
    suffix_off = _u32le(data, pos + 24)

    info: dict = {}
    if flags & 1:  # VolumeIDAndLocalBasePath
        base = _cstring(data, pos + local_base_off)
        suffix = _cstring(data, pos + suffix_off) if header_size >= 0x24 and suffix_off else ""
        if base:
            info["target"] = base + suffix
        if volume_off and pos + volume_off + 16 <= len(data):
            label = _cstring(data, pos + volume_off + 16)
            if label:
                info["volume_label"] = label
    if flags & 2 and network_off:  # CommonNetworkRelativeLink
        share = _cstring(data, pos + network_off + 20)
        if share:
            info["network_share"] = share
    return info, size


def parse_lnk(path: Path) -> dict:
    """Parse a Windows shell link into its meaningful fields (best effort)."""
    data = path.read_bytes()
    if len(data) < 0x4C or data[0:4] != b"L\x00\x00\x00":
        raise ValueError("not a shell link")
    flags = _u32le(data, 20)
    is_unicode = bool(flags & 0x80)
    pos = 0x4C

    result: dict = {"flags": flags}
    if flags & 0x1:  # HasLinkTargetIDList
        idlist_size = _u16le(data, pos)
        pos += 2
        idlist = data[pos:pos + idlist_size]
        pos += idlist_size
        path_from_idlist = _lnk_idlist_path(idlist)
        if path_from_idlist:
            result["target_idlist"] = path_from_idlist
    if flags & 0x2:  # HasLinkInfo
        info, size = _lnk_link_info(data, pos)
        pos += size
        result.update(info)

    for flag, key in (
        (0x4, "description"),
        (0x8, "relative_path"),
        (0x10, "working_dir"),
        (0x20, "arguments"),
        (0x40, "icon_location"),
    ):
        if flags & flag and pos + 2 <= len(data):
            text, pos = _lnk_string(data, pos, is_unicode)
            result[key] = text

    environment_targets: list[str] = []
    while pos + 8 <= len(data):
        block_size = _u32le(data, pos)
        if block_size < 4 or pos + block_size > len(data):
            break
        signature = _u32le(data, pos + 4)
        if signature == 0:
            break
        if signature in (0xA0000001, 0xA0000007):  # EnvironmentVariable / IconEnvironment blocks
            block = data[pos:pos + block_size]
            ansi = _cstring(block, 8)
            unicode_target = block[8 + 260:8 + 260 + 520].decode("utf-16-le", "replace")
            unicode_target = unicode_target.split("\x00", 1)[0]
            target = unicode_target or ansi
            if target:
                environment_targets.append(target)
        pos += block_size
    if environment_targets:
        result["environment_target"] = environment_targets
    return result


def _extract_lnk(path: Path, state: _State, depth: int, context: str) -> None:
    try:
        link = parse_lnk(path)
    except (ValueError, OSError) as exc:
        state.errors.append(f"{context}: shell-link parse failed: {exc}")
        return
    state.details["link"] = link

    targets = [value for value in (link.get("target"), link.get("target_idlist")) if value]
    if link.get("network_share"):
        targets.append(link["network_share"])
    targets.extend(link.get("environment_target") or [])

    flags = ["lnk"]
    if link.get("arguments"):
        flags.append("lnk-arguments")
    if any(target.startswith("\\\\") for target in targets):
        flags.append("lnk-remote-target")
    if any(target.lower().endswith(_LNK_EXECUTABLE_SUFFIXES) for target in targets):
        flags.append("lnk-executable-target")

    lines = ["HATCHERY shell-link dissection", ""]
    for key in (
        "target", "target_idlist", "network_share", "arguments", "working_dir",
        "description", "icon_location", "relative_path", "volume_label",
    ):
        if link.get(key):
            lines.append(f"{key}: {link[key]}")
    for target in link.get("environment_target") or []:
        lines.append(f"environment_target: {target}")
    payload = "\n".join(lines).encode("utf-8")

    _write_child(
        state, len(state.children), f"{path.name}.txt", payload,
        extractor="lnk", reason="decoded shell-link fields", depth=depth, flags=flags,
    )
    for flag in flags:
        state.add_flag(flag)


# ---------------------------------------------------------------------------
# ISO 9660 / IMG
# ---------------------------------------------------------------------------

_ISO_SECTOR = 2048


def _iso_descriptor(data: bytes, lba: int) -> Optional[bytes]:
    offset = lba * _ISO_SECTOR
    if offset + _ISO_SECTOR > len(data):
        return None
    descriptor = data[offset:offset + _ISO_SECTOR]
    if descriptor[1:6] != b"CD001":
        return None
    return descriptor


def _iso_entries(data: bytes, extent_lba: int, length: int, joliet: bool) -> list[tuple[str, bool, int, int]]:
    entries: list[tuple[str, bool, int, int]] = []
    start = extent_lba * _ISO_SECTOR
    end = min(start + length, len(data))
    pos = start
    while pos < end:
        record_len = data[pos]
        if record_len == 0:
            pos = ((pos // _ISO_SECTOR) + 1) * _ISO_SECTOR
            continue
        if record_len < 34 or pos + record_len > end:
            break
        record = data[pos:pos + record_len]
        extent = _u32le(record, 2)
        size = _u32le(record, 10)
        flags = record[25]
        name_len = record[32]
        name_bytes = record[33:33 + name_len]
        if name_len == 1 and name_bytes == b"\x00":
            name = "."
        elif name_len == 1 and name_bytes == b"\x01":
            name = ".."
        else:
            name = name_bytes.decode("utf-16-be" if joliet else "ascii", "replace")
        if name.endswith(";1"):
            name = name[:-2]
        entries.append((name, bool(flags & 0x2), extent, size))
        pos += record_len
    return entries


def _extract_iso(path: Path, state: _State, depth: int, context: str) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        state.errors.append(f"{context}: read failed: {exc}")
        return
    if len(data) > MAX_ENTRY_BYTES:
        data = data[:MAX_ENTRY_BYTES]
        state.truncated = True
        state.add_flag("iso-truncated-read")

    pvd = _iso_descriptor(data, 16)
    if pvd is None:
        state.errors.append(f"{context}: no ISO9660 primary volume descriptor")
        return
    joliet = False
    svd = _iso_descriptor(data, 17)
    if svd is not None and svd[0] == 2 and svd[88:90] == b"%/":
        joliet = True

    state.details["iso"] = {
        "volume_identifier": pvd[40:72].decode("ascii", "replace").strip(),
        "volume_space_size": _u32le(pvd, 80),
        "joliet": joliet,
    }
    state.add_flag("iso9660-joliet" if joliet else "iso9660")

    # The root directory record must come from the descriptor that matches the
    # name encoding, or Joliet (UCS-2) names get decoded against the ISO9660
    # root and come out as mojibake.
    root_descriptor = svd if joliet and svd is not None else pvd
    root_extent = _u32le(root_descriptor, 156 + 2)
    root_length = _u32le(root_descriptor, 156 + 10)
    index = len(state.children)
    seen_files = 0
    visited: set[int] = set()
    queue: list[tuple[int, int, str]] = [(root_extent, root_length, "")]
    while queue:
        extent_lba, length, prefix = queue.pop(0)
        if extent_lba in visited:
            continue
        visited.add(extent_lba)
        for name, is_dir, child_extent, child_size in _iso_entries(data, extent_lba, length, joliet):
            if name in (".", ".."):
                continue
            relative = f"{prefix}/{name}" if prefix else name
            if is_dir:
                if len(queue) < MAX_CHILDREN:
                    queue.append((child_extent, child_size, relative))
                continue
            if not state.budget_left():
                state.truncated = True
                state.add_flag("child-limit-reached")
                break
            if child_size > MAX_ENTRY_BYTES:
                state.unsupported.append({
                    "path": f"{context}!/{relative}", "format": "oversize",
                    "reason": f"ISO extent of {child_size} bytes exceeds the cap",
                })
                continue
            file_offset = child_extent * _ISO_SECTOR
            payload = data[file_offset:file_offset + child_size]
            child = _write_child(
                state, index, relative, payload,
                extractor="iso", reason="ISO9660 file", depth=depth,
                flags=_member_flags(relative),
            )
            index += 1
            seen_files += 1
            if depth < state.max_depth and state.budget_left():
                _recurse(child, state, depth)
    if seen_files == 0:
        state.add_flag("iso-no-files")


# ---------------------------------------------------------------------------
# PDF — targeted embedded-file and JavaScript extraction (best effort)
# ---------------------------------------------------------------------------

_PDF_OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")


def _pdf_unescape(raw: bytes) -> bytes:
    out = bytearray()
    i = 0
    escapes = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}
    while i < len(raw):
        byte = raw[i]
        if byte == 0x5C and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
            if 0x30 <= nxt <= 0x37:
                j = i + 1
                octal = 0
                for _ in range(3):
                    if j < len(raw) and 0x30 <= raw[j] <= 0x37:
                        octal = octal * 8 + (raw[j] - 0x30)
                        j += 1
                    else:
                        break
                out.append(octal & 0xFF)
                i = j
                continue
            i += 2
            continue
        out.append(byte)
        i += 1
    return bytes(out)


def _pdf_read_literal(data: bytes, start: int) -> Optional[bytes]:
    """Read a balanced ``(...)`` string starting at the opening paren."""
    depth = 0
    i = start
    while i < len(data):
        byte = data[i]
        if byte == 0x5C:
            i += 2
            continue
        if byte == 0x28:
            depth += 1
        elif byte == 0x29:
            depth -= 1
            if depth == 0:
                return data[start + 1:i]
        i += 1
    return None


def _pdf_filters(dict_text: bytes) -> list[str]:
    match = re.search(rb"/Filter\s*(\[[^\]]*\]|/\w+)", dict_text)
    if not match:
        return []
    return [name.decode("ascii", "replace") for name in re.findall(rb"/(\w+)", match.group(1))]


def _pdf_decode_stream(
    raw: bytes, filters: list[str], state: _State, context: str
) -> Optional[bytes]:
    for name in filters:
        try:
            if name == "FlateDecode":
                raw = zlib.decompress(raw)
            elif name == "ASCIIHexDecode":
                payload = re.sub(rb"\s+", b"", raw.split(b">", 1)[0])
                if len(payload) % 2:
                    payload += b"0"
                raw = bytes.fromhex(payload.decode("ascii"))
            elif name == "ASCII85Decode":
                raw = base64.a85decode(raw.split(b"~>", 1)[0].strip())
            else:
                state.unsupported.append({
                    "path": context, "format": f"pdf-filter:{name}",
                    "reason": f"PDF filter {name} is not decoded in this revision",
                })
                return None
        except (zlib.error, ValueError, TypeError):
            state.errors.append(f"{context}: PDF filter {name} failed")
            return None
    return raw


def _extract_pdf(path: Path, state: _State, depth: int, context: str) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        state.errors.append(f"{context}: read failed: {exc}")
        return
    if len(data) > MAX_ENTRY_BYTES:
        data = data[:MAX_ENTRY_BYTES]
        state.truncated = True
        state.add_flag("pdf-truncated-read")

    for token, flag in (
        (b"/JavaScript", "pdf-javascript"), (b"/JS", "pdf-javascript"),
        (b"/Launch", "pdf-launch-action"), (b"/OpenAction", "pdf-open-action"),
        (b"/URI", "pdf-uri-action"), (b"/EmbeddedFile", "pdf-embedded-file"),
        (b"/RichMedia", "pdf-richmedia"),
    ):
        if token in data:
            state.add_flag(flag)
    state.add_flag("pdf")

    objects: dict[int, tuple[bytes, Optional[bytes], bytes]] = {}
    for match in _PDF_OBJ_RE.finditer(data):
        number = int(match.group(1))
        end = data.find(b"endobj", match.end())
        if end < 0:
            end = len(data)
        body = data[match.end():end]
        dict_text = body
        stream: Optional[bytes] = None
        stream_type = b""
        stream_start = re.search(rb"\bstream\r?\n", body)
        if stream_start:
            dict_text = body[:stream_start.start()]
            stop = body.find(b"endstream", stream_start.end())
            raw = body[stream_start.end():stop if stop >= 0 else len(body)]
            length_match = re.search(rb"/Length\s+(\d+)", dict_text)
            if length_match:
                raw = raw[:int(length_match.group(1))]
            stream = _pdf_decode_stream(raw, _pdf_filters(dict_text), state, f"{context} obj {number}")
            type_match = re.search(rb"/(?:Subtype|Type)\s*/(\w+)", dict_text)
            if type_match:
                stream_type = type_match.group(1)
        objects[number] = (dict_text, stream, stream_type)

    named: set[str] = set()
    consumed: set[int] = set()
    embedded: list[tuple[str, bytes]] = []
    for number, (dict_text, _, _) in objects.items():
        if b"/Filespec" not in dict_text:
            continue
        name_match = re.search(rb"/(?:UF|F)\s*\(([^)]*)\)", dict_text)
        name = _pdf_unescape(name_match.group(1)).decode("utf-8", "replace") if name_match else f"file-{number}"
        ref = re.search(rb"/EF\s*<<\s*/(?:UF|F)\s+(\d+)\s+\d+\s+R", dict_text)
        if ref:
            target = int(ref.group(1))
            entry = objects.get(target)
            if entry and entry[1] is not None:
                embedded.append((name, entry[1]))
                named.add(name)
                consumed.add(target)
    for number, (dict_text, stream, _) in objects.items():
        if number in consumed or stream is None or b"/EmbeddedFile" not in dict_text:
            continue
        name_match = re.search(rb"/(?:UF|F)\s*\(([^)]*)\)", dict_text)
        name = _pdf_unescape(name_match.group(1)).decode("utf-8", "replace") if name_match else f"embedded-{number}.bin"
        if name not in named:
            embedded.append((name, stream))
            named.add(name)

    index = len(state.children)
    for name, payload in embedded:
        if not state.budget_left():
            state.truncated = True
            state.add_flag("child-limit-reached")
            break
        safe = _safe_member_name(name) or f"embedded-{index}.bin"
        child = _write_child(
            state, index, safe, payload,
            extractor="pdf", reason="PDF embedded file", depth=depth,
            flags=["pdf-embedded-file"],
        )
        index += 1
        if depth < state.max_depth and state.budget_left():
            _recurse(child, state, depth)

    js_blobs: list[bytes] = []
    for match in re.finditer(rb"/JS\s*(\()", data):
        literal = _pdf_read_literal(data, match.start(1))
        if literal is not None:
            js_blobs.append(decode_js_escapes(_pdf_unescape(literal)))
    for match in re.finditer(rb"/JS\s*<([0-9A-Fa-f\s]*)>", data):
        payload = re.sub(rb"\s+", b"", match.group(1))
        if len(payload) % 2:
            payload += b"0"
        try:
            js_blobs.append(bytes.fromhex(payload.decode("ascii")))
        except ValueError:
            continue
    for number, (dict_text, stream, stream_type) in objects.items():
        if stream is not None and (stream_type in (b"JavaScript",) or b"/S /JavaScript" in dict_text):
            js_blobs.append(stream)

    for i, blob in enumerate(js_blobs[:MAX_HTML_SCRIPTS]):
        _write_child(
            state, len(state.children), f"{path.name}.js-{i}.js", blob,
            extractor="pdf-js", reason=f"PDF JavaScript blob #{i}", depth=depth,
            flags=["pdf-javascript"],
        )
    if js_blobs:
        state.add_flag("pdf-javascript")
    if len(js_blobs) > MAX_HTML_SCRIPTS:
        state.truncated = True
        state.add_flag("script-limit-reached")


# ---------------------------------------------------------------------------
# OLE / CFB — legacy Office compound files
# ---------------------------------------------------------------------------

_OLE_OFFICE_STREAMS = {"worddocument", "workbook", "book", "powerpoint document"}


def _ole_stream_flags(path: str) -> list[str]:
    """Flags for one compound-file stream, keyed off its leaf and storages."""

    leaf = path.rsplit("/", 1)[-1].lower()
    parts = {part.lower() for part in path.split("/")}
    flags = ["ole"]
    if leaf in ("dir", "_vba_project") or "vba" in parts:
        flags.append("ole-vba")
    if "objectpool" in parts or leaf == "ole10native" or leaf == "package":
        flags.append("ole-embedded-object")
    if leaf in _OLE_OFFICE_STREAMS:
        flags.append("ole-legacy-office")
    return flags


def _extract_ole(path: Path, state: _State, depth: int, context: str) -> None:
    """Enumerate an OLE/CFB compound file and extract the parts that matter.

    Order is deliberate: embedded VBA macro *source* and carved package
    payloads are written first, so the shared child budget cannot starve the
    security-relevant content; the raw streams follow so YARA and the string
    extractor still see everything else. Nothing is executed.
    """

    try:
        data = path.read_bytes()
    except OSError as exc:
        state.errors.append(f"{context}: read failed: {exc}")
        return
    if len(data) > MAX_ENTRY_BYTES:
        data = data[:MAX_ENTRY_BYTES]
        state.truncated = True
        state.add_flag("ole-truncated-read")
    try:
        cfb = ole.CompoundFile(
            data,
            max_streams=state.max_children * 4,
            max_stream_bytes=MAX_ENTRY_BYTES,
        )
    except ole.OleError as exc:
        state.errors.append(f"{context}: OLE/CFB parse failed: {exc}")
        return

    state.add_flag("ole")
    state.details.setdefault("ole", {})
    state.details["ole"][context] = {
        "streams": [entry.path for entry in cfb.streams],
        "storages": list(cfb.storages),
    }

    # 1. Embedded VBA projects — decompress the module source. The dir stream
    #    and every module stream are MS-OVBA-compressed; without this step a
    #    macro document only ever yields opaque compressed bytes.
    for vba_root, project_path, dir_path in ole.find_vba_projects(cfb):
        try:
            modules = ole.parse_vba_modules(cfb, vba_root, project_path, dir_path)
        except ole.OleError as exc:
            state.errors.append(f"{context}: VBA project parse failed: {exc}")
            continue
        if not modules:
            continue
        state.add_flag("ole-vba-macro")
        for module in modules:
            if not state.budget_left():
                state.truncated = True
                state.add_flag("child-limit-reached")
                break
            extension = module.ext or ("cls" if module.kind == "class" else "bas")
            _write_child(
                state, len(state.children), f"{module.name}.{extension}",
                (module.source or "").encode("utf-8"),
                extractor="ole-vba", reason="decompressed VBA module source",
                depth=depth, flags=["ole-vba-macro"],
            )

    # 2. \x01Ole10Native package streams — carve the embedded file out of the
    #    MS-OLEDS wrapper. This is usually the executable a legacy document drops.
    for entry in cfb.streams:
        if entry.leaf_name.lower() != "ole10native":
            continue
        if not state.budget_left():
            state.truncated = True
            state.add_flag("child-limit-reached")
            break
        try:
            native = ole.parse_ole10native(cfb.read_stream(entry))
        except ole.OleError:
            continue
        if native is None or not native.payload:
            continue
        state.add_flag("ole-embedded-native")
        name = _safe_member_name(native.filename) or "ole10native.bin"
        child = _write_child(
            state, len(state.children), name, native.payload,
            extractor="ole-native",
            reason="embedded file carved from an OLE package stream",
            depth=depth, flags=["ole-embedded-native"],
        )
        entry_details = state.details["ole"].get(context)
        if entry_details is not None:
            entry_details.setdefault("embedded", []).append(native.filename or name)
        if depth < state.max_depth and state.budget_left():
            _recurse(child, state, depth)

    # 3. Every remaining raw stream, so YARA/strings still see container-wide
    #    content (WordDocument, _VBA_PROJECT, ObjectPool, ...).
    for entry in cfb.streams:
        if not state.budget_left():
            state.truncated = True
            state.add_flag("child-limit-reached")
            break
        flags = _ole_stream_flags(entry.path)
        try:
            payload = cfb.read_stream(entry)
        except ole.OleError as exc:
            state.errors.append(f"{context}!/{entry.path}: stream read failed: {exc}")
            continue
        child = _write_child(
            state, len(state.children), entry.path, payload,
            extractor="ole", reason="OLE/CFB stream", depth=depth, flags=flags,
        )
        for flag in flags:
            state.add_flag(flag)
        if depth < state.max_depth and state.budget_left():
            _recurse(child, state, depth)


# ---------------------------------------------------------------------------
# Recursion
# ---------------------------------------------------------------------------

_EXTRACTORS = {
    DeliveryFormat.ZIP: "zip",
    DeliveryFormat.OOXML: "zip",
    DeliveryFormat.TAR: "tar",
    DeliveryFormat.GZIP: "gzip",
    DeliveryFormat.BZIP2: "bzip2",
    DeliveryFormat.XZ: "xz",
    DeliveryFormat.HTML: "html",
    DeliveryFormat.SVG: "svg",
    DeliveryFormat.LNK: "lnk",
    DeliveryFormat.ISO: "iso",
    DeliveryFormat.PDF: "pdf",
    DeliveryFormat.OLE: "ole",
}


def _recurse(child: ExtractedChild, state: _State, depth: int) -> None:
    """Recurse into a freshly extracted child when it is itself a container."""
    classification = classify_delivery(child.path)
    if classification.format is not DeliveryFormat.UNKNOWN:
        child.format = classification.format.value
    if classification.format not in _EXTRACTORS:
        if classification.format.value in DELIVERY_FORMATS:
            state.unsupported.append({
                "path": f"{child.name} ({child.rel_path})",
                "format": classification.format.value,
                "reason": _unsupported_reason(classification.format),
            })
        return
    _dispatch(child.path, classification.format, state, depth + 1, child.name)


def _dispatch(path: Path, fmt: DeliveryFormat, state: _State, depth: int, context: str) -> None:
    if fmt in (DeliveryFormat.ZIP, DeliveryFormat.OOXML):
        _extract_zip(path, state, depth, context)
    elif fmt is DeliveryFormat.TAR:
        _extract_tar(path, state, depth, context)
    elif fmt in (DeliveryFormat.GZIP, DeliveryFormat.BZIP2, DeliveryFormat.XZ):
        _extract_stream(path, state, depth, context, fmt.value)
    elif fmt is DeliveryFormat.HTML:
        _extract_markup(path, state, depth, "html")
    elif fmt is DeliveryFormat.SVG:
        _extract_markup(path, state, depth, "svg")
    elif fmt is DeliveryFormat.LNK:
        _extract_lnk(path, state, depth, context)
    elif fmt is DeliveryFormat.ISO:
        _extract_iso(path, state, depth, context)
    elif fmt is DeliveryFormat.PDF:
        _extract_pdf(path, state, depth, context)
    elif fmt is DeliveryFormat.OLE:
        _extract_ole(path, state, depth, context)


def _unsupported_reason(fmt: DeliveryFormat) -> str:
    reasons = {
        DeliveryFormat.RTF: (
            "RTF embedded-object extraction is not implemented in this "
            "revision; the document is still scanned as raw bytes"
        ),
        DeliveryFormat.SEVEN_ZIP: "7-Zip extraction requires an external library; not extracted",
        DeliveryFormat.RAR: "RAR extraction requires an external library; not extracted",
        DeliveryFormat.CAB: "CAB extraction is not implemented in this revision",
        DeliveryFormat.MACHO: "Mach-O is a binary, not a container",
    }
    return reasons.get(fmt, "extraction not implemented in this revision")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract_delivery(
    path: Path,
    output_dir: Path,
    *,
    max_depth: int = MAX_DEPTH,
    max_children: int = MAX_CHILDREN,
) -> DeliveryIntakeResult:
    """Extract a delivery container's contents into ``output_dir``.

    This is the single intake path. It never raises for a malformed container:
    every failure is recorded in ``errors`` and returned, so a caller cannot
    mistake "extraction failed" for "container was empty". A detected-but-
    unsupported format is recorded in ``unsupported`` with a reason.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    state = _State(
        out_root=output_dir,
        max_depth=max(1, min(max_depth, MAX_DEPTH)),
        max_children=max(1, min(max_children, MAX_CHILDREN)),
    )
    classification = DeliveryClassification(DeliveryFormat.UNKNOWN)

    try:
        classification = classify_delivery(path)
        if classification.format in _EXTRACTORS:
            _dispatch(path, classification.format, state, 1, path.name)
        elif classification.format.value in DELIVERY_FORMATS:
            state.unsupported.append({
                "path": path.name,
                "format": classification.format.value,
                "reason": _unsupported_reason(classification.format),
            })
    except Exception as exc:  # never let a bad container abort the analysis
        logger.exception("Delivery intake failed for %s", path)
        state.errors.append(f"{path.name}: delivery intake failed: {exc}")

    result = DeliveryIntakeResult(
        classification=classification,
        children=state.children,
        unsupported=state.unsupported,
        flags=state.flags,
        errors=state.errors,
        truncated=state.truncated,
        details=state.details,
    )
    logger.info(
        "Delivery intake %s: format=%s children=%d unsupported=%d flags=%s",
        path.name, result.format.value, len(result.children),
        len(result.unsupported), result.flags,
    )
    return result
