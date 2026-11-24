"""Deterministic hostile corpus — one lie per file (D39).

Every fixture here is built from a *valid* artifact with exactly one property
broken, so a failure names the lie rather than "some bytes". They are generated
in-process (no committed binaries, no manifest to keep in sync) and the tests
assert they are byte-identical across builds.

The corpus is the answer to "no fuzzing, no property tests in the suite". Each
row states which stage consumes it and what the stage must record. A fixture
that merely "does not crash" proves nothing: the assertion is that the outcome
is **named, bounded and fast**.

Nothing in this module ships; it is not collected by pytest (leading ``_``).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
PE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "benign_pe.exe"
ELF_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "acceptance" / "benign" / "hello.elf"

MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_CHILDREN = 64
MAX_DEPTH = 3


@dataclass(frozen=True)
class Hostile:
    """One deliberate lie and the outcome it must produce."""

    name: str
    lie: str
    stage: str
    data: bytes
    #: Substrings; at least one must appear in the stage's recorded reasons.
    #: Empty means "a bounded result is the honest outcome" (nothing to refuse).
    expect: tuple[str, ...] = ()
    #: Parser keyword arguments this row needs (e.g. a tighter object cap, so a
    #: 2 MiB fixture can exercise a bound without a 64 MiB file).
    options: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Builders — a valid artifact with one field broken
# ---------------------------------------------------------------------------


#: A fixed DOS timestamp. ``zipfile.writestr`` stamps "now" by default, which
#: would make a "deterministic" corpus differ between two builds in the same run.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _zip(members: dict[str, bytes], *, compress: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compress) as archive:
        for name, payload in members.items():
            info = zipfile.ZipInfo(name, date_time=_ZIP_EPOCH)
            info.compress_type = compress
            archive.writestr(info, payload)
    return buffer.getvalue()


def _patch(data: bytes, offset: int, replacement: bytes) -> bytes:
    return data[:offset] + replacement + data[offset + len(replacement):]


def _find_central_directory(data: bytes) -> int:
    offset = data.find(b"PK\x01\x02")
    assert offset >= 0, "the fixture was supposed to contain a central directory"
    return offset


def _tar(members: list[tuple[str, bytes, bytes]]) -> bytes:
    """``(name, payload, type)`` where type is ``b"0"`` file or ``b"2"`` symlink."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == b"0":
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = "target"
                archive.addfile(info)
    return buffer.getvalue()


def _patch_tar_size(data: bytes, size_field: str) -> bytes:
    """Overwrite the first member's 12-byte octal size field (offset 124)."""
    assert len(size_field) == 12
    return _patch(data, 124, size_field.encode("ascii"))


def _cfb(streams: dict[str, bytes]) -> bytes:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _ole_builder import build_cfb  # type: ignore[import-not-found]

    return build_cfb(streams)


def corpus() -> dict[str, Hostile]:
    """The hostile corpus, keyed by fixture name. Deterministic by construction."""

    rows: list[Hostile] = []

    # -- ZIP -----------------------------------------------------------------
    valid_zip = _zip({"invoice.txt": b"A" * 64})
    rows.append(Hostile(
        "zip_truncated_central_directory",
        "the central directory is cut in half",
        "delivery",
        valid_zip[:-20],
        ("could not open ZIP", "read failed"),
    ))

    size_lie = _zip({"payload.bin": b"small"}, compress=zipfile.ZIP_STORED)
    central = _find_central_directory(size_lie)
    # Central-directory header offset 24 is the uncompressed size.
    size_lie = _patch(size_lie, central + 24, struct.pack("<I", 0xFFFFFFF0))
    rows.append(Hostile(
        "zip_declared_size_lie",
        "the central directory declares a 4 GiB member",
        "delivery",
        size_lie,
        ("exceeds", "oversize", "declared size"),
    ))

    rows.append(Hostile(
        "zip_ratio_bomb",
        "8 MiB of zeros in an ~8 KiB member (1000:1)",
        "delivery",
        _zip({"bomb.bin": b"\x00" * (8 * 1024 * 1024)}),
        ("zip-bomb guard", "compression ratio"),
    ))

    rows.append(Hostile(
        "zip_member_traversal",
        "../../etc/passwd as a member name",
        "delivery",
        _zip({"../../etc/passwd": b"root:x:0:0:root:/root:/bin/sh\n"}),
        (),
    ))

    symlink = io.BytesIO()
    with zipfile.ZipFile(symlink, "w") as archive:
        info = zipfile.ZipInfo("link", date_time=_ZIP_EPOCH)
        info.external_attr = (0o120777 << 16)
        archive.writestr(info, b"/etc/passwd")
    rows.append(Hostile(
        "zip_symlink_member",
        "a member whose Unix mode says symlink",
        "delivery",
        symlink.getvalue(),
        ("symlink",),
    ))

    # Incompressible payload, so the deflate body is long enough to corrupt
    # without touching the central directory that follows it.
    noise = b"".join(
        hashlib.sha256(str(i).encode("ascii")).digest() for i in range(128)
    )
    corrupt = bytearray(_zip({"payload.bin": noise}))
    body_start = 30 + len("payload.bin")
    for index in range(body_start, body_start + 16):
        corrupt[index] ^= 0xFF
    rows.append(Hostile(
        "zip_corrupt_deflate",
        "valid headers, undecodable deflate body",
        "delivery",
        bytes(corrupt),
        ("read failed", "could not open ZIP"),
    ))

    # -- tar -----------------------------------------------------------------
    valid_tar = _tar([("hello.txt", b"hello", b"0")])
    rows.append(Hostile(
        "tar_truncated_header",
        "300 bytes of a tar header",
        "delivery",
        valid_tar[:300],
        ("tar",),
    ))
    rows.append(Hostile(
        "tar_declared_size_lie",
        "the header claims an 8 GiB member",
        "delivery",
        _patch_tar_size(valid_tar, "77777777777\x00"),
        ("tar", "exceeds", "declared size"),
    ))
    rows.append(Hostile(
        "tar_member_traversal",
        "../evil.txt as a member name",
        "delivery",
        _tar([("../evil.txt", b"pwn", b"0")]),
        (),
    ))
    rows.append(Hostile(
        "tar_symlink_member",
        "a member of type symlink",
        "delivery",
        _tar([("link", b"", b"2")]),
        ("refused", "special-member"),
    ))

    # -- gzip ----------------------------------------------------------------
    rows.append(Hostile(
        "gzip_corrupt_deflate",
        "a gzip header followed by garbage",
        "delivery",
        b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" + b"\xff" * 256,
        ("decompression failed",),
    ))
    good = gzip.compress(b"E" * 4096, mtime=0)
    rows.append(Hostile(
        "gzip_isize_lie",
        "the trailer's ISIZE says 4 GiB",
        "delivery",
        _patch(good, len(good) - 4, b"\xff\xff\xff\xff"),
        ("decompression failed",),
    ))

    # -- OLE / CFB -----------------------------------------------------------
    valid_cfb = _cfb({"WordDocument": b"\xec\xa5\xc1\x00" + b"A" * 5000})
    rows.append(Hostile(
        "ole_truncated",
        "a valid header with the sectors cut away",
        "ole",
        valid_cfb[:600],
        ("no FAT sectors",),
    ))

    bad_shift = _patch(valid_cfb, 30, struct.pack("<H", 0x1F))
    rows.append(Hostile(
        "ole_impossible_sector_shift",
        "sector shift 31 (a 2 GiB sector)",
        "ole",
        bad_shift,
        ("unreasonable CFB sector shift",),
    ))

    first_dir = struct.unpack_from("<I", valid_cfb, 48)[0]
    looping = _patch(valid_cfb, 48, struct.pack("<I", 0xFFFFFFF0))
    rows.append(Hostile(
        "ole_directory_sector_out_of_range",
        "the first directory sector points past EOF",
        "ole",
        looping,
        ("no directory", "out of range"),
    ))

    first_fat = struct.unpack_from("<I", valid_cfb, 76)[0]
    fat_offset = (first_fat + 1) * 512
    cycled = _patch(valid_cfb, fat_offset + first_dir * 4, struct.pack("<I", first_dir))
    rows.append(Hostile(
        "ole_fat_cycle",
        "the FAT entry for the directory sector points to itself",
        "ole",
        cycled,
        (),
    ))

    # -- RTF -----------------------------------------------------------------
    rows.append(Hostile(
        "rtf_group_depth",
        "20,000 nested groups in \\objdata",
        "rtf",
        b"{\\rtf1" + b"{\\*\\objdata " * 20_000 + b"}" * 20_001,
        ("nesting deeper",),
    ))
    rows.append(Hostile(
        "rtf_bin_past_end",
        "\\bin1000000 with ten bytes of data",
        "rtf",
        b"{\\rtf1{\\*\\objdata \\bin1000000 0123456789}}",
        ("past the end",),
    ))
    rows.append(Hostile(
        "rtf_embedded_object_over_cap",
        "2 MiB of hex in one \\objdata, capped at 64 bytes",
        "rtf",
        b"{\\rtf1{\\*\\objdata " + b"41" * (2 * 1024 * 1024) + b"}}",
        ("cap",),
        {"max_object_bytes": 1024},
    ))

    # -- PE ------------------------------------------------------------------
    pe_bytes = PE_FIXTURE.read_bytes()
    rows.append(Hostile(
        "pe_mz_only",
        "MZ magic and nothing else",
        "pe",
        b"MZ" + b"\x00" * 64,
        ("Invalid PE format", "parsing error", "pe"),
    ))
    rows.append(Hostile(
        "pe_lfanew_past_eof",
        "e_lfanew points past the end of the file",
        "pe",
        _patch(pe_bytes, 0x3C, struct.pack("<I", 0x7FFFFFF0)),
        ("Invalid PE format", "parsing error", "PE"),
    ))
    lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    rows.append(Hostile(
        "pe_section_count_lie",
        "NumberOfSections is 65535",
        "pe",
        _patch(pe_bytes, lfanew + 6, struct.pack("<H", 0xFFFF)),
        (),
    ))

    # -- ELF -----------------------------------------------------------------
    rows.append(Hostile(
        "elf_truncated",
        "16 bytes of ELF identification",
        "elf",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        ("parsing error", "ELF", "not"),
    ))
    elf_bytes = ELF_FIXTURE.read_bytes()
    rows.append(Hostile(
        "elf_section_table_lie",
        "e_shnum is 65535 and e_shoff is past EOF",
        "elf",
        _patch(_patch(elf_bytes, 0x28, struct.pack("<Q", 0x10000000)), 0x3C, struct.pack("<H", 0xFFFF)),
        ("parsing error", "ELF", "section"),
    ))
    rows.append(Hostile(
        "elf_impossible_class",
        "EI_CLASS is 7",
        "elf",
        _patch(elf_bytes, 4, b"\x07"),
        ("parsing error", "ELF", "class"),
    ))

    # -- strace --------------------------------------------------------------
    rows.append(Hostile(
        "strace_absurd_pid",
        "a 21-digit pid",
        "strace",
        b'999999999999999999999   execve("/bin/sh", ["sh", "-c", "id"], 0x7ffd) = 0\n',
        (),
    ))
    rows.append(Hostile(
        "strace_deep_nesting",
        "50,000 nested parentheses on one line",
        "strace",
        b"1234  " + b"(" * 50_000 + b"openat" + b")" * 50_000 + b" = 3\n",
        (),
    ))
    rows.append(Hostile(
        "strace_huge_line",
        "an 8 MiB single line with no newline",
        "strace",
        b"1234  write(1, \"" + b"A" * (8 * 1024 * 1024) + b"\", 8388608) = 8388608",
        (),
    ))

    # -- JSON documents ------------------------------------------------------
    rows.append(Hostile(
        "json_deep_nesting",
        "100,000 nested arrays where an object belongs",
        "json",
        b"[" * 100_000,
        ("not readable", "recursion", "not a JSON object"),
    ))

    return {row.name: row for row in rows}


def materialise(directory: Path, name: Optional[str] = None) -> dict[str, Path]:
    """Write the corpus (or one fixture) under ``directory`` and return paths."""
    directory.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for fixture in corpus().values():
        if name is not None and fixture.name != name:
            continue
        path = directory / fixture.name
        path.write_bytes(fixture.data)
        paths[fixture.name] = path
    return paths
