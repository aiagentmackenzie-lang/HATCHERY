"""Test-only builders for OLE/CFB and MS-OVBA fixtures.

The runtime parses OLE with the standard library (``engine/intake/ole.py``);
tests need to *produce* compound files, so these helpers write them by hand and
the suite then cross-validates the result against independent implementations:

* ``olefile`` — an independent CFB reader, so a writer bug cannot be mirrored
  by the reader without the cross-check failing.
* ``oletools`` — an independent MS-OVBA implementation, so the compressed
  module streams and the ``dir`` stream are confirmed to be genuinely valid.

Nothing in this module ships; it is not collected by pytest (leading ``_``).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

SECTOR = 512
MINI = 64
CUTOFF = 4096
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

_OVBA_SIGNATURE = 0x01


# ---------------------------------------------------------------------------
# MS-OVBA compression (literal-only is enough for fixtures; the copy-token
# path is exercised by a dedicated vector in the tests)
# ---------------------------------------------------------------------------


def compress_ovba(source: bytes) -> bytes:
    """Wrap ``source`` in a valid MS-OVBA compressed container.

    Emits literal tokens only. Each chunk's region (flag byte + literals) is
    kept at or below 4096 bytes, which is the MS-OVBA compressed-chunk limit.
    """

    out = bytearray([_OVBA_SIGNATURE])
    step = 3600  # region = 3600 + ceil(3600/8) = 4050 <= 4096
    for start in range(0, max(len(source), 1), step):
        chunk = source[start:start + step]
        if not chunk:
            break
        region = bytearray()
        for i in range(0, len(chunk), 8):
            region.append(0x00)  # every token in this group is a literal
            region.extend(chunk[i:i + 8])
        bits = len(region) - 1
        header = bits | (0b011 << 12) | (1 << 15)
        out += struct.pack("<H", header)
        out += bytes(region)
        if start + step >= len(source):
            break
    return bytes(out)


# ---------------------------------------------------------------------------
# dir stream (MS-OVBA 2.3.4.2)
# ---------------------------------------------------------------------------


def _record(rid: int, payload: bytes) -> bytes:
    return struct.pack("<HI", rid, len(payload)) + payload


def build_dir_stream(
    modules: list[dict],
    *,
    codepage: int = 1252,
    project_name: str = "Project",
) -> bytes:
    """Build a spec-shaped, uncompressed dir stream for the given modules.

    Each module dict carries ``name``, ``stream``, ``text_offset`` and
    ``kind`` (``"std"`` or ``"class"``).
    """

    out = bytearray()
    out += _record(0x0001, struct.pack("<I", 1))          # PROJECTSYSKIND 32-bit
    out += _record(0x0002, struct.pack("<I", 0x409))      # PROJECTLCID
    out += _record(0x0014, struct.pack("<I", 0x409))      # PROJECTLCIDINVOKE
    out += _record(0x0003, struct.pack("<H", codepage))   # PROJECTCODEPAGE
    out += _record(0x0004, project_name.encode("cp1252"))  # PROJECTNAME

    # PROJECTDOCSTRING (empty): record, reserved 0x0040, unicode length+data.
    out += _record(0x0005, b"")
    out += struct.pack("<H", 0x0040) + struct.pack("<I", 0)
    # PROJECTHELPFILEPATH (empty): record, reserved 0x003D, unicode length+data.
    out += _record(0x0006, b"")
    out += struct.pack("<H", 0x003D) + struct.pack("<I", 0)
    out += _record(0x0007, struct.pack("<I", 0))          # PROJECTHELPCONTEXT
    out += _record(0x0008, struct.pack("<I", 0))          # PROJECTLIBFLAGS
    # PROJECTVERSION: id, reserved (=4), major, minor.
    out += struct.pack("<H", 0x0009) + struct.pack("<I", 4) + struct.pack("<I", 0) + struct.pack("<H", 0)
    # PROJECTCONSTANTS (empty): record, reserved 0x003C, unicode length+data.
    out += _record(0x000C, b"")
    out += struct.pack("<H", 0x003C) + struct.pack("<I", 0)

    out += _record(0x000F, struct.pack("<H", len(modules)))  # PROJECTMODULES
    out += struct.pack("<HIH", 0x0013, 2, 0xFFFF)            # ProjectCookieRecord

    for module in modules:
        name = module["name"].encode("cp1252")
        name_unicode = module["name"].encode("utf-16-le")
        stream_name = module["stream"].encode("cp1252")
        stream_unicode = module["stream"].encode("utf-16-le")
        out += _record(0x0019, name)                          # MODULENAME
        out += _record(0x0047, name_unicode)                  # MODULENAMEUNICODE
        out += _record(0x001A, stream_name)                   # MODULESTREAMNAME
        out += struct.pack("<H", 0x0032) + struct.pack("<I", len(stream_unicode)) + stream_unicode
        out += _record(0x001C, b"")                          # MODULEDOCSTRING
        out += struct.pack("<H", 0x0048) + struct.pack("<I", 0)
        out += _record(0x0031, struct.pack("<I", module["text_offset"]))  # MODULEOFFSET
        out += _record(0x001E, struct.pack("<I", 0))          # MODULEHELPCONTEXT
        out += _record(0x002C, struct.pack("<H", 0xFFFF))     # MODULECOOKIE
        type_id = 0x0021 if module.get("kind", "std") == "std" else 0x0022
        out += struct.pack("<HI", type_id, 0)                 # MODULETYPE (reserved)
        out += struct.pack("<HI", 0x002B, 0)                  # MODULE TERMINATOR
    return bytes(out)


# ---------------------------------------------------------------------------
# OLENativeStream (\x01Ole10Native, MS-OLEDS 2.3.6)
# ---------------------------------------------------------------------------


def build_ole10native(
    payload: bytes,
    *,
    filename: str = "payload.exe",
    src_path: str = r"C:\Temp\payload.exe",
    temp_path: str = "C:\\Temp\\",
) -> bytes:
    body = bytearray()
    body += struct.pack("<H", 2)
    body += filename.encode("latin-1") + b"\x00"
    body += src_path.encode("latin-1") + b"\x00"
    body += struct.pack("<II", 0, 0)
    body += temp_path.encode("latin-1") + b"\x00"
    body += struct.pack("<I", len(payload))
    body += payload
    return struct.pack("<I", len(body)) + bytes(body)


# ---------------------------------------------------------------------------
# CFB writer
# ---------------------------------------------------------------------------


@dataclass
class _Node:
    name: str
    type: int
    data: bytes = b""
    children: list = field(default_factory=list)
    sid: int = -1
    child: int = NOSTREAM
    right: int = NOSTREAM
    start: int = 0
    size: int = 0


def _ceil_div(value: int, divisor: int) -> int:
    return (value + divisor - 1) // divisor


def _insert(root: _Node, path: str, data: bytes) -> None:
    node = root
    parts = path.split("/")
    for part in parts[:-1]:
        found = next((c for c in node.children if c.name == part and c.type == 1), None)
        if found is None:
            found = _Node(name=part, type=1)
            node.children.append(found)
        node = found
    node.children.append(_Node(name=parts[-1], type=2, data=data))


def _dir_entry(node: _Node) -> bytes:
    block = bytearray(128)
    encoded = (node.name.encode("utf-16-le") + b"\x00\x00")[:64]
    block[0:len(encoded)] = encoded
    struct.pack_into("<H", block, 64, len(encoded))
    block[66] = node.type
    block[67] = 1  # black
    struct.pack_into("<I", block, 68, NOSTREAM)                 # left
    struct.pack_into("<I", block, 72, node.right)               # right
    struct.pack_into("<I", block, 76, node.child if node.type in (1, 5) else NOSTREAM)
    struct.pack_into("<I", block, 116, node.start)
    struct.pack_into("<Q", block, 120, node.size)
    return bytes(block)


def build_cfb(streams: dict[str, bytes]) -> bytes:
    """Return a valid version-3 CFB containing ``streams`` (path -> bytes).

    Streams smaller than the 4096-byte mini-stream cutoff go through the mini
    FAT, exactly as real Office files store VBA metadata; larger ones use the
    regular FAT. Storages are implied by the path separators.
    """

    root = _Node(name="Root Entry", type=5)
    for path, data in streams.items():
        _insert(root, path, data)

    nodes: list[_Node] = []

    def assign(node: _Node) -> None:
        node.sid = len(nodes)
        nodes.append(node)
        for child in node.children:
            assign(child)

    assign(root)

    def link(node: _Node) -> None:
        previous = None
        for child in node.children:
            if previous is not None:
                previous.right = child.sid
            else:
                node.child = child.sid
            previous = child
            link(child)

    link(root)

    # Split streams: mini stream vs regular FAT stream.
    mini_nodes = [n for n in nodes if n.type == 2 and len(n.data) < CUTOFF]
    big_nodes = [n for n in nodes if n.type == 2 and len(n.data) >= CUTOFF]

    mini_sectors: list[bytes] = []
    minifat: list[int] = []
    for node in mini_nodes:
        if not node.data:
            node.start = ENDOFCHAIN
            node.size = 0
            continue
        count = _ceil_div(len(node.data), MINI)
        node.start = len(mini_sectors)
        node.size = len(node.data)
        for i in range(count):
            chunk = node.data[i * MINI:(i + 1) * MINI].ljust(MINI, b"\x00")
            mini_sectors.append(chunk)
            minifat.append(node.start + i + 1 if i < count - 1 else ENDOFCHAIN)
    mini_stream_data = b"".join(mini_sectors)

    big_sizes = [(node, _ceil_div(len(node.data), SECTOR)) for node in big_nodes]
    dir_sectors = max(1, _ceil_div(len(nodes) * 128, SECTOR))
    minifat_sectors = _ceil_div(max(1, len(minifat) * 4), SECTOR) if mini_stream_data else 0
    mini_sector_count = _ceil_div(len(mini_stream_data), SECTOR) if mini_stream_data else 0
    data_sectors = dir_sectors + minifat_sectors + mini_sector_count + sum(c for _, c in big_sizes)

    num_fat = 1
    while True:
        total = num_fat + data_sectors
        needed = max(1, _ceil_div(total, SECTOR // 4))
        if needed == num_fat:
            break
        num_fat = needed

    cursor = num_fat
    dir_start = cursor
    cursor += dir_sectors
    minifat_start = cursor if minifat_sectors else ENDOFCHAIN
    cursor += minifat_sectors
    mini_start = cursor if mini_sector_count else ENDOFCHAIN
    cursor += mini_sector_count
    for node, count in big_sizes:
        node.start = cursor
        node.size = len(node.data)
        cursor += count

    root.start = mini_start
    root.size = len(mini_stream_data)

    total_sectors = num_fat + data_sectors
    fat = [FREESECT] * total_sectors
    for i in range(num_fat):
        fat[i] = FATSECT
    for start, count in ((dir_start, dir_sectors), (minifat_start, minifat_sectors),
                         (mini_start, mini_sector_count)):
        for i in range(count):
            fat[start + i] = start + i + 1 if i < count - 1 else ENDOFCHAIN
    for node, count in big_sizes:
        for i in range(count):
            fat[node.start + i] = node.start + i + 1 if i < count - 1 else ENDOFCHAIN

    data_area = bytearray(data_sectors * SECTOR)

    def put(sid: int, blob: bytes) -> None:
        base = (sid - num_fat) * SECTOR
        data_area[base:base + len(blob)] = blob

    put(dir_start, b"".join(_dir_entry(n) for n in nodes))
    if minifat_sectors:
        minifat_bytes = b"".join(struct.pack("<I", v) for v in minifat)
        put(minifat_start, minifat_bytes.ljust(minifat_sectors * SECTOR, b"\xff"))
    if mini_sector_count:
        put(mini_start, mini_stream_data.ljust(mini_sector_count * SECTOR, b"\x00"))
    for node, count in big_sizes:
        put(node.start, node.data.ljust(count * SECTOR, b"\x00"))

    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    fat_bytes = fat_bytes.ljust(num_fat * SECTOR, b"\xff")

    header = bytearray(512)
    header[0:8] = OLE_MAGIC
    struct.pack_into("<H", header, 24, 0x003E)     # minor version
    struct.pack_into("<H", header, 26, 0x0003)     # major version (512-byte sectors)
    struct.pack_into("<H", header, 28, 0xFFFE)     # byte order
    struct.pack_into("<H", header, 30, 9)          # sector shift
    struct.pack_into("<H", header, 32, 6)          # mini sector shift
    struct.pack_into("<I", header, 40, 0)          # num directory sectors (v3)
    struct.pack_into("<I", header, 44, num_fat)
    struct.pack_into("<I", header, 48, dir_start)
    struct.pack_into("<I", header, 56, CUTOFF)
    struct.pack_into("<I", header, 60, minifat_start)
    struct.pack_into("<I", header, 64, minifat_sectors)
    struct.pack_into("<I", header, 68, ENDOFCHAIN)  # first DIFAT sector
    struct.pack_into("<I", header, 72, 0)           # num DIFAT sectors
    for i in range(109):
        struct.pack_into("<I", header, 76 + 4 * i, i if i < num_fat else FREESECT)

    return bytes(header) + fat_bytes + bytes(data_area)


def build_macro_doc(
    *,
    macro_source: bytes = (
        b'Attribute VB_Name = "Module1"\r\n'
        b"Sub AutoOpen()\r\n"
        b'    Shell "powershell.exe -nop -w hidden -enc AAAA", vbHide\r\n'
        b"End Sub\r\n"
    ),
    native_payload: bytes = b"MZ\x90\x00" + b"\x00" * 4092,
    native_filename: str = "dropped.exe",
) -> bytes:
    """A legacy macro-enabled .doc: VBA project + an embedded OLE package."""

    modules = [
        {"name": "Module1", "stream": "Module1", "text_offset": 16, "kind": "std"},
        {"name": "ThisDocument", "stream": "ThisDocument", "text_offset": 0, "kind": "class"},
    ]
    dir_bytes = build_dir_stream(modules)
    project_stream = (
        b'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
        b"Document=ThisDocument/&H00000000\r\n"
        b"Module=Module1\r\n"
        b'Name="Project"\r\n'
    )
    this_document = b'Attribute VB_Name = "ThisDocument"\r\n'
    streams = {
        # A regular-FAT stream (> 4096 bytes) carrying the document body.
        "WordDocument": b"\xec\xa5\xc1\x00" + b"\x41" * 5000,
        "Macros/PROJECT": project_stream,
        "Macros/PROJECTwm": b"\x00" * 8,
        # Mini-stream members (< 4096 bytes): the VBA project.
        "Macros/VBA/_VBA_PROJECT": b"\xcc\x61" + b"\x00" * 200,
        "Macros/VBA/dir": compress_ovba(dir_bytes),
        "Macros/VBA/Module1": b"\x00" * 16 + compress_ovba(macro_source),
        "Macros/VBA/ThisDocument": compress_ovba(this_document),
        "ObjectPool/_1/\x01Ole10Native": build_ole10native(
            native_payload, filename=native_filename
        ),
    }
    return build_cfb(streams)
