"""OLE/CFB (Compound File Binary) parsing — bounded, stdlib only.

Legacy Office documents (``.doc``/``.xls``/``.ppt``) are OLE/CFB compound
files: a small filesystem of storages and streams inside one file. This
module is the *parser* half of delivery intake; ``engine/intake/delivery.py``
is still the single bounded entry point and owns every size/child limit.

What it does, and why each part matters:

* **Enumerate the compound file** (header, DIFAT, FAT, mini FAT, directory
  tree) and read streams through either the FAT or the mini stream. Legacy
  Office stores most streams — including the VBA metadata — in the mini
  stream, so a reader that only understands the FAT silently returns nothing.
* **Decompress embedded VBA projects** (MS-OVBA) so the macro *source* reaches
  YARA and the string extractor. The ``dir`` stream and every module stream are
  stored compressed; extracting the compressed bytes makes a macro look inert.
* **Carve ``\\x01Ole10Native`` package streams** (MS-OLEDS): the stream usually
  wraps an embedded file (frequently an executable), and the payload is what a
  legacy document actually drops.

Nothing here executes anything, and every loop is bounded so a malformed or
hostile container cannot make the parser spin or allocate without limit.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

# CFB sector markers.
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
MAXREGSECT = 0xFFFFFFFA

# Sanity ceilings. These are deliberately far above any real Office file but
# low enough that a corrupt header cannot cause a huge allocation.
MAX_FAT_ENTRIES = 1 << 22          # 4M FAT entries = 2 GiB of sectors
MAX_DIR_ENTRIES = 1 << 16          # 65536 directory entries
MAX_DIFAT_SECTORS = 1 << 12        # 4096 DIFAT sectors
MAX_CHAIN_HOPS = 1 << 24           # per-stream FAT chain bound

# MS-OVBA dir-stream record identifiers (MS-OVBA 2.3.4.2).
_DIR_PROJECTMODULES = 0x000F
_DIR_MODULENAME = 0x0019
_DIR_MODULENAMEUNICODE = 0x0047
_DIR_MODULESTREAMNAME = 0x001A
_DIR_MODULEDOCSTRING = 0x001C
_DIR_MODULEOFFSET = 0x0031
_DIR_MODULEHELPCONTEXT = 0x001E
_DIR_MODULECOOKIE = 0x002C
_DIR_MODULETYPE_STD = 0x0021
_DIR_MODULETYPE_CLASS = 0x0022
_DIR_MODULEREADONLY = 0x0025
_DIR_MODULEPRIVATE = 0x0028
_DIR_TERMINATOR = 0x002B

_MODULESTREAMNAME_RESERVED = 0x0032
_MODULEDOCSTRING_RESERVED = 0x0048


class OleError(ValueError):
    """Raised when a compound file cannot be parsed within the bounds."""


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


@dataclass
class OleEntry:
    """One directory entry (storage, stream or the root entry)."""

    name: str
    type: int                     # 1 storage, 2 stream, 5 root
    left: int
    right: int
    child: int
    start: int
    size: int
    path: str = ""
    depth: int = 0

    @property
    def is_root(self) -> bool:
        return self.type == 5

    @property
    def is_storage(self) -> bool:
        return self.type == 1

    @property
    def is_stream(self) -> bool:
        return self.type == 2

    @property
    def leaf_name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


class CompoundFile:
    """A bounded reader for an OLE/CFB compound file held in memory."""

    def __init__(
        self,
        data: bytes,
        *,
        max_streams: int = 4096,
        max_stream_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        if len(data) < 512 or data[:8] != OLE_MAGIC:
            raise OleError("not an OLE/CFB compound file")
        self._data = data
        self._max_streams = max(1, max_streams)
        self._max_stream_bytes = max(1, max_stream_bytes)
        self._parse_header()
        self._fat = self._read_fat()
        self._minifat = self._read_minifat()
        self._entries = self._read_directory()
        self._mini_stream = self._read_mini_stream()
        self.storages: list[str] = []
        self._streams: list[OleEntry] = []
        self._index_tree()

    # -- header -----------------------------------------------------------

    def _parse_header(self) -> None:
        data = self._data
        if _u16(data, 28) != 0xFFFE:
            raise OleError("bad CFB byte-order mark")
        sector_shift = _u16(data, 30)
        mini_shift = _u16(data, 32)
        if not 7 <= sector_shift <= 12:
            raise OleError(f"unreasonable CFB sector shift {sector_shift}")
        if not 4 <= mini_shift <= 8:
            raise OleError(f"unreasonable CFB mini-sector shift {mini_shift}")
        self.major_version = _u16(data, 26)
        self.sector_size = 1 << sector_shift
        self.mini_size = 1 << mini_shift
        self.mini_cutoff = _u32(data, 56) or 4096
        self.num_fat = _u32(data, 44)
        self.first_dir = _u32(data, 48)
        self.first_minifat = _u32(data, 60)
        self.num_minifat = _u32(data, 64)
        self.first_difat = _u32(data, 68)
        self.num_difat = _u32(data, 72)
        self._difat = [_u32(data, 76 + 4 * i) for i in range(109)]

    # -- sectors ----------------------------------------------------------

    def _sector(self, sid: int) -> bytes:
        offset = (sid + 1) * self.sector_size
        if sid < 0 or sid > MAXREGSECT or offset + self.sector_size > len(self._data):
            raise OleError(f"CFB sector {sid} out of range")
        return self._data[offset:offset + self.sector_size]

    def _difat_entries(self) -> list[int]:
        entries = list(self._difat)
        next_sid = self.first_difat
        per_sector = self.sector_size // 4
        for _ in range(min(self.num_difat, MAX_DIFAT_SECTORS)):
            if next_sid in (ENDOFCHAIN, FREESECT, FATSECT, DIFSECT) or next_sid > MAXREGSECT:
                break
            try:
                sector = self._sector(next_sid)
            except OleError:
                break
            values = struct.unpack_from(f"<{per_sector}I", sector, 0)
            entries.extend(values[:-1])
            next_sid = values[-1]
        return entries

    def _chain_sector_ids(self, start: int, table: list[int], max_units: int) -> list[int]:
        ids: list[int] = []
        seen: set[int] = set()
        sid = start
        hops = 0
        while sid not in (ENDOFCHAIN, FREESECT) and sid <= MAXREGSECT:
            if sid in seen or len(ids) >= max_units or hops >= MAX_CHAIN_HOPS:
                break
            seen.add(sid)
            ids.append(sid)
            hops += 1
            if sid >= len(table):
                break
            sid = table[sid]
        return ids

    # -- FAT / mini FAT ---------------------------------------------------

    def _read_fat(self) -> list[int]:
        difat = self._difat_entries()
        target = self.num_fat or len([s for s in difat if s not in (FREESECT, ENDOFCHAIN)])
        fat: list[int] = []
        per_sector = self.sector_size // 4
        used = 0
        for sid in difat:
            if sid in (ENDOFCHAIN, FREESECT) or sid > MAXREGSECT:
                continue
            try:
                sector = self._sector(sid)
            except OleError:
                continue
            fat.extend(struct.unpack_from(f"<{per_sector}I", sector, 0))
            used += 1
            if used >= target or len(fat) > MAX_FAT_ENTRIES:
                break
        if not fat:
            raise OleError("no FAT sectors found")
        return fat

    def _read_minifat(self) -> list[int]:
        if self.first_minifat in (ENDOFCHAIN, FREESECT) or self.first_minifat > MAXREGSECT:
            return []
        units = self.num_minifat or ((len(self._fat) * 4) // self.sector_size + 1)
        ids = self._chain_sector_ids(self.first_minifat, self._fat, units + 8)
        per_sector = self.sector_size // 4
        minifat: list[int] = []
        for sid in ids:
            try:
                sector = self._sector(sid)
            except OleError:
                break
            minifat.extend(struct.unpack_from(f"<{per_sector}I", sector, 0))
        return minifat

    # -- directory --------------------------------------------------------

    def _read_directory(self) -> list[OleEntry]:
        ids = self._chain_sector_ids(self.first_dir, self._fat, (MAX_DIR_ENTRIES // 4) + 16)
        raw = bytearray()
        for sid in ids:
            try:
                raw.extend(self._sector(sid))
            except OleError:
                break
            if len(raw) >= MAX_DIR_ENTRIES * 128:
                break
        entries: list[OleEntry] = []
        for offset in range(0, len(raw) - 127, 128):
            entries.append(self._parse_dir_entry(bytes(raw[offset:offset + 128])))
            if len(entries) >= MAX_DIR_ENTRIES:
                break
        if not entries:
            raise OleError("compound file has no directory")
        return entries

    def _parse_dir_entry(self, block: bytes) -> OleEntry:
        name_length = _u16(block, 64)
        entry_type = block[66]
        if 2 <= name_length <= 64:
            name = block[:name_length - 2].decode("utf-16-le", "replace")
        else:
            name = ""
        # Directory names are untrusted and, for \x01Ole10Native, may start with
        # a control byte. Strip it; the leaf name is what callers match on.
        name = "".join(ch for ch in name if ch >= " ").strip()
        size = _u64(block, 120)
        if self.major_version < 4:
            size &= 0xFFFFFFFF
        return OleEntry(
            name=name,
            type=entry_type,
            left=_u32(block, 68),
            right=_u32(block, 72),
            child=_u32(block, 76),
            start=_u32(block, 116),
            size=size,
        )

    # -- stream reading ---------------------------------------------------

    def _read_mini_stream(self) -> bytes:
        if not self._entries:
            return b""
        root = self._entries[0]
        if root.size <= 0:
            return b""
        size = min(root.size, self._max_stream_bytes)
        return self._read_fat_stream(root.start, size)

    def _read_fat_stream(self, start: int, size: int) -> bytes:
        if size <= 0:
            return b""
        max_units = (size // self.sector_size) + 16
        out = bytearray()
        for sid in self._chain_sector_ids(start, self._fat, max_units):
            try:
                out.extend(self._sector(sid))
            except OleError:
                break
            if len(out) >= size:
                break
        return bytes(out[:size])

    def _read_mini_stream_data(self, start: int, size: int) -> bytes:
        if size <= 0:
            return b""
        max_units = (size // self.mini_size) + 16
        out = bytearray()
        for sid in self._chain_sector_ids(start, self._minifat, max_units):
            offset = sid * self.mini_size
            if offset + self.mini_size > len(self._mini_stream):
                break
            out.extend(self._mini_stream[offset:offset + self.mini_size])
            if len(out) >= size:
                break
        return bytes(out[:size])

    def read_stream(self, entry: OleEntry) -> bytes:
        size = min(entry.size, self._max_stream_bytes)
        if entry.is_root or entry.size >= self.mini_cutoff:
            return self._read_fat_stream(entry.start, size)
        return self._read_mini_stream_data(entry.start, size)

    def read_path(self, path: str) -> bytes:
        for entry in self._streams:
            if entry.path.lower() == path.lower():
                return self.read_stream(entry)
        raise KeyError(path)

    # -- directory-tree walk ----------------------------------------------

    def _index_tree(self) -> None:
        if not self._entries:
            return
        root = self._entries[0]
        if not root.is_root:
            raise OleError("first directory entry is not the root")
        visited: set[int] = set()

        def walk(sid: int, prefix: str, depth: int) -> None:
            if sid in (NOSTREAM, FREESECT, ENDOFCHAIN) or sid >= len(self._entries):
                return
            if sid in visited or len(self._streams) >= self._max_streams or depth > 64:
                return
            visited.add(sid)
            entry = self._entries[sid]
            if entry.left not in (NOSTREAM, FREESECT, ENDOFCHAIN):
                walk(entry.left, prefix, depth)
            name = entry.name or f"entry{sid}"
            path = f"{prefix}/{name}" if prefix else name
            entry.path = path
            entry.depth = depth
            if entry.is_storage:
                if path:
                    self.storages.append(path)
                if entry.child not in (NOSTREAM, FREESECT, ENDOFCHAIN):
                    walk(entry.child, path, depth + 1)
            elif entry.is_stream:
                self._streams.append(entry)
            if entry.right not in (NOSTREAM, FREESECT, ENDOFCHAIN):
                walk(entry.right, prefix, depth)

        if root.child not in (NOSTREAM, FREESECT, ENDOFCHAIN):
            walk(root.child, "", 0)

    @property
    def streams(self) -> list[OleEntry]:
        return self._streams

    @property
    def stream_paths(self) -> set[str]:
        return {entry.path.lower() for entry in self._streams}


# ---------------------------------------------------------------------------
# MS-OVBA decompression
# ---------------------------------------------------------------------------


def decompress_ovba(data: bytes, *, max_output: int = 8 * 1024 * 1024) -> bytes:
    """Decompress an MS-OVBA compressed container (MS-OVBA 2.4.1).

    The algorithm is small but easy to get subtly wrong: the copy-token length
    and offset bit split depends on how many bytes have been produced *in the
    current chunk*, and copies may overlap the bytes they are writing.
    """

    if not data:
        return b""
    if data[0] != 0x01:
        raise OleError("MS-OVBA signature byte is not 0x01")
    out = bytearray()
    pos = 1
    length = len(data)
    while pos < length:
        if pos + 2 > length:
            break
        header = _u16(data, pos)
        chunk_size = (header & 0x0FFF) + 3
        if ((header >> 12) & 0x07) != 0b011:
            raise OleError("invalid MS-OVBA chunk signature")
        compressed = bool(header >> 15)
        chunk_end = min(length, pos + chunk_size)
        current = pos + 2
        if not compressed:
            if len(out) + 4096 > max_output:
                raise OleError("MS-OVBA output exceeds the configured cap")
            out.extend(data[current:current + 4096])
            current += 4096
        else:
            chunk_start_out = len(out)
            while current < chunk_end:
                flag_byte = data[current]
                current += 1
                for bit in range(8):
                    if current >= chunk_end:
                        break
                    if (flag_byte >> bit) & 1 == 0:
                        out.append(data[current])
                        current += 1
                        continue
                    if current + 2 > length:
                        raise OleError("truncated MS-OVBA copy token")
                    token = _u16(data, current)
                    current += 2
                    difference = len(out) - chunk_start_out
                    bit_count = max(4, (difference - 1).bit_length()) if difference > 0 else 4
                    length_mask = 0xFFFF >> bit_count
                    offset_mask = (~length_mask) & 0xFFFF
                    copy_length = (token & length_mask) + 3
                    copy_offset = ((token & offset_mask) >> (16 - bit_count)) + 1
                    source = len(out) - copy_offset
                    if source < 0:
                        raise OleError("MS-OVBA copy offset precedes the buffer")
                    if len(out) + copy_length > max_output:
                        raise OleError("MS-OVBA output exceeds the configured cap")
                    for index in range(copy_length):
                        out.append(out[source + index])
        if len(out) > max_output:
            raise OleError("MS-OVBA output exceeds the configured cap")
        pos = chunk_end
    return bytes(out)


# ---------------------------------------------------------------------------
# dir-stream / VBA project parsing
# ---------------------------------------------------------------------------


@dataclass
class VbaModule:
    name: str
    stream: str
    text_offset: int
    kind: str
    docstring: str = ""
    source: Optional[str] = None
    code_path: str = ""
    ext: str = ""


def _codepage_codec(codepage: int) -> str:
    overrides = {65001: "utf-8", 1200: "utf-16-le", 0: "cp1252", 28591: "latin-1"}
    if codepage in overrides:
        return overrides[codepage]
    try:
        import codecs

        return codecs.lookup(f"cp{codepage}").name
    except (LookupError, ValueError):
        return "cp1252"


def _find_codepage(dir_data: bytes) -> int:
    """Read PROJECTCODEPAGE from the fixed project-information prefix."""

    try:
        if _u16(dir_data, 0) != 0x0001:
            return 1252
        pos = 6 + _u32(dir_data, 2)
        if pos + 6 <= len(dir_data) and _u16(dir_data, pos) == 0x004A:
            pos += 6 + _u32(dir_data, pos + 2)
        if pos + 6 <= len(dir_data) and _u16(dir_data, pos) == 0x0002:
            pos += 6 + _u32(dir_data, pos + 2)
        if pos + 6 <= len(dir_data) and _u16(dir_data, pos) == 0x0014:
            pos += 6 + _u32(dir_data, pos + 2)
        if pos + 8 <= len(dir_data) and _u16(dir_data, pos) == 0x0003:
            if _u32(dir_data, pos + 2) >= 2:
                return _u16(dir_data, pos + 6)
    except (struct.error, IndexError):
        pass
    return 1252


def _find_modules_record(dir_data: bytes) -> Optional[tuple[int, int]]:
    """Locate the PROJECTMODULES record; return ``(modules_start, count)``."""

    pattern = b"\x0f\x00\x02\x00\x00\x00"
    search_from = 0
    while True:
        index = dir_data.find(pattern, search_from)
        if index < 0:
            return None
        if index + 16 <= len(dir_data):
            count = _u16(dir_data, index + 6)
            if _u16(dir_data, index + 8) == 0x0013 and count < 4096:
                return index + 16, count
        search_from = index + 1


def find_vba_projects(cfb: CompoundFile) -> list[tuple[str, str, str]]:
    """Return ``(vba_root, project_path, dir_path)`` for each VBA project."""

    present = cfb.stream_paths
    results: list[tuple[str, str, str]] = []
    for storage in cfb.storages:
        if storage.rsplit("/", 1)[-1].upper() != "VBA":
            continue
        vba_root = storage[: -len("VBA")].rstrip("/")
        prefix = f"{vba_root}/" if vba_root else ""
        project_path = f"{prefix}PROJECT"
        dir_path = f"{prefix}VBA/dir"
        if project_path.lower() in present and dir_path.lower() in present:
            results.append((vba_root, project_path, dir_path))
    return results


def _parse_project_stream(data: bytes, codec: str) -> dict[str, str]:
    extensions: dict[str, str] = {}
    try:
        text = data.decode(codec, "replace")
    except (LookupError, ValueError):
        text = data.decode("cp1252", "replace")
    for line in text.replace("\r\n", "\n").split("\n"):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().lower()
        if key == "Module":
            extensions[value] = "bas"
        elif key == "Class":
            extensions[value] = "cls"
        elif key == "BaseClass":
            extensions[value] = "frm"
        elif key == "Document":
            extensions[value.split("/", 1)[0]] = "cls"
    return extensions


def _parse_module_records(
    dir_data: bytes, start: int, count: int, codec: str
) -> list[VbaModule]:
    modules: list[VbaModule] = []
    pos = start
    for _ in range(min(count, 512)):
        if pos + 6 > len(dir_data) or _u16(dir_data, pos) != _DIR_MODULENAME:
            break
        size = _u32(dir_data, pos + 2)
        pos += 6
        if pos + size > len(dir_data):
            break
        name = dir_data[pos:pos + size].decode(codec, "replace")
        pos += size
        module = VbaModule(name=name, stream="", text_offset=0, kind="std")
        while pos + 2 <= len(dir_data):
            section = _u16(dir_data, pos)
            pos += 2
            if section == _DIR_TERMINATOR:
                pos = min(len(dir_data), pos + 4)
                break
            if pos + 4 > len(dir_data):
                break
            record_size = _u32(dir_data, pos)
            pos += 4
            if pos + record_size > len(dir_data):
                pos = len(dir_data)
                break
            payload = dir_data[pos:pos + record_size]
            pos += record_size
            if section == _DIR_MODULESTREAMNAME:
                module.stream = payload.decode(codec, "replace")
                if pos + 2 <= len(dir_data) and _u16(dir_data, pos) == _MODULESTREAMNAME_RESERVED:
                    pos = _skip_reserved(dir_data, pos)
            elif section == _DIR_MODULEDOCSTRING:
                module.docstring = payload.decode(codec, "replace")
                if pos + 2 <= len(dir_data) and _u16(dir_data, pos) == _MODULEDOCSTRING_RESERVED:
                    pos = _skip_reserved(dir_data, pos)
            elif section == _DIR_MODULEOFFSET:
                if len(payload) >= 4:
                    module.text_offset = _u32(payload, 0)
            elif section == _DIR_MODULETYPE_CLASS:
                module.kind = "class"
            elif section == _DIR_MODULETYPE_STD:
                module.kind = "std"
        modules.append(module)
    return modules


def _skip_reserved(dir_data: bytes, pos: int) -> int:
    """Skip a ``<reserved id><size><unicode payload>`` sub-record."""

    pos += 2
    if pos + 4 > len(dir_data):
        return len(dir_data)
    size = _u32(dir_data, pos)
    pos += 4
    return min(len(dir_data), pos + size)


def parse_vba_modules(
    cfb: CompoundFile, vba_root: str, project_path: str, dir_path: str
) -> list[VbaModule]:
    """Decompress and return every module of one VBA project."""

    try:
        dir_data = decompress_ovba(cfb.read_path(dir_path))
        project_data = cfb.read_path(project_path)
    except (OleError, KeyError):
        return []
    codec = _codepage_codec(_find_codepage(dir_data))
    found = _find_modules_record(dir_data)
    if found is None:
        return []
    modules_start, count = found
    extensions = _parse_project_stream(project_data, codec)
    modules = _parse_module_records(dir_data, modules_start, count, codec)
    result: list[VbaModule] = []
    for module in modules:
        extension = extensions.get(module.name.lower(), "")
        module.ext = extension
        prefix = f"{vba_root}/" if vba_root else ""
        candidates = [module.stream, module.name]
        for candidate in candidates:
            if not candidate:
                continue
            code_path = f"{prefix}VBA/{candidate}"
            try:
                raw = cfb.read_path(code_path)
            except KeyError:
                continue
            code = raw[module.text_offset:]
            if not code:
                continue
            try:
                source = decompress_ovba(code)
            except OleError:
                continue
            try:
                module.source = source.decode(codec, "replace")
            except (LookupError, ValueError):
                module.source = source.decode("cp1252", "replace")
            module.code_path = code_path
            result.append(module)
            break
    return result


# ---------------------------------------------------------------------------
# \x01Ole10Native (MS-OLEDS OLENativeStream)
# ---------------------------------------------------------------------------


def _read_cstring(data: bytes, pos: int, limit: int = 8192) -> tuple[str, int]:
    end = data.find(b"\x00", pos, pos + limit)
    if end < 0:
        end = min(len(data), pos + limit)
    return data[pos:end].decode("latin-1", "replace"), (end + 1 if end < len(data) else end)


@dataclass
class OleNative:
    filename: str = ""
    src_path: str = ""
    temp_path: str = ""
    payload: bytes = b""
    is_link: bool = False


def parse_ole10native(data: bytes) -> Optional[OleNative]:
    """Parse an ``\\x01Ole10Native`` stream and carve the embedded file.

    Returns ``None`` when the bytes do not follow the documented layout, so the
    caller can fall back to keeping the raw stream rather than guessing.
    """

    try:
        pos = 4                       # NativeDataSize
        if pos + 2 > len(data):
            return None
        pos += 2                      # unknown short (0x0002)
        filename, pos = _read_cstring(data, pos)
        src_path, pos = _read_cstring(data, pos)
        if pos + 8 > len(data):
            return None
        pos += 8                      # two unknown DWORDs (often a FILETIME)
        temp_path, pos = _read_cstring(data, pos)
        if pos + 4 > len(data):
            # No size field: the stream is a link, not an embedded package.
            return OleNative(filename=filename, src_path=src_path, temp_path=temp_path, is_link=True)
        actual_size = _u32(data, pos)
        pos += 4
        if actual_size == 0 or pos + actual_size > len(data):
            return OleNative(
                filename=filename, src_path=src_path, temp_path=temp_path, is_link=True
            )
        return OleNative(
            filename=filename,
            src_path=src_path,
            temp_path=temp_path,
            payload=data[pos:pos + actual_size],
        )
    except (struct.error, IndexError, ValueError):
        return None
