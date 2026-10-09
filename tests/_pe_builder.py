"""Build a tiny, benign PE32 (i386) fixture for the emulation tests.

No compiler and no vendored binary: PE headers, an import table and the x86
machine code are emitted with :mod:`struct`. The default program calls a handful
of Windows APIs Speakeasy emulates so a real report has API, network and mutex
facts to extract; the caller can pass a custom program (e.g. a single call to an
unimplemented API) to build a negative fixture.

This is a **test-only** helper. Nothing in the runtime builds a PE.
"""

from __future__ import annotations

import struct
from pathlib import Path

IMAGE_BASE = 0x400000
SECT_RVA = 0x1000
SECT_VA = IMAGE_BASE + SECT_RVA
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

# A benign program: a mutex name, a user agent and a URL. Speakeasy dereferences
# the string arguments, so this yields real config to extract.
DEFAULT_PROGRAM: list[tuple] = [
    ("call", ("kernel32", "GetTickCount")),
    ("push_str", "HatcheryMutex"),
    ("push_imm", 0),
    ("push_imm", 0),
    ("call", ("kernel32", "CreateMutexA")),
    ("push_imm", 0), ("push_imm", 0), ("push_imm", 0), ("push_imm", 0),
    ("push_str", "HatcheryAgent"),
    ("call", ("wininet", "InternetOpenA")),
    ("mov_esi_eax",),
    ("push_imm", 0), ("push_imm", 0), ("push_imm", 0), ("push_imm", 0),
    ("push_str", "http://c2.example/stage"),
    ("push_esi",),
    ("call", ("wininet", "InternetOpenUrlA")),
    ("ret",),
]

# A negative program: one call to an API Speakeasy has no handler for.
UNIMPLEMENTED_PROGRAM: list[tuple] = [
    ("call", ("kernel32", "ThisApiDoesNotExistBySpeakeasy")),
    ("ret",),
]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_pe(path: Path, program: list[tuple] | None = None) -> Path:
    """Write a benign PE32 to ``path`` and return it."""
    program = program or DEFAULT_PROGRAM
    dlls: list[str] = []
    apis: dict[str, list[str]] = {}
    for op in program:
        if op[0] == "call":
            dll, func = op[1]
            if dll not in dlls:
                dlls.append(dll)
            apis.setdefault(dll, [])
            if func not in apis[dll]:
                apis[dll].append(func)

    strings: list[str] = []
    for op in program:
        if op[0] == "push_str" and op[1] not in strings:
            strings.append(op[1])

    def op_size(op: tuple) -> int:
        return {
            "call": 6, "push_imm": 5, "push_str": 5, "push_esi": 1,
            "mov_esi_eax": 2, "ret": 1,
        }[op[0]]

    code_size = sum(op_size(op) for op in program)

    string_offsets = {}
    cursor = _align(code_size, 16)
    for text in strings:
        string_offsets[text] = cursor
        cursor += len(text.encode()) + 1

    hint_offsets: dict[tuple[str, str], int] = {}
    cursor = _align(cursor, 4)
    for dll in dlls:
        for func in apis[dll]:
            hint_offsets[(dll, func)] = cursor
            cursor += 2 + len(func.encode()) + 1
            cursor = _align(cursor, 2)

    int_offsets: dict[str, int] = {}
    iat_offsets: dict[str, int] = {}
    cursor = _align(cursor, 4)
    for dll in dlls:
        int_offsets[dll] = cursor
        cursor += 4 * (len(apis[dll]) + 1)
    for dll in dlls:
        iat_offsets[dll] = cursor
        cursor += 4 * (len(apis[dll]) + 1)

    dllname_offsets: dict[str, int] = {}
    for dll in dlls:
        dllname_offsets[dll] = cursor
        cursor += len(dll.encode()) + len(b".dll") + 1
        cursor = _align(cursor, 4)

    desc_off = _align(cursor, 4)
    desc_size = 20 * (len(dlls) + 1)
    sect_size = _align(desc_off + desc_size, 16)

    def rva(off: int) -> int:
        return SECT_RVA + off

    def va(off: int) -> int:
        return SECT_VA + off

    def iat_va(dll: str, func: str) -> int:
        return va(iat_offsets[dll] + 4 * apis[dll].index(func))

    code = bytearray()
    for op in program:
        if op[0] == "call":
            code += b"\xff\x15" + struct.pack("<I", iat_va(*op[1]))
        elif op[0] == "push_imm":
            code += b"\x68" + struct.pack("<I", op[1] & 0xFFFFFFFF)
        elif op[0] == "push_str":
            code += b"\x68" + struct.pack("<I", va(string_offsets[op[1]]))
        elif op[0] == "push_esi":
            code += b"\x56"
        elif op[0] == "mov_esi_eax":
            code += b"\x89\xc6"
        elif op[0] == "ret":
            code += b"\xc3"
    assert len(code) == code_size

    sect = bytearray(sect_size)
    sect[0:len(code)] = code
    for text, off in string_offsets.items():
        raw = text.encode() + b"\x00"
        sect[off:off + len(raw)] = raw
    for (dll, func), off in hint_offsets.items():
        raw = struct.pack("<H", 0) + func.encode() + b"\x00"
        sect[off:off + len(raw)] = raw
    for dll in dlls:
        off = int_offsets[dll]
        for i, func in enumerate(apis[dll]):
            struct.pack_into("<I", sect, off + 4 * i, rva(hint_offsets[(dll, func)]))
        off = iat_offsets[dll]
        for i, func in enumerate(apis[dll]):
            struct.pack_into("<I", sect, off + 4 * i, rva(hint_offsets[(dll, func)]))
        name = dll.encode() + b".dll\x00"
        off = dllname_offsets[dll]
        sect[off:off + len(name)] = name
    for i, dll in enumerate(dlls):
        struct.pack_into(
            "<IIIII", sect, desc_off + 20 * i,
            rva(int_offsets[dll]), 0, 0, rva(dllname_offsets[dll]), rva(iat_offsets[dll]),
        )

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0x00, 0x10B)
    struct.pack_into("<I", opt, 0x04, sect_size)
    struct.pack_into("<I", opt, 0x10, SECT_RVA)
    struct.pack_into("<I", opt, 0x14, SECT_RVA)
    struct.pack_into("<I", opt, 0x18, SECT_RVA)
    struct.pack_into("<I", opt, 0x1C, IMAGE_BASE)
    struct.pack_into("<I", opt, 0x20, SECT_ALIGN)
    struct.pack_into("<I", opt, 0x24, FILE_ALIGN)
    struct.pack_into("<H", opt, 0x28, 4)
    struct.pack_into("<H", opt, 0x30, 4)
    struct.pack_into("<I", opt, 0x38, _align(0x1000 + sect_size, SECT_ALIGN))
    struct.pack_into("<I", opt, 0x3C, 0x200)
    struct.pack_into("<H", opt, 0x44, 3)
    struct.pack_into("<I", opt, 0x48, 0x100000)
    struct.pack_into("<I", opt, 0x4C, 0x1000)
    struct.pack_into("<I", opt, 0x50, 0x100000)
    struct.pack_into("<I", opt, 0x54, 0x1000)
    struct.pack_into("<I", opt, 0x5C, 16)
    struct.pack_into("<I", opt, 0x60 + 8, rva(desc_off))
    struct.pack_into("<I", opt, 0x60 + 12, desc_size)

    sechdr = b".text\x00\x00\x00" + struct.pack(
        "<IIIIIIHHI", len(sect), SECT_RVA, sect_size, 0x200, 0, 0, 0, 0, 0x60000020,
    )

    image = bytearray()
    image += bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sechdr
    while len(image) < 0x200:
        image += b"\x00"
    image += bytes(sect)
    while len(image) % FILE_ALIGN:
        image += b"\x00"

    path.write_bytes(bytes(image))
    return path
