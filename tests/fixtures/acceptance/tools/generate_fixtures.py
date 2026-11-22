#!/usr/bin/env python3
"""Generate the acceptance fixtures deterministically.

Everything here is written from byte templates so a clean checkout can
regenerate byte-identical files on any platform without a compiler, a network
connection or a malware sample:

* a minimal but structurally valid x86-64 PE executable (benign, one `.text`
  section, no imports, entry point is `ret`)
* a minimal but structurally valid x86-64 ELF executable (benign, exits 42)
* an ordinary-text negative control
* two strace layouts (timestamp-first, and PID-first for the known parser gap)
* an inotifywait file-event log
* a one-packet TCP capture, a valid empty capture and an unreadable capture

Run from the repository root:

    python tests/fixtures/acceptance/tools/generate_fixtures.py
    python tests/fixtures/acceptance/tools/generate_fixtures.py --check

The manifest (`tests/fixtures/acceptance/manifest.json`) records the SHA-256 of
every fixture after generation. `--check` fails if a file on disk no longer
matches, or if the manifest no longer matches the generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "acceptance"
MANIFEST = FIXTURES / "manifest.json"

# ---------------------------------------------------------------------------
# PE (PE32+ / x86-64, console subsystem, one .text section containing `ret`)
# ---------------------------------------------------------------------------

TEXT_CODE = b"\xc3"
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200


def _dos_stub() -> bytes:
    stub = bytearray(0x80)
    stub[0:2] = b"MZ"
    # e_lfanew -> PE header at 0x80
    struct.pack_into("<I", stub, 0x3C, 0x80)
    message = b"This program cannot be run in DOS mode.\r\r\n$"
    stub[0x40:0x40 + len(message)] = message
    return bytes(stub)


def build_pe() -> bytes:
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,   # Machine: AMD64
        1,        # NumberOfSections
        0,        # TimeDateStamp: fixed so output is reproducible
        0,        # PointerToSymbolTable
        0,        # NumberOfSymbols
        0x00F0,   # SizeOfOptionalHeader (PE32+)
        0x0022,   # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    opt = bytearray(0x00F0)
    struct.pack_into("<H", opt, 0, 0x20B)          # PE32+
    struct.pack_into("<B", opt, 2, 1)              # linker 1.0
    struct.pack_into("<I", opt, 4, FILE_ALIGNMENT)  # SizeOfCode
    struct.pack_into("<I", opt, 8, FILE_ALIGNMENT)  # SizeOfInitializedData
    struct.pack_into("<I", opt, 16, 0x1000)        # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, 0x1000)        # BaseOfCode
    struct.pack_into("<Q", opt, 24, 0x140000000)   # ImageBase
    struct.pack_into("<I", opt, 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", opt, 36, FILE_ALIGNMENT)
    struct.pack_into("<HH", opt, 40, 6, 0)          # OS version 6.0
    struct.pack_into("<HH", opt, 44, 0, 0)          # image version
    struct.pack_into("<HH", opt, 48, 6, 0)          # subsystem version 6.0
    struct.pack_into("<I", opt, 56, 0x2000)         # SizeOfImage
    struct.pack_into("<I", opt, 60, FILE_ALIGNMENT)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)              # Subsystem: Windows CUI
    struct.pack_into("<H", opt, 70, 0x8160)         # NX, ASLR, high entropy VA
    struct.pack_into("<Q", opt, 72, 0x100000)       # stack reserve
    struct.pack_into("<Q", opt, 80, 0x1000)         # stack commit
    struct.pack_into("<Q", opt, 88, 0x100000)       # heap reserve
    struct.pack_into("<Q", opt, 96, 0x1000)         # heap commit
    struct.pack_into("<I", opt, 108, 16)            # NumberOfRvaAndSizes

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        1,               # VirtualSize
        0x1000,          # VirtualAddress
        FILE_ALIGNMENT,  # SizeOfRawData
        FILE_ALIGNMENT,  # PointerToRawData (headers are 0x200 bytes)
        0, 0,
        0, 0,
        0x60000020,      # CODE | EXECUTE | READ
    )

    headers = _dos_stub() + b"PE\x00\x00" + coff + bytes(opt) + section
    headers += b"\x00" * (FILE_ALIGNMENT - len(headers))
    assert len(headers) == FILE_ALIGNMENT, len(headers)
    return headers + TEXT_CODE + b"\x00" * (FILE_ALIGNMENT - len(TEXT_CODE))


# ---------------------------------------------------------------------------
# ELF (ELF64 little-endian x86-64, ET_EXEC, one PT_LOAD, .text + .shstrtab)
# ---------------------------------------------------------------------------

ELF_CODE_OFFSET = 0x1000
# mov edi, 42 ; mov eax, 60 (exit) ; syscall  -> deterministic exit status
ELF_CODE = b"\xbf\x2a\x00\x00\x00\xb8\x3c\x00\x00\x00\x0f\x05"
SHSTRTAB = b"\x00.text\x00.shstrtab\x00"
SHSTRTAB_OFFSET = 0x1010
SHOFF = 0x1028


def build_elf() -> bytes:
    shstrtab_size = len(SHSTRTAB)
    file_size = SHOFF + 3 * 64

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2   # ELFCLASS64
    ehdr[5] = 1   # little endian
    ehdr[6] = 1   # EV_CURRENT
    ehdr[7] = 0   # System V ABI
    struct.pack_into(
        "<HHIQQQIHHHHHH", ehdr, 16,
        2,            # e_type: ET_EXEC
        62,           # e_machine: x86-64
        1,            # e_version
        0x401000,     # e_entry
        64,           # e_phoff
        SHOFF,        # e_shoff
        0,            # e_flags
        64,           # e_ehsize
        56,           # e_phentsize
        1,            # e_phnum
        64,           # e_shentsize
        3,            # e_shnum
        2,            # e_shstrndx
    )

    phdr = struct.pack(
        "<IIQQQQQQ",
        1,          # PT_LOAD
        5,          # PF_R | PF_X
        0,          # p_offset
        0x400000,   # p_vaddr
        0x400000,   # p_paddr
        file_size,  # p_filesz
        file_size,  # p_memsz
        SECTION_ALIGNMENT,
    )

    null_sh = bytes(64)
    text_sh = struct.pack(
        "<IIQQQQIIQQ",
        1,              # sh_name -> ".text"
        1,              # SHT_PROGBITS
        0x6,            # SHF_ALLOC | SHF_EXECINSTR
        0x401000,       # sh_addr
        ELF_CODE_OFFSET,
        len(ELF_CODE),
        0, 0,
        16,             # alignment
        0,
    )
    shstrtab_sh = struct.pack(
        "<IIQQQQIIQQ",
        7,              # sh_name -> ".shstrtab"
        3,              # SHT_STRTAB
        0,
        0,
        SHSTRTAB_OFFSET,
        shstrtab_size,
        0, 0,
        1,
        0,
    )

    blob = bytearray(file_size)
    blob[0:64] = ehdr
    blob[64:64 + len(phdr)] = phdr
    blob[ELF_CODE_OFFSET:ELF_CODE_OFFSET + len(ELF_CODE)] = ELF_CODE
    blob[SHSTRTAB_OFFSET:SHSTRTAB_OFFSET + shstrtab_size] = SHSTRTAB
    blob[SHOFF:SHOFF + 64] = null_sh
    blob[SHOFF + 64:SHOFF + 128] = text_sh
    blob[SHOFF + 128:SHOFF + 192] = shstrtab_sh
    return bytes(blob)


# ---------------------------------------------------------------------------
# Text and replay fixtures
# ---------------------------------------------------------------------------

NEGATIVE_TEXT = (
    "HATCHERY negative control.\n"
    "This file is ordinary prose with no executable content, no URLs and no\n"
    "indicators. A static scan that is running correctly reports zero YARA\n"
    "matches and no findings; a scan that failed to run must say so instead.\n"
).encode("ascii")

TRACE_TIMESTAMP = """\
10:00:00.000001 1000 execve("/opt/hatchery/sample", ["/opt/hatchery/sample"], 0x7ffd0000) = 0
10:00:00.000100 1000 brk(NULL) = 0x5555a000
10:00:00.000200 1000 openat(AT_FDCWD, "/sandbox/output/hatched.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
10:00:00.000300 1000 write(3, "hatched\\n", 8) = 8
10:00:00.000400 1000 close(3) = 0
10:00:00.000500 1000 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD) = 1001
10:00:00.000600 1001 execve("/opt/hatchery/child", ["/opt/hatchery/child"], 0x7ffd0000) = 0
10:00:00.000700 1001 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
10:00:00.000800 1001 exit_group(42) = ?
+++ exited with 42 +++
""".encode("ascii")

# Same events, PID first. This is a layout strace can emit when -f and -tt are
# combined with -o/prefix options; the current parser discards every line.
# Expected to parse zero events until master plan slice 2.4 fixes the parser.
TRACE_PID_FIRST = """\
1000 10:00:00.000001 execve("/opt/hatchery/sample", ["/opt/hatchery/sample"], 0x7ffd0000) = 0
1000 10:00:00.000100 brk(NULL) = 0x5555a000
1000 10:00:00.000200 openat(AT_FDCWD, "/sandbox/output/hatched.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
1000 10:00:00.000300 write(3, "hatched\\n", 8) = 8
1000 10:00:00.000400 close(3) = 0
1000 10:00:00.000500 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD) = 1001
1001 10:00:00.000600 execve("/opt/hatchery/child", ["/opt/hatchery/child"], 0x7ffd0000) = 0
1001 10:00:00.000700 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
1001 10:00:00.000800 exit_group(42) = ?
+++ exited with 42 +++
""".encode("ascii")

FILE_EVENTS = """\
2026-11-20T10:00:00 /sandbox/output/hatched.txt CREATE
2026-11-20T10:00:01 /sandbox/output/hatched.txt MODIFY
2026-11-20T10:00:02 /sandbox/output/old.txt MOVED_FROM
2026-11-20T10:00:03 /sandbox/output/renamed.txt MOVED_TO
2026-11-20T10:00:04 /sandbox/output/hatched.txt DELETE
""".encode("ascii")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_one_packet_pcap() -> bytes:
    src_ip = bytes((10, 0, 0, 2))
    dst_ip = bytes((10, 0, 0, 3))
    src_port, dst_port = 40000, 8080
    seq, ack = 1, 0
    tcp_offset_flags = (5 << 12) | 0x002  # data offset 5, SYN

    tcp = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, tcp_offset_flags, 65535, 0, 0
    )
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]

    total_len = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0, src_ip, dst_ip,
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]

    ethernet = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x03" + b"\x08\x00"
    packet = ethernet + ip + tcp

    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1_700_000_000, 0, len(packet), len(packet))
    return global_header + record + packet


def build_empty_pcap() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def build_malformed_pcap() -> bytes:
    return b"this is not a packet capture\n" + bytes(range(64))


# ---------------------------------------------------------------------------
# Manifest and command line
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()



def fixture_entries() -> list[dict]:
    pe = build_pe()
    elf = build_elf()
    pcap = build_one_packet_pcap()
    eicar_path = REPO_ROOT / "samples" / "eicar.com"

    return [
        {
            "id": "eicar",
            "path": "samples/eicar.com",
            "description": "Checked-in EICAR anti-malware test string (positive control)",
            "provenance": "checked-in",
            "sha256": _sha256(eicar_path.read_bytes()),
            "size": eicar_path.stat().st_size,
            "expected": {
                "uploader_file_type": "Unknown",
                "yara": {"status": "match", "rules": ["HATCHERY_EICAR_TestFile"]},
                "packer": "error_not_pe",
                "capa": "explicit_status",
            },
        },
        {
            "id": "negative_text",
            "path": "tests/fixtures/acceptance/benign/negative.txt",
            "description": "Ordinary prose, negative control (no executable content)",
            "provenance": "generated",
            "sha256": _sha256(NEGATIVE_TEXT),
            "size": len(NEGATIVE_TEXT),
            "expected": {
                "uploader_file_type": "Unknown",
                "yara": {"status": "clean", "rules": []},
                "packer": "error_not_pe",
                "capa": "explicit_status",
            },
        },
        {
            "id": "benign_pe",
            "path": "tests/fixtures/acceptance/benign/benign_pe.exe",
            "description": "Generated PE32+ x86-64 console executable, one .text section, ret",
            "provenance": "generated",
            "sha256": _sha256(pe),
            "size": len(pe),
            "expected": {
                "uploader_file_type": "PE",
                "pe": {"valid": True, "machine": "x64 (AMD64)", "subsystem": "Windows CUI"},
                # A benign minimal PE must score clean (D37): the hex-string
                # rule no longer counts a PE's own MZ header as an embedded PE,
                # and the packing rule checks the entropy its name promises.
                "yara": {"status": "clean", "rules": []},
                "packer": "not_packed",
                "capa": "explicit_status",
            },
        },
        {
            "id": "benign_elf",
            "path": "tests/fixtures/acceptance/benign/hello.elf",
            "description": "Generated ELF64 x86-64 ET_EXEC, exits 42, .text + .shstrtab",
            "provenance": "generated",
            "sha256": _sha256(elf),
            "size": len(elf),
            "expected": {
                "uploader_file_type": "ELF",
                # The fixture is a valid ELF (verified independently with
                # pyelftools) and ELFAnalyzer now reports its metadata; the
                # header enums are normalised for pyelftools int and str forms
                # (D36).
                "elf": {
                    "valid": True,
                    "arch": "x86-64",
                    "bits": 64,
                    "type": "EXEC (executable)",
                },
                "elf_independent": {"arch": "EM_X86_64", "type": "ET_EXEC"},
                "yara": {"status": "clean", "rules": []},
                "packer": "error_not_pe",
                "capa": "explicit_status",
            },
        },
        {
            "id": "trace_timestamp",
            "path": "tests/fixtures/acceptance/replay/trace_timestamp.log",
            "description": "strace -f -tt layout: execve, file write, clone, connect, exit_group",
            "provenance": "generated",
            "sha256": _sha256(TRACE_TIMESTAMP),
            "size": len(TRACE_TIMESTAMP),
            "expected": {
                "parse": {"parsed_events": 9, "process_tree": {"1000": [1001]},
                          "network_connections": 1},
            },
        },
        {
            "id": "trace_pid_first",
            "path": "tests/fixtures/acceptance/replay/trace_pid_first.log",
            "description": "Same events with PID before timestamp",
            "provenance": "generated",
            "sha256": _sha256(TRACE_PID_FIRST),
            "size": len(TRACE_PID_FIRST),
            "expected": {
                "parse": {"parsed_events": 9, "process_tree": {"1000": [1001]},
                          "network_connections": 1},
            },
        },
        {
            "id": "file_events",
            "path": "tests/fixtures/acceptance/replay/file_events.log",
            "description": "inotifywait log: create, modify, rename pair, delete",
            "provenance": "generated",
            "sha256": _sha256(FILE_EVENTS),
            "size": len(FILE_EVENTS),
            "expected": {
                "parse": {"total_events": 5, "created_files": 1,
                          "modified_files": 1, "deleted_files": 1},
            },
        },
        {
            "id": "pcap_one_packet",
            "path": "tests/fixtures/acceptance/replay/one_packet.pcap",
            "description": "One Ethernet/IPv4/TCP SYN packet, 10.0.0.2:40000 -> 10.0.0.3:8080",
            "provenance": "generated",
            "sha256": _sha256(pcap),
            "size": len(pcap),
            "expected": {
                "parse": {"total_packets": 1, "connections": 1},
                "backend_required": "tshark",
            },
        },
        {
            "id": "pcap_empty",
            "path": "tests/fixtures/acceptance/replay/empty.pcap",
            "description": "Valid global header, zero packets",
            "provenance": "generated",
            "sha256": _sha256(build_empty_pcap()),
            "size": len(build_empty_pcap()),
            "expected": {"parse": {"total_packets": 0}},
            "backend_required": "tshark",
        },
        {
            "id": "pcap_malformed",
            "path": "tests/fixtures/acceptance/replay/malformed.pcap",
            "description": "Not a capture file: used to check that unreadable input is reported",
            "provenance": "generated",
            "sha256": _sha256(build_malformed_pcap()),
            "size": len(build_malformed_pcap()),
            "expected": {
                # An unreadable capture is an error, not an empty one (D37).
                "parse": {"total_packets": 0, "errors": True},
                "backend_required": "tshark",
            },
        },
    ]


def write() -> None:
    files = {
        FIXTURES / "benign" / "benign_pe.exe": build_pe(),
        FIXTURES / "benign" / "hello.elf": build_elf(),
        FIXTURES / "benign" / "negative.txt": NEGATIVE_TEXT,
        FIXTURES / "replay" / "trace_timestamp.log": TRACE_TIMESTAMP,
        FIXTURES / "replay" / "trace_pid_first.log": TRACE_PID_FIRST,
        FIXTURES / "replay" / "file_events.log": FILE_EVENTS,
        FIXTURES / "replay" / "one_packet.pcap": build_one_packet_pcap(),
        FIXTURES / "replay" / "empty.pcap": build_empty_pcap(),
        FIXTURES / "replay" / "malformed.pcap": build_malformed_pcap(),
    }
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"wrote {path.relative_to(REPO_ROOT)} ({len(data)} bytes, sha256 {_sha256(data)[:16]}…)")

    manifest = {
        "schema_version": 1,
        "generated_by": "tests/fixtures/acceptance/tools/generate_fixtures.py",
        "note": "Regenerate with `python tests/fixtures/acceptance/tools/generate_fixtures.py`; verify with `python scripts/verify_fixtures.py`.",
        "fixtures": fixture_entries(),
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST.relative_to(REPO_ROOT)}")


def check() -> int:
    if not MANIFEST.exists():
        print("manifest missing; run without --check", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures = 0
    for entry in manifest["fixtures"]:
        path = REPO_ROOT / entry["path"]
        if not path.exists():
            print(f"MISSING  {entry['path']}")
            failures += 1
            continue
        data = path.read_bytes()
        digest = _sha256(data)
        if digest != entry["sha256"] or len(data) != entry["size"]:
            print(f"MISMATCH {entry['path']}: expected {entry['sha256']}, got {digest}")
            failures += 1
        else:
            print(f"ok       {entry['path']}")

    expected = {e["id"]: e for e in fixture_entries()}
    actual = {e["id"]: e for e in manifest["fixtures"]}
    if set(expected) != set(actual):
        print(f"MANIFEST STALE: ids differ ({sorted(set(expected) ^ set(actual))})")
        failures += 1
    for fixture_id, entry in expected.items():
        if fixture_id in actual and entry["sha256"] != actual[fixture_id]["sha256"]:
            print(f"GENERATOR DRIFT {fixture_id}: manifest has "
                  f"{actual[fixture_id]['sha256']}, generator produces {entry['sha256']}")
            failures += 1
        elif fixture_id in actual and entry.get("expected") != actual[fixture_id].get("expected"):
            print(f"MANIFEST STALE {fixture_id}: expectations differ from the generator")
            failures += 1

    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify hashes instead of writing")
    args = parser.parse_args()
    if args.check:
        return check()
    write()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
