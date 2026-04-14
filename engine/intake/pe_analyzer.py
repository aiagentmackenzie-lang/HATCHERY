"""PE binary analysis — extract structural information from Windows executables.

Uses pefile to parse PE headers, imports, exports, sections, resources,
and compile timestamps. Handles malformed/packed binaries gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    logger.warning("pefile not available — PE analysis disabled")


@dataclass
class PESectionInfo:
    """Information about a single PE section."""
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    md5: str
    is_executable: bool
    is_writable: bool
    is_readable: bool
    suspicious: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "entropy": self.entropy,
            "md5": self.md5,
            "is_executable": self.is_executable,
            "is_writable": self.is_writable,
            "is_readable": self.is_readable,
            "suspicious": self.suspicious,
        }


@dataclass
class PEImport:
    """A single imported function."""
    dll: str
    function: str
    ordinal: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "dll": self.dll,
            "function": self.function,
            "ordinal": self.ordinal,
        }


@dataclass
class PEResult:
    """Complete PE analysis result."""
    is_valid_pe: bool = False
    machine_type: str = ""
    compile_timestamp: str = ""
    subsystem: str = ""
    is_dll: bool = False
    is_64bit: bool = False
    entry_point: int = 0
    image_base: int = 0
    sections: list[PESectionInfo] = field(default_factory=list)
    imports: list[PEImport] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    version_info: dict[str, str] = field(default_factory=dict)
    suspicious_indicators: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_valid_pe": self.is_valid_pe,
            "machine_type": self.machine_type,
            "compile_timestamp": self.compile_timestamp,
            "subsystem": self.subsystem,
            "is_dll": self.is_dll,
            "is_64bit": self.is_64bit,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "sections": [s.to_dict() for s in self.sections],
            "imports": [i.to_dict() for i in self.imports],
            "exports": self.exports,
            "resources": self.resources,
            "version_info": self.version_info,
            "suspicious_indicators": self.suspicious_indicators,
            "error": self.error,
        }


# Machine type mapping
MACHINE_TYPES: dict[int, str] = {
    0x0: "Unknown",
    0x14c: "x86 (i386)",
    0x166: "R4000",
    0x1a2: "SH3",
    0x1c0: "ARM",
    0x1c2: "ARM Thumb-2",
    0x1c4: "ARM Thumb-2 (mixed)",
    0x5032: "RISC-V 32",
    0x5064: "RISC-V 64",
    0x8664: "x64 (AMD64)",
    0xaa64: "ARM64",
}

# Subsystem mapping
SUBSYSTEMS: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (Console)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM Image",
    14: "XBOX",
    16: "Windows Boot Application",
}

# DLLs commonly imported by malware
SUSPICIOUS_DLLS: set[str] = {
    "ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll",
    "advapi32.dll", "crypt32.dll", "kernel32.dll",
}

# Functions commonly used by malware
SUSPICIOUS_FUNCTIONS: set[str] = {
    # Networking
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
    "socket", "connect", "send", "recv", "WSAStartup",
    # Process manipulation
    "CreateProcessA", "CreateProcessW", "CreateRemoteThread",
    "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "TerminateProcess",
    # Registry
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    # File system
    "CreateFileA", "CreateFileW", "WriteFile", "DeleteFileA", "DeleteFileW",
    "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "QueryPerformanceCounter",
    "NtQueryInformationProcess",
    # Injection
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "CreateThread", "SetWindowsHookExA", "SetWindowsHookExW",
}


class PEAnalyzer:
    """Analyze PE (Windows executable) files for structural information.

    Extracts headers, sections, imports, exports, resources, and flags
    suspicious patterns commonly associated with malware.
    """

    def analyze(self, file_path: Path) -> PEResult:
        """Perform full PE analysis on a file.

        Args:
            file_path: Path to the PE file.

        Returns:
            PEResult with all extracted information.
        """
        if not HAS_PEFILE:
            return PEResult(error="pefile library not available")

        if not file_path.exists():
            return PEResult(error=f"File not found: {file_path}")

        try:
            pe = pefile.PE(str(file_path))
        except pefile.PEFormatError as e:
            return PEResult(error=f"Invalid PE format: {e}")
        except Exception as e:
            return PEResult(error=f"PE parsing error: {e}")

        result = PEResult(is_valid_pe=True)
        suspicious: list[str] = []

        # Basic headers
        machine = pe.FILE_HEADER.Machine
        result.machine_type = MACHINE_TYPES.get(machine, f"0x{machine:04x}")
        result.is_64bit = machine == 0x8664 or machine == 0xaa64
        result.is_dll = bool(pe.is_dll())
        result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        result.image_base = pe.OPTIONAL_HEADER.ImageBase

        # Compile timestamp
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            from datetime import datetime, timezone
            result.compile_timestamp = datetime.fromtimestamp(
                timestamp, tz=timezone.utc
            ).isoformat()
        except (OSError, ValueError):
            result.compile_timestamp = str(timestamp)

        # Subsystem
        subsystem = getattr(pe.OPTIONAL_HEADER, "Subsystem", 0)
        result.subsystem = SUBSYSTEMS.get(subsystem, f"Unknown ({subsystem})")

        # Sections
        result.sections = self._analyze_sections(pe, suspicious)

        # Imports
        result.imports, import_suspicious = self._analyze_imports(pe)
        suspicious.extend(import_suspicious)

        # Exports
        result.exports = self._analyze_exports(pe)

        # Resources
        result.resources = self._analyze_resources(pe)

        # Version info
        result.version_info = self._analyze_version_info(pe)

        # Compile suspicious indicators
        if result.compile_timestamp == "1970-01-01T00:00:00+00:00":
            suspicious.append("Zero compile timestamp (likely packed or forged)")

        result.suspicious_indicators = suspicious
        pe.close()
        return result

    def _analyze_sections(
        self, pe: pefile.PE, suspicious: list[str]
    ) -> list[PESectionInfo]:
        """Extract and analyze PE sections."""
        sections: list[PESectionInfo] = []
        has_executable_writable = False

        for section in pe.sections:
            try:
                name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            except Exception:
                name = "unknown"

            entropy = section.get_entropy()
            raw_size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize

            is_exec = bool(section.Characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            is_write = bool(section.Characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE
            is_read = bool(section.Characteristics & 0x40000000)  # IMAGE_SCN_MEM_READ

            # Calculate section MD5
            try:
                import hashlib
                section_data = section.get_data()
                section_md5 = hashlib.md5(section_data).hexdigest()
            except Exception:
                section_md5 = "N/A"

            is_suspicious = False

            # High entropy (possible packing/encryption)
            if entropy > 7.0:
                is_suspicious = True
                suspicious.append(
                    f"Section '{name}' has high entropy ({entropy:.2f}) — possible packing/encryption"
                )

            # Writable + executable section (possible self-modifying code)
            if is_exec and is_write:
                has_executable_writable = True
                is_suspicious = True
                suspicious.append(
                    f"Section '{name}' is writable+executable — possible self-modification"
                )

            # Section with no raw data but large virtual size (unpacked at runtime)
            if raw_size == 0 and virtual_size > 0:
                is_suspicious = True
                suspicious.append(
                    f"Section '{name}' has no raw data but virtual size {virtual_size}"
                )

            # Unusual section names
            non_standard = name not in {
                ".text", ".data", ".rdata", ".rsrc", ".idata",
                ".edata", ".bss", ".reloc", ".tls", ".gfids",
            }
            if non_standard and name.strip():
                is_suspicious = True

            sections.append(PESectionInfo(
                name=name,
                virtual_size=virtual_size,
                raw_size=raw_size,
                entropy=entropy,
                md5=section_md5,
                is_executable=is_exec,
                is_writable=is_write,
                is_readable=is_read,
                suspicious=is_suspicious,
            ))

        if has_executable_writable:
            suspicious.append("PE has writable+executable sections (W^X violation)")

        return sections

    def _analyze_imports(
        self, pe: pefile.PE
    ) -> tuple[list[PEImport], list[str]]:
        """Extract and analyze imported functions."""
        imports: list[PEImport] = []
        suspicious: list[str] = []
        seen_dlls: set[str] = set()

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports, suspicious

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.rstrip(b"\x00").decode("ascii", errors="replace").lower()
            except Exception:
                dll_name = "unknown"

            seen_dlls.add(dll_name)

            # Check for suspicious DLLs
            if dll_name in SUSPICIOUS_DLLS:
                suspicious.append(f"Imports from suspicious DLL: {dll_name}")

            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode("ascii", errors="replace")
                    except Exception:
                        func_name = f"ordinal_{imp.ordinal}"

                    if func_name in SUSPICIOUS_FUNCTIONS:
                        suspicious.append(f"Suspicious import: {dll_name}!{func_name}")

                    imports.append(PEImport(
                        dll=dll_name,
                        function=func_name,
                        ordinal=imp.ordinal if imp.ordinal else None,
                    ))
                elif imp.ordinal:
                    imports.append(PEImport(
                        dll=dll_name,
                        function=f"ordinal_{imp.ordinal}",
                        ordinal=imp.ordinal,
                    ))

        return imports, suspicious

    def _analyze_exports(self, pe: pefile.PE) -> list[str]:
        """Extract exported function names."""
        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    name = exp.name.decode("ascii", errors="replace") if exp.name else f"ordinal_{exp.ordinal}"
                    exports.append(name)
                except Exception:
                    continue
        return exports

    def _analyze_resources(self, pe: pefile.PE) -> list[str]:
        """Extract resource type information."""
        resources: list[str] = []
        RESOURCE_TYPES: dict[int, str] = {
            1: "Cursor", 2: "Bitmap", 3: "Icon", 4: "Menu",
            5: "Dialog", 6: "StringTable", 7: "FontDir", 8: "Font",
            9: "Accelerator", 10: "RCData", 11: "MessageTable",
            12: "GroupCursor", 14: "GroupIcon", 16: "VersionInfo",
            24: "Manifest",
        }

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rt_id = resource_type.id
                rt_name = RESOURCE_TYPES.get(rt_id, f"Type_{rt_id}")
                resources.append(rt_name)
        return resources

    def _analyze_version_info(self, pe: pefile.PE) -> dict[str, str]:
        """Extract version information from PE resources."""
        version_info: dict[str, str] = {}
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for string_table in entry.StringTable:
                            for key, value in string_table.entries.items():
                                try:
                                    version_info[key] = value.decode(
                                        "utf-8", errors="replace"
                                    ) if isinstance(value, bytes) else str(value)
                                except Exception:
                                    pass
        return version_info