"""ELF binary analysis — extract structural information from Linux executables.

Uses pyelftools to parse ELF headers, sections, symbols, dynamic libraries,
and security properties (NX, PIE, RELRO, canaries).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAS_PYELFTOOLS = True
except ImportError:
    HAS_PYELFTOOLS = False
    logger.warning("pyelftools not available — ELF analysis disabled")


@dataclass
class ELFSectionInfo:
    """Information about a single ELF section."""
    name: str
    size: int
    type: str
    flags: str
    address: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "size": self.size,
            "type": self.type,
            "flags": self.flags,
            "address": self.address,
        }


@dataclass
class ELFSecurityProps:
    """Security properties of an ELF binary."""
    has_nx: bool = False
    is_pie: bool = False
    has_relro: bool = False
    has_full_relro: bool = False
    has_canary: bool = False
    has_rpath: bool = False
    has_runpath: bool = False
    is_stripped: bool = False

    def to_dict(self) -> dict:
        return {
            "has_nx": self.has_nx,
            "is_pie": self.is_pie,
            "has_relro": self.has_relro,
            "has_full_relro": self.has_full_relro,
            "has_canary": self.has_canary,
            "has_rpath": self.has_rpath,
            "has_runpath": self.has_runpath,
            "is_stripped": self.is_stripped,
        }


@dataclass
class ELFResult:
    """Complete ELF analysis result."""
    is_valid_elf: bool = False
    arch: str = ""
    bits: int = 0
    endian: str = ""
    elf_type: str = ""
    entry_point: int = 0
    sections: list[ELFSectionInfo] = field(default_factory=list)
    dynamic_libraries: list[str] = field(default_factory=list)
    exported_symbols: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    security: ELFSecurityProps = field(default_factory=ELFSecurityProps)
    suspicious_indicators: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_valid_elf": self.is_valid_elf,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "elf_type": self.elf_type,
            "entry_point": self.entry_point,
            "sections": [s.to_dict() for s in self.sections],
            "dynamic_libraries": self.dynamic_libraries,
            "exported_symbols": self.exported_symbols[:50],  # Cap at 50
            "imported_symbols": self.imported_symbols[:50],
            "security": self.security.to_dict(),
            "suspicious_indicators": self.suspicious_indicators,
            "error": self.error,
        }


# ELF type mapping
ELF_TYPES: dict[int, str] = {
    0: "NONE",
    1: "REL (relocatable)",
    2: "EXEC (executable)",
    3: "DYN (shared object)",
    4: "CORE (core dump)",
}

# ELF machine mapping
ELF_MACHINES: dict[int, str] = {
    0: "No machine",
    2: "SPARC",
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    43: "SPARC V9",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}


class ELFAnalyzer:
    """Analyze ELF (Linux executable) files for structural information.

    Extracts headers, sections, symbols, dynamic libraries, and checks
    security hardening properties.
    """

    def analyze(self, file_path: Path) -> ELFResult:
        """Perform full ELF analysis on a file.

        Args:
            file_path: Path to the ELF file.

        Returns:
            ELFResult with all extracted information.
        """
        if not HAS_PYELFTOOLS:
            return ELFResult(error="pyelftools library not available")

        if not file_path.exists():
            return ELFResult(error=f"File not found: {file_path}")

        result = ELFResult()
        suspicious: list[str] = []

        try:
            with open(file_path, "rb") as f:
                elf = ELFFile(f)
                result.is_valid_elf = True
                result.arch = ELF_MACHINES.get(elf.header.e_machine, f"0x{elf.header.e_machine:04x}")
                result.bits = elf.elfclass
                result.endian = "Little-endian" if elf.little_endian else "Big-endian"
                result.elf_type = ELF_TYPES.get(elf.header.e_type, f"0x{elf.header.e_type:04x}")
                result.entry_point = elf.header.e_entry

                # Sections
                result.sections = self._analyze_sections(elf)

                # Dynamic libraries
                result.dynamic_libraries = self._analyze_dynamic(elf, suspicious)

                # Symbols
                result.exported_symbols, result.imported_symbols = self._analyze_symbols(elf)

                # Security properties
                result.security = self._analyze_security(elf, suspicious)

                result.suspicious_indicators = suspicious

        except Exception as e:
            return ELFResult(error=f"ELF parsing error: {e}")

        return result

    def _analyze_sections(self, elf: ELFFile) -> list[ELFSectionInfo]:
        """Extract ELF section information."""
        sections: list[ELFSectionInfo] = []
        for section in elf.iter_sections():
            flags_str = ""
            if section["sh_flags"] & 0x1:  # SHF_WRITE
                flags_str += "W"
            if section["sh_flags"] & 0x2:  # SHF_ALLOC
                flags_str += "A"
            if section["sh_flags"] & 0x4:  # SHF_EXECINSTR
                flags_str += "X"

            sections.append(ELFSectionInfo(
                name=section.name,
                size=section["sh_size"],
                type=str(section["sh_type"]),
                flags=flags_str,
                address=section["sh_addr"],
            ))
        return sections

    def _analyze_dynamic(self, elf: ELFFile, suspicious: list[str]) -> list[str]:
        """Extract dynamically linked libraries."""
        libraries: list[str] = []
        dynamic_section = elf.get_section_by_name(".dynamic")
        if dynamic_section is None:
            return libraries

        from elftools.elf.dynamic import DynamicSection
        if not isinstance(dynamic_section, DynamicSection):
            return libraries

        for tag in dynamic_section.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                lib_name = tag.needed
                libraries.append(lib_name)

        # Flag suspicious libraries
        suspicious_libs = {"libpcap.so", "libcrypto.so", "libssl.so", "libresolv.so"}
        for lib in libraries:
            if any(s in lib for s in suspicious_libs):
                suspicious.append(f"Links to suspicious library: {lib}")

        return libraries

    def _analyze_symbols(self, elf: ELFFile) -> tuple[list[str], list[str]]:
        """Extract exported and imported symbols."""
        exported: list[str] = []
        imported: list[str] = []

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                name = symbol.name
                if not name:
                    continue

                # Determine if symbol is imported (undefined) or exported (defined)
                if symbol["st_shndx"] == "SHN_UNDEF":
                    imported.append(name)
                else:
                    if symbol["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT"):
                        exported.append(name)

        return exported, imported

    def _analyze_security(
        self, elf: ELFFile, suspicious: list[str]
    ) -> ELFSecurityProps:
        """Check ELF security hardening properties."""
        props = ELFSecurityProps()

        # NX (non-executable stack) — check GNU_STACK
        for section in elf.iter_sections():
            if section.name == ".note.GNU-stack":
                # If the section is not executable, NX is enabled
                props.has_nx = not bool(section["sh_flags"] & 0x4)
                break

        # PIE — check if ELF type is DYN (shared object)
        props.is_pie = elf.header.e_type == 3

        # RELRO — check for .rela.dyn and BIND_NOW flag
        for section in elf.iter_sections():
            if section.name in (".rela.dyn", ".rel.dyn"):
                props.has_relro = True
                break

        # Full RELRO — check for BIND_NOW in dynamic section
        dynamic_section = elf.get_section_by_name(".dynamic")
        if dynamic_section is not None:
            from elftools.elf.dynamic import DynamicSection
            if isinstance(dynamic_section, DynamicSection):
                for tag in dynamic_section.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        props.has_full_relro = True
                        break
                    if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 0x8:
                        # DF_BIND_NOW = 0x8
                        props.has_full_relro = True
                        break
                    if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 0x8:
                        # DF_1_NOW = 0x8
                        props.has_full_relro = True
                        break

        # Stack canary — check for __stack_chk_fail in symbols
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol.name == "__stack_chk_fail":
                    props.has_canary = True
                    break

        # RPATH / RUNPATH
        if dynamic_section is not None:
            from elftools.elf.dynamic import DynamicSection
            if isinstance(dynamic_section, DynamicSection):
                for tag in dynamic_section.iter_tags():
                    if tag.entry.d_tag == "DT_RPATH":
                        props.has_rpath = True
                        suspicious.append(f"Has RPATH: {tag.rpath}")
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        props.has_runpath = True
                        suspicious.append(f"Has RUNPATH: {tag.runpath}")

        # Stripped — no symbol table
        symtab = elf.get_section_by_name(".symtab")
        props.is_stripped = symtab is None

        if props.is_stripped:
            suspicious.append("Binary is stripped (no symbol table)")

        if not props.has_nx:
            suspicious.append("No NX (executable stack)")
        if not props.is_pie:
            suspicious.append("Not PIE (position-dependent)")
        if not props.has_relro:
            suspicious.append("No RELRO")

        return props