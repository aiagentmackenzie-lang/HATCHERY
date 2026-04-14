"""Packer detection — identify common executable packers and protectors.

Detects packers through multiple methods:
1. Section name heuristics (UPX, Themida, VMProtect)
2. Entry point analysis (suspicious EP outside .text)
3. Import count (packed binaries have very few imports)
4. Entropy analysis (high section entropy = compressed/encrypted)
5. Signature matching on PE resources and overlay data
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
    logger.warning("pefile not available — packer detection limited")


@dataclass
class PackerMatch:
    """A detected packer/protector."""
    name: str
    confidence: str  # HIGH, MEDIUM, LOW
    indicators: list[str] = field(default_factory=list)
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "version": self.version,
        }


@dataclass
class PackerResult:
    """Complete packer detection result."""
    packers: list[PackerMatch] = field(default_factory=list)
    is_packed: bool = False
    suspicion_score: float = 0.0  # 0.0 - 1.0
    indicators: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "packers": [p.to_dict() for p in self.packers],
            "is_packed": self.is_packed,
            "suspicion_score": self.suspicion_score,
            "indicators": self.indicators,
            "error": self.error,
        }


# Known packer section names
SECTION_PACKER_MAP: dict[str, tuple[str, str]] = {
    # Section name: (packer name, confidence)
    "UPX0": ("UPX", "HIGH"),
    "UPX1": ("UPX", "HIGH"),
    "UPX2": ("UPX", "HIGH"),
    "UPX!": ("UPX", "HIGH"),
    ".UPX0": ("UPX", "HIGH"),
    ".UPX1": ("UPX", "HIGH"),
    ".vmp0": ("VMProtect", "HIGH"),
    ".vmp1": ("VMProtect", "HIGH"),
    ".vmp2": ("VMProtect", "HIGH"),
    ".vmp3": ("VMProtect", "HIGH"),
    ".vmp4": ("VMProtect", "HIGH"),
    "VMP0": ("VMProtect", "HIGH"),
    "VMP1": ("VMProtect", "HIGH"),
    ".themida": ("Themida", "HIGH"),
    ".winlice": ("WinLicense", "HIGH"),
    ".advmp": ("VMProtect (advanced)", "MEDIUM"),
    ".mpress1": ("MPRESS", "HIGH"),
    ".mpress2": ("MPRESS", "HIGH"),
    ".ndata": ("NSIS", "MEDIUM"),
    ".rsrc": ("Resource-packed", "LOW"),
    ".pec2": ("PECompact", "HIGH"),
    "pec2": ("PECompact", "HIGH"),
    ".petite": ("PE-Petite", "HIGH"),
    ".enigma1": ("Enigma Protector", "HIGH"),
    ".enigma2": ("Enigma Protector", "HIGH"),
    "CODE": ("Old Borland Delphi", "LOW"),
    ".text2": ("Multi-section packer", "MEDIUM"),
    ".ndata": ("Installer/NSIS", "MEDIUM"),
}

# Known overlay signatures
OVERLAY_SIGNATURES: dict[bytes, tuple[str, str]] = {
    b"UPX!": ("UPX", "HIGH"),
    b"MPRESS1": ("MPRESS", "HIGH"),
    b"MPRESS2": ("MPRESS", "HIGH"),
    b"\xeb\x04PE\x00": ("PE-in-PE (nested)", "MEDIUM"),
    b"Rar!": ("RAR SFX", "MEDIUM"),
    b"PK\x03\x04": ("ZIP SFX", "MEDIUM"),
    b"\x1f\x8b": ("GZIP compressed overlay", "LOW"),
}

# Heuristic thresholds
MAX_LOW_IMPORT_COUNT = 5       # Very few imports = suspicious
HIGH_ENTROPY_THRESHOLD = 7.0  # Section entropy > 7.0 = likely compressed
EP_OUTSIDE_TEXT_SCORE = 0.4   # EP outside .text adds this suspicion


class PackerDetector:
    """Detect packers and protectors in PE executables.

    Uses multiple heuristics: section names, entry point location,
    import count, section entropy, and overlay signatures.
    """

    def detect(self, file_path: Path) -> PackerResult:
        """Detect packers in a PE file.

        Args:
            file_path: Path to the PE file.

        Returns:
            PackerResult with detected packers and suspicion score.
        """
        if not file_path.exists():
            return PackerResult(error=f"File not found: {file_path}")

        if not HAS_PEFILE:
            return PackerResult(error="pefile not available for packer detection")

        result = PackerResult()
        suspicion = 0.0
        indicators: list[str] = []

        try:
            pe = pefile.PE(str(file_path))
        except Exception as e:
            return PackerResult(error=f"Failed to parse PE: {e}")

        # 1. Section name matching
        section_packers = self._check_section_names(pe, indicators)
        result.packers.extend(section_packers)

        # 2. Entry point analysis
        ep_suspicion = self._check_entry_point(pe, indicators)
        suspicion += ep_suspicion

        # 3. Import count analysis
        import_suspicion = self._check_import_count(pe, indicators)
        suspicion += import_suspicion

        # 4. Section entropy analysis
        entropy_suspicion = self._check_entropy(pe, indicators)
        suspicion += entropy_suspicion

        # 5. Overlay data check
        overlay_packers = self._check_overlay(file_path, pe, indicators)
        result.packers.extend(overlay_packers)

        # Clamp and score
        suspicion = min(suspicion, 1.0)
        result.is_packed = suspicion >= 0.5 or len(result.packers) > 0
        result.suspicion_score = round(suspicion, 3)
        result.indicators = indicators

        # Deduplicate packers by name
        seen: set[str] = set()
        unique_packers: list[PackerMatch] = []
        for p in result.packers:
            if p.name not in seen:
                seen.add(p.name)
                unique_packers.append(p)
        result.packers = unique_packers

        pe.close()

        logger.info(
            "Packer detection on %s: packed=%s, score=%.2f, packers=%s",
            file_path.name,
            result.is_packed,
            result.suspicion_score,
            [p.name for p in result.packers],
        )
        return result

    def _check_section_names(
        self, pe: pefile.PE, indicators: list[str]
    ) -> list[PackerMatch]:
        """Check PE section names against known packer signatures."""
        packers: list[PackerMatch] = []
        seen: set[str] = set()

        for section in pe.sections:
            try:
                name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").strip()
            except Exception:
                continue

            if name in SECTION_PACKER_MAP and name not in seen:
                packer_name, confidence = SECTION_PACKER_MAP[name]
                packers.append(PackerMatch(
                    name=packer_name,
                    confidence=confidence,
                    indicators=[f"Section name: {name}"],
                ))
                seen.add(name)
                indicators.append(f"Known packer section: {name} → {packer_name}")

        return packers

    def _check_entry_point(self, pe: pefile.PE, indicators: list[str]) -> float:
        """Check if entry point is outside the .text section."""
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        # Find the .text section
        text_section = None
        for section in pe.sections:
            try:
                name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").strip()
            except Exception:
                continue
            if name == ".text":
                text_section = section
                break

        if text_section is not None:
            text_start = text_section.VirtualAddress
            text_end = text_start + text_section.Misc_VirtualSize

            if not (text_start <= ep < text_end):
                indicators.append(
                    f"Entry point (0x{ep:x}) outside .text section "
                    f"(0x{text_start:x}-0x{text_end:x}) — common in packed binaries"
                )
                return EP_OUTSIDE_TEXT_SCORE
        else:
            # No .text section at all — very suspicious
            indicators.append("No .text section found — possible packed binary")
            return 0.3

        return 0.0

    def _check_import_count(self, pe: pefile.PE, indicators: list[str]) -> float:
        """Check for suspiciously low import count."""
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            indicators.append("No import directory — possibly packed or shellcode")
            return 0.3

        total_imports = sum(
            len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT
        )
        total_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)

        if total_imports == 0:
            indicators.append("Zero imports — shellcode or heavily packed")
            return 0.4
        elif total_imports <= MAX_LOW_IMPORT_COUNT and total_dlls <= 2:
            indicators.append(
                f"Very few imports ({total_imports} from {total_dlls} DLLs) — possible packing"
            )
            return 0.2

        return 0.0

    def _check_entropy(self, pe: pefile.PE, indicators: list[str]) -> float:
        """Check section entropy for compression/encryption indicators."""
        high_entropy_count = 0
        total_sections = 0

        for section in pe.sections:
            total_sections += 1
            try:
                entropy = section.get_entropy()
            except Exception:
                continue

            if entropy > HIGH_ENTROPY_THRESHOLD:
                high_entropy_count += 1
                try:
                    name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace").strip()
                except Exception:
                    name = "unknown"
                indicators.append(
                    f"Section '{name}' entropy = {entropy:.2f} — likely compressed/encrypted"
                )

        if total_sections > 0 and high_entropy_count > 0:
            ratio = high_entropy_count / total_sections
            if ratio >= 0.5:
                return 0.4
            elif ratio >= 0.25:
                return 0.2

        return 0.0

    def _check_overlay(
        self, file_path: Path, pe: pefile.PE, indicators: list[str]
    ) -> list[PackerMatch]:
        """Check overlay data (appended after PE) for packer signatures."""
        packers: list[PackerMatch] = []

        try:
            pe_size = pe.OPTIONAL_HEADER.SizeOfHeaders
            for section in pe.sections:
                section_end = section.PointerToRawData + section.SizeOfRawData
                if section_end > pe_size:
                    pe_size = section_end

            file_size = file_path.stat().st_size
            overlay_size = file_size - pe_size

            if overlay_size > 0:
                with open(file_path, "rb") as f:
                    f.seek(pe_size)
                    overlay_data = f.read(min(256, overlay_size))

                for sig, (name, confidence) in OVERLAY_SIGNATURES.items():
                    if overlay_data.startswith(sig):
                        packers.append(PackerMatch(
                            name=name,
                            confidence=confidence,
                            indicators=[f"Overlay signature: {name} ({overlay_size} bytes)"],
                        ))
                        indicators.append(f"Overlay detected: {name} ({overlay_size} bytes)")

                if overlay_size > 1024 * 1024 and not packers:
                    indicators.append(f"Large overlay ({overlay_size} bytes) — may contain embedded files")

        except Exception as e:
            logger.debug("Overlay check failed: %s", e)

        return packers