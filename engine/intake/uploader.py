"""File upload handling — accept samples and store with metadata.

Supports PE, ELF, Mach-O, scripts, and raw shellcode.
Files are stored in a samples directory with SHA256-based naming to deduplicate.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SAMPLES_DIR = Path("samples")

# Known magic bytes for binary identification
MAGIC_SIGNATURES: dict[bytes, str] = {
    b"\x4d\x5a": "PE",           # MZ header (Windows executable)
    b"\x7f\x45\x4c\x46": "ELF",  # \x7fELF (Linux executable)
    b"\xfe\xed\xfa\xce": "Mach-O",     # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf": "Mach-O_64",  # Mach-O 64-bit
    b"\xca\xfe\xba\xbe": "Mach-O_FAT", # Mach-O FAT binary
    b"\xcf\xfa\xed\xfe": "Mach-O_64_le", # Mach-O 64-bit little-endian
    b"\x23\x21": "Script",       # #! shebang
    b"\xff\xfb": "Shellcode_x86", # Common x86 shellcode prefix
    b"\xe8\x00\x00\x00": "Shellcode_call", # call $+5 pattern
}

# Dangerous file extensions that may indicate scripts/droppers
SCRIPT_EXTENSIONS: set[str] = {
    ".ps1", ".vbs", ".vba", ".js", ".jse", ".wsf",
    ".bat", ".cmd", ".py", ".sh", ".rb", ".pl",
    ".hta", ".lnk", ".inf", ".reg",
}


@dataclass
class SampleMetadata:
    """Metadata for an uploaded sample."""
    sample_id: str
    original_filename: str
    file_size: int
    file_type: str
    magic_match: str
    is_script: bool
    upload_time: datetime
    storage_path: Path
    extension: str = ""
    mime_guess: str = ""

    def to_dict(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "original_filename": self.original_filename,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "magic_match": self.magic_match,
            "is_script": self.is_script,
            "upload_time": self.upload_time.isoformat(),
            "storage_path": str(self.storage_path),
            "extension": self.extension,
            "mime_guess": self.mime_guess,
        }


class SampleUploader:
    """Handles file upload, deduplication, and storage.

    Samples are stored by SHA256 hash to avoid duplicates.
    The original filename is preserved in metadata.
    """

    def __init__(self, samples_dir: Path = SAMPLES_DIR) -> None:
        self.samples_dir = samples_dir
        self.samples_dir.mkdir(parents=True, exist_ok=True)

    def _detect_file_type(self, data: bytes) -> str:
        """Identify file type from magic bytes.

        Args:
            data: First few bytes of the file.

        Returns:
            File type string (PE, ELF, Mach-O, Script, Shellcode, or Unknown).
        """
        for magic, file_type in MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                return file_type
        return "Unknown"

    def _detect_script(self, filename: str, data: bytes) -> bool:
        """Check if a file is a script based on extension or shebang.

        Args:
            filename: Original filename.
            data: File content bytes.

        Returns:
            True if the file appears to be a script.
        """
        ext = Path(filename).suffix.lower()
        if ext in SCRIPT_EXTENSIONS:
            return True
        # Check for shebang in first two bytes
        if data[:2] == b"#!":
            return True
        # Check for common script indicators
        try:
            text = data[:512].decode("utf-8", errors="ignore")
            script_indicators = [
                "<script", "function ", "var ", "Sub ", "Dim ",
                "$", "#!", "import ", "require(",
            ]
            if sum(1 for ind in script_indicators if ind in text) >= 2:
                return True
        except Exception:
            pass
        return False

    def _guess_mime(self, filename: str, file_type: str) -> str:
        """Guess MIME type from filename and detected file type.

        Args:
            filename: Original filename.
            file_type: Detected file type from magic bytes.

        Returns:
            MIME type string.
        """
        mime_map: dict[str, str] = {
            "PE": "application/x-dosexec",
            "ELF": "application/x-elf",
            "Mach-O": "application/x-mach-binary",
            "Script": "text/x-script",
            "Shellcode_x86": "application/octet-stream",
            "Shellcode_call": "application/octet-stream",
        }
        if file_type in mime_map:
            return mime_map[file_type]

        ext_mimes: dict[str, str] = {
            ".ps1": "text/x-powershell",
            ".vbs": "text/vbscript",
            ".js": "text/javascript",
            ".bat": "text/x-msdos-batch",
            ".py": "text/x-python",
            ".sh": "text/x-shellscript",
            ".exe": "application/x-dosexec",
            ".dll": "application/x-dosexec",
            ".so": "application/x-elf",
        }
        ext = Path(filename).suffix.lower()
        return ext_mimes.get(ext, "application/octet-stream")

    def upload(
        self,
        source_path: Path,
        original_filename: Optional[str] = None,
        sample_id: Optional[str] = None,
    ) -> SampleMetadata:
        """Upload and store a sample file.

        Args:
            source_path: Path to the file to upload.
            original_filename: Override filename (defaults to source filename).
            sample_id: Override sample ID (defaults to SHA256 of content).

        Returns:
            SampleMetadata with file info and storage path.

        Raises:
            FileNotFoundError: If source_path does not exist.
            ValueError: If the file is empty.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Sample file not found: {source_path}")

        file_size = source_path.stat().st_size
        if file_size == 0:
            raise ValueError("Cannot upload empty file")

        data = source_path.read_bytes()
        filename = original_filename or source_path.name

        # Detect file type
        magic_match = self._detect_file_type(data)
        is_script = self._detect_script(filename, data)
        file_type = "Script" if is_script else magic_match
        mime_guess = self._guess_mime(filename, file_type)

        # Compute SHA256 for dedup storage
        import hashlib
        sha256 = hashlib.sha256(data).hexdigest()

        # Use provided sample_id or SHA256
        sid = sample_id or sha256[:16]

        # Store by SHA256 to deduplicate
        storage_path = self.samples_dir / f"{sha256}.sample"
        if not storage_path.exists():
            shutil.copy2(source_path, storage_path)
            logger.info("Stored new sample %s (%d bytes) at %s", sid, file_size, storage_path)
        else:
            logger.info("Sample %s already stored (dedup by SHA256)", sha256)

        extension = Path(filename).suffix.lower()

        metadata = SampleMetadata(
            sample_id=sid,
            original_filename=filename,
            file_size=file_size,
            file_type=file_type,
            magic_match=magic_match,
            is_script=is_script,
            upload_time=datetime.now(timezone.utc),
            storage_path=storage_path,
            extension=extension,
            mime_guess=mime_guess,
        )

        logger.info(
            "Uploaded %s: type=%s, size=%d, sha256=%s",
            filename, file_type, file_size, sha256[:16],
        )
        return metadata