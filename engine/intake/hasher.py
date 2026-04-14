"""Multi-hash computation — MD5, SHA1, SHA256, and SSDeep fuzzy hashing.

All hashes are computed in a single pass over the file data for efficiency.
SSDeep requires the ssdeep library; if unavailable, it is skipped gracefully.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import ssdeep for fuzzy hashing
try:
    import ssdeep as ssdeep_lib
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False
    logger.debug("ssdeep not available — fuzzy hashing disabled")


@dataclass
class HashResult:
    """Complete hash set for a file."""
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str] = None
    file_size: int = 0

    def to_dict(self) -> dict:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "ssdeep": self.ssdeep,
            "file_size": self.file_size,
        }

    def __str__(self) -> str:
        lines = [
            f"MD5:    {self.md5}",
            f"SHA1:   {self.sha1}",
            f"SHA256: {self.sha256}",
        ]
        if self.ssdeep:
            lines.append(f"SSDeep: {self.ssdeep}")
        lines.append(f"Size:   {self.file_size} bytes")
        return "\n".join(lines)


class MultiHasher:
    """Compute multiple hashes in a single file pass.

    Reads the file once and computes MD5, SHA1, and SHA256 simultaneously.
    SSDeep requires a separate pass (library limitation).
    """

    # Chunk size for reading files — 64KB balances memory and I/O
    CHUNK_SIZE = 65536

    def hash_file(self, file_path: Path) -> HashResult:
        """Compute all hashes for a file in a single pass.

        Args:
            file_path: Path to the file to hash.

        Returns:
            HashResult with all computed hashes.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        ssdeep_hash: Optional[str] = None
        if HAS_SSDEEP:
            try:
                ssdeep_hash = ssdeep_lib.hash_from_file(str(file_path))
            except Exception:
                logger.warning("SSDeep hashing failed for %s", file_path)

        return HashResult(
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
            ssdeep=ssdeep_hash,
            file_size=file_size,
        )

    def hash_bytes(self, data: bytes) -> HashResult:
        """Compute hashes for in-memory bytes.

        Useful for hashing samples already loaded into memory.

        Args:
            data: Bytes to hash.

        Returns:
            HashResult with all computed hashes.
        """
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        ssdeep_hash: Optional[str] = None
        if HAS_SSDEEP:
            try:
                ssdeep_hash = ssdeep_lib.hash(data)
            except Exception:
                logger.warning("SSDeep hashing failed for in-memory data")

        return HashResult(
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            ssdeep=ssdeep_hash,
            file_size=len(data),
        )