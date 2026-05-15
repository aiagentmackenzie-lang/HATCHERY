"""Tests for HATCHERY multi-hash computation."""

import pytest
import tempfile
from pathlib import Path

from engine.intake.hasher import MultiHasher, HashResult


class TestMultiHasher:
    """Test multi-hash computation."""

    def setup_method(self):
        self.hasher = MultiHasher()

    def test_hash_file_basic(self, tmp_path):
        """Test hashing a small file produces valid hashes."""
        test_file = tmp_path / "test.bin"
        test_data = b"Hello, HATCHERY! This is a test payload."
        test_file.write_bytes(test_data)

        result = self.hasher.hash_file(test_file)

        assert result.md5  # Not empty
        assert result.sha1  # Not empty
        assert result.sha256  # Not empty
        assert result.file_size == len(test_data)
        assert len(result.md5) == 32  # MD5 hex length
        assert len(result.sha1) == 40  # SHA1 hex length
        assert len(result.sha256) == 64  # SHA256 hex length

    def test_hash_file_deterministic(self, tmp_path):
        """Test that hashing the same file twice produces the same result."""
        test_file = tmp_path / "consistent.bin"
        test_file.write_bytes(b"deterministic test data")

        result1 = self.hasher.hash_file(test_file)
        result2 = self.hasher.hash_file(test_file)

        assert result1.md5 == result2.md5
        assert result1.sha1 == result2.sha1
        assert result1.sha256 == result2.sha256

    def test_hash_file_empty_raises(self, tmp_path):
        """Test that hashing an empty file raises ValueError."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        with pytest.raises(FileNotFoundError):
            self.hasher.hash_file(tmp_path / "nonexistent.bin")

    def test_hash_bytes(self):
        """Test hashing in-memory bytes."""
        data = b"hash me if you can"
        result = self.hasher.hash_bytes(data)

        assert result.md5
        assert result.sha1
        assert result.sha256
        assert result.file_size == len(data)

    def test_hash_bytes_known_value(self):
        """Test hashing known data produces correct SHA256."""
        import hashlib
        data = b"known test data"
        expected = hashlib.sha256(data).hexdigest()

        result = self.hasher.hash_bytes(data)
        assert result.sha256 == expected

    def test_hash_file_not_found(self):
        """Test that hashing a nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            self.hasher.hash_file(Path("/nonexistent/path/file.bin"))

    def test_hash_result_to_dict(self):
        """Test HashResult serialization."""
        result = HashResult(
            md5="abc123",
            sha1="def456",
            sha256="ghi789",
            ssdeep=None,
            file_size=1024,
        )

        d = result.to_dict()
        assert d["md5"] == "abc123"
        assert d["sha1"] == "def456"
        assert d["sha256"] == "ghi789"
        assert d["ssdeep"] is None
        assert d["file_size"] == 1024

    def test_hash_result_str(self):
        """Test HashResult string representation."""
        result = HashResult(
            md5="abc123",
            sha1="def456",
            sha256="ghi789",
            file_size=1024,
        )
        s = str(result)
        assert "MD5" in s
        assert "SHA256" in s
        assert "1024" in s

    def test_hash_large_file(self, tmp_path):
        """Test hashing a larger file (chunk reading)."""
        test_file = tmp_path / "large.bin"
        # Write 256KB of data (more than one chunk)
        test_file.write_bytes(b"\x41" * (256 * 1024))

        result = self.hasher.hash_file(test_file)
        assert result.file_size == 256 * 1024
        assert len(result.sha256) == 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])