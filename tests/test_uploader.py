"""Tests for HATCHERY uploader (sample intake)."""

import pytest
from pathlib import Path

from engine.intake.uploader import SampleUploader, SampleMetadata


class TestSampleUploader:
    """Test sample upload, type detection, and storage."""

    def setup_method(self):
        self.uploader = SampleUploader(samples_dir=Path("/tmp/hatchery_test_samples"))

    def test_detect_pe_file(self):
        """Test detection of PE (Windows executable) files."""
        data = b"\x4d\x5a" + b"\x00" * 100  # MZ header
        file_type = self.uploader._detect_file_type(data)
        assert file_type == "PE"

    def test_detect_elf_file(self):
        """Test detection of ELF (Linux executable) files."""
        data = b"\x7f\x45\x4c\x46" + b"\x00" * 100  # \x7fELF header
        file_type = self.uploader._detect_file_type(data)
        assert file_type == "ELF"

    def test_detect_script_shebang(self):
        """Test detection of script files via shebang."""
        data = b"#!/bin/bash\necho hello"
        file_type = self.uploader._detect_file_type(data)
        assert file_type == "Script"

    def test_detect_unknown_file(self):
        """Test detection of unknown file types."""
        data = b"\x00\x01\x02\x03"  # No matching magic
        file_type = self.uploader._detect_file_type(data)
        assert file_type == "Unknown"

    def test_detect_script_by_extension(self):
        """Test script detection by file extension."""
        assert self.uploader._detect_script("malware.ps1", b"code") is True
        assert self.uploader._detect_script("malware.vbs", b"code") is True
        assert self.uploader._detect_script("malware.bat", b"code") is True
        assert self.uploader._detect_script("malware.py", b"code") is True
        assert self.uploader._detect_script("malware.sh", b"code") is True
        assert self.uploader._detect_script("legitimate.exe", b"MZ\x00") is False

    def test_detect_script_by_shebang(self):
        """Test script detection by shebang content."""
        assert self.uploader._detect_script("unknown", b"#!/usr/bin/python") is True
        assert self.uploader._detect_script("unknown", b"\x7fELF") is False

    def test_detect_script_by_content(self):
        """Test script detection by multiple content indicators."""
        # Multiple indicators found
        content = b"<script>function test() { var x = 1; }"
        assert self.uploader._detect_script("page.html", content) is True

    def test_guess_mime_pe(self):
        """Test MIME type guess for PE files."""
        mime = self.uploader._guess_mime("test.exe", "PE")
        assert mime == "application/x-dosexec"

    def test_guess_mime_elf(self):
        """Test MIME type guess for ELF files."""
        mime = self.uploader._guess_mime("test.so", "ELF")
        assert mime == "application/x-elf"

    def test_guess_mime_script(self):
        """Test MIME type guess for scripts."""
        # When file_type is "Script", the type-based map takes priority
        mime = self.uploader._guess_mime("test.py", "Script")
        assert mime == "text/x-script"  # mime_map type lookup wins over extension

        # When file_type has no mapping, falls back to extension
        mime = self.uploader._guess_mime("test.py", "Unknown")
        assert mime == "text/x-python"  # Extension-based lookup for unknown types

    def test_guess_mime_by_extension(self):
        """Test MIME type guess by file extension."""
        mime = self.uploader._guess_mime("unknown.bin", "Unknown")
        assert mime == "application/octet-stream"

    def test_upload_creates_storage(self, tmp_path):
        """Test that uploading a file creates storage."""
        samples_dir = tmp_path / "samples"
        uploader = SampleUploader(samples_dir=samples_dir)

        test_file = tmp_path / "test_sample.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 50)

        metadata = uploader.upload(test_file)

        assert metadata.file_type == "PE"
        assert metadata.file_size == 52
        assert metadata.magic_match == "PE"
        assert metadata.original_filename == "test_sample.exe"
        assert samples_dir.exists()

    def test_upload_empty_file_raises(self, tmp_path):
        """Test that uploading an empty file raises ValueError."""
        uploader = SampleUploader(samples_dir=tmp_path / "samples")

        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        with pytest.raises(ValueError, match="empty"):
            uploader.upload(test_file)

    def test_upload_nonexistent_file_raises(self, tmp_path):
        """Test that uploading a nonexistent file raises FileNotFoundError."""
        uploader = SampleUploader(samples_dir=tmp_path / "samples")

        with pytest.raises(FileNotFoundError):
            uploader.upload(tmp_path / "nonexistent.bin")

    def test_upload_deduplication(self, tmp_path):
        """Test that duplicate files are deduplicated by SHA256."""
        samples_dir = tmp_path / "samples"
        uploader = SampleUploader(samples_dir=samples_dir)

        data = b"same content for both"
        file1 = tmp_path / "sample1.bin"
        file2 = tmp_path / "sample2.bin"
        file1.write_bytes(data)
        file2.write_bytes(data)

        meta1 = uploader.upload(file1)
        meta2 = uploader.upload(file2)

        # Storage paths should be the same (dedup by SHA256)
        stored_files = list(samples_dir.glob("*.sample"))
        assert len(stored_files) == 1  # Only one stored file

    def test_metadata_to_dict(self, tmp_path):
        """Test SampleMetadata serialization."""
        uploader = SampleUploader(samples_dir=tmp_path / "samples")
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 50)

        metadata = uploader.upload(test_file)
        d = metadata.to_dict()

        assert "sample_id" in d
        assert "original_filename" in d
        assert "file_size" in d
        assert "file_type" in d
        assert "upload_time" in d

    def test_shellcode_detection(self):
        """Test detection of shellcode magic bytes."""
        data = b"\xe8\x00\x00\x00" + b"\x00" * 50
        file_type = self.uploader._detect_file_type(data)
        assert file_type == "Shellcode_call"

    def test_macho_detection(self):
        """Test detection of Mach-O binary."""
        data = b"\xfe\xed\xfa\xce" + b"\x00" * 50
        file_type = self.uploader._detect_file_type(data)
        assert file_type == "Mach-O"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])