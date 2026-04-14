"""Tests for HATCHERY string extractor."""

import pytest
from pathlib import Path
from engine.intake.strings import StringExtractor


class TestStringExtractor:
    """Test string extraction and classification."""

    def setup_method(self):
        self.extractor = StringExtractor()

    def test_extract_urls(self):
        """Test URL extraction from binary data."""
        data = b"visit http://evil.com/payload and https://c2.attacker.com:443/api"
        result = self.extractor.extract_from_bytes(data)

        assert len(result.urls) == 2
        assert "http://evil.com/payload" in result.urls
        assert "https://c2.attacker.com:443/api" in result.urls

    def test_extract_ips(self):
        """Test IP address extraction."""
        data = b"connect to 185.220.101.34 on port 443"
        result = self.extractor.extract_from_bytes(data)

        assert "185.220.101.34" in result.ips

    def test_extract_domains(self):
        """Test domain extraction."""
        data = b"resolve c2.evil-domain.com and mail.attacker.net"
        result = self.extractor.extract_from_bytes(data)

        domains = result.domains
        assert any("evil-domain.com" in d for d in domains)
        assert any("attacker.net" in d for d in domains)

    def test_extract_emails(self):
        """Test email address extraction."""
        data = b"send data to exfil@attacker.com and admin@evil.org"
        result = self.extractor.extract_from_bytes(data)

        assert "exfil@attacker.com" in result.emails
        assert "admin@evil.org" in result.emails

    def test_extract_registry_keys(self):
        """Test Windows registry key extraction."""
        data = b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        result = self.extractor.extract_from_bytes(data)

        assert len(result.registry_keys) >= 1

    def test_extract_wide_strings(self):
        """Test wide (UTF-16LE) string extraction."""
        # UTF-16LE encoded "http://evil.com"
        data = b"h\x00t\x00t\x00p\x00:\x00/\x00/\x00e\x00v\x00i\x00l\x00.\x00c\x00o\x00m\x00\x00\x00"
        result = self.extractor.extract_from_bytes(data)

        # Should extract at least the domain or partial URL
        assert len(result.all_strings) > 0

    def test_crypto_constants(self):
        """Test crypto constant detection."""
        data = b"0x67452301 0xefcdab89 0x98badcfe 0x10325476"
        result = self.extractor.extract_from_bytes(data)

        assert len(result.crypto_constants) >= 1

    def test_empty_data(self):
        """Test extraction from empty data."""
        result = self.extractor.extract_from_bytes(b"")
        assert len(result.all_strings) == 0

    def test_min_length_filter(self):
        """Test that short strings are filtered out."""
        data = b"ab\x00abc\x00abcdef"
        result = self.extractor.extract_from_bytes(data)

        # "ab" (2 chars) should be filtered, "abc" (3) borderline, "abcdef" (6) kept
        for s in result.all_strings:
            assert len(s) >= 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])