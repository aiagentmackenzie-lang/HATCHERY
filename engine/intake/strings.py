"""String extraction and classification — pull meaningful strings from binaries.

Extracts ASCII and Unicode strings, then classifies them into categories:
URLs, IPs, domains, file paths, registry keys, email addresses, and
crypto-related strings.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Minimum string length to extract
MIN_ASCII_LENGTH = 4
MIN_UNICODE_LENGTH = 4

# Classification patterns
URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,})\b"
)
FILE_PATH_WIN = re.compile(
    r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>]+",
)
FILE_PATH_UNIX = re.compile(
    r"(?:/etc/|/tmp/|/var/|/home/|/usr/|/opt/|/dev/shm/)[^\s\"'<>]*",
)
REGISTRY_PATTERN = re.compile(
    r"HK(?:LM|CU|CR|U|CC)\\[^\s\"'<>]+",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
)
# Common crypto constants
CRYPTO_CONSTANTS: dict[str, str] = {
    "0x67452301": "MD5 init (A)",
    "0xefcdab89": "MD5 init (B)",
    "0x98badcfe": "MD5 init (C)",
    "0x10325476": "MD5 init (D)",
    "0x6a09e667": "SHA-256 init (H0)",
    "0xbb67ae85": "SHA-256 init (H1)",
    "0x3c6ef372": "SHA-256 init (H2)",
    "0xa54ff53a": "SHA-256 init (H3)",
    "0x5be0cd19": "SHA-256 init (H7)",
    "0x61707865": "ChaCha20 constant (sigma[0])",
    "0x3320646e": "ChaCha20 constant (sigma[1])",
    "0x79622d32": "ChaCha20 constant (sigma[2])",
    "0x6b206574": "ChaCha20 constant (sigma[3])",
    "0x9e3779b9": "Golden ratio constant (TEA/XTEA)",
}


@dataclass
class StringClassification:
    """Classified string results from a binary."""
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    crypto_constants: list[dict[str, str]] = field(default_factory=list)
    all_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "urls": self.urls,
            "ips": self.ips,
            "domains": self.domains,
            "file_paths": self.file_paths,
            "registry_keys": self.registry_keys,
            "emails": self.emails,
            "crypto_constants": self.crypto_constants,
            "total_strings": len(self.all_strings),
        }


class StringExtractor:
    """Extract and classify strings from binary files.

    Supports both ASCII and wide (Unicode) string extraction.
    All extracted strings are classified into IOC categories automatically.
    """

    def extract(self, file_path: Path) -> StringClassification:
        """Extract and classify strings from a file.

        Args:
            file_path: Path to the binary or text file.

        Returns:
            StringClassification with categorized strings.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        data = file_path.read_bytes()
        return self.extract_from_bytes(data)

    def extract_from_bytes(self, data: bytes) -> StringClassification:
        """Extract and classify strings from in-memory bytes.

        Args:
            data: Raw bytes to extract strings from.

        Returns:
            StringClassification with categorized strings.
        """
        ascii_strings = self._extract_ascii(data)
        wide_strings = self._extract_wide(data)

        # Merge and deduplicate
        all_strings_set: set[str] = set()
        all_strings: list[str] = []

        for s in ascii_strings + wide_strings:
            clean = s.strip()
            if clean and len(clean) >= MIN_ASCII_LENGTH and clean not in all_strings_set:
                all_strings_set.add(clean)
                all_strings.append(clean)

        return self._classify(all_strings)

    def _extract_ascii(self, data: bytes) -> list[str]:
        """Extract null-terminated ASCII strings from binary data.

        Scans for contiguous printable ASCII characters (0x20-0x7E).
        """
        strings: list[str] = []
        current: list[int] = []

        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(byte)
            else:
                if len(current) >= MIN_ASCII_LENGTH:
                    strings.append(bytes(current).decode("ascii"))
                current = []

        # Don't forget trailing string
        if len(current) >= MIN_ASCII_LENGTH:
            strings.append(bytes(current).decode("ascii"))

        return strings

    def _extract_wide(self, data: bytes) -> list[str]:
        """Extract wide (UTF-16LE) strings from binary data.

        Looks for patterns of printable char + null byte (UTF-16LE).
        Common in Windows executables.
        """
        strings: list[str] = []
        current: list[str] = []

        i = 0
        while i < len(data) - 1:
            char = data[i]
            null = data[i + 1]

            if 0x20 <= char <= 0x7E and null == 0x00:
                current.append(chr(char))
                i += 2
            else:
                if len(current) >= MIN_UNICODE_LENGTH:
                    strings.append("".join(current))
                current = []
                i += 1

        if len(current) >= MIN_UNICODE_LENGTH:
            strings.append("".join(current))

        return strings

    def _classify(self, strings: list[str]) -> StringClassification:
        """Classify extracted strings into IOC categories.

        Args:
            strings: List of extracted strings.

        Returns:
            StringClassification with categorized results.
        """
        result = StringClassification(all_strings=strings)
        seen_urls: set[str] = set()
        seen_ips: set[str] = set()
        seen_domains: set[str] = set()
        seen_paths: set[str] = set()
        seen_reg: set[str] = set()
        seen_emails: set[str] = set()
        seen_crypto: set[str] = set()

        for s in strings:
            # URLs (highest priority — captures domain + path)
            for url in URL_PATTERN.findall(s):
                if url not in seen_urls:
                    seen_urls.add(url)
                    result.urls.append(url)

            # IP addresses
            for ip in IP_PATTERN.findall(s):
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    result.ips.append(ip)

            # Domains (skip those already captured as URLs)
            for domain in DOMAIN_PATTERN.findall(s):
                if domain not in seen_domains and domain not in seen_urls:
                    seen_domains.add(domain)
                    result.domains.append(domain)

            # File paths
            for path in FILE_PATH_WIN.findall(s):
                if path not in seen_paths:
                    seen_paths.add(path)
                    result.file_paths.append(path)
            for path in FILE_PATH_UNIX.findall(s):
                if path not in seen_paths:
                    seen_paths.add(path)
                    result.file_paths.append(path)

            # Registry keys
            for key in REGISTRY_PATTERN.findall(s):
                if key not in seen_reg:
                    seen_reg.add(key)
                    result.registry_keys.append(key)

            # Email addresses
            for email in EMAIL_PATTERN.findall(s):
                if email not in seen_emails:
                    seen_emails.add(email)
                    result.emails.append(email)

            # Crypto constants
            s_lower = s.lower()
            for const, description in CRYPTO_CONSTANTS.items():
                if const in s_lower and const not in seen_crypto:
                    seen_crypto.add(const)
                    result.crypto_constants.append({
                        "value": const,
                        "description": description,
                        "context": s[:100],
                    })

        return result