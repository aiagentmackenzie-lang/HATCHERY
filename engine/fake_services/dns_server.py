"""Fake DNS server — sinkhole all DNS queries and log them.

Resolves every query to 127.0.0.1 (or a configurable IP) so that
malware's C2 domain resolution points to our fake services.
All queries are logged for IOC extraction.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# DNS record types
DNS_RECORD_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

# SINKHOLE_IP: Where all DNS queries resolve to
DEFAULT_SINKHOLE_IP = "127.0.0.1"
DEFAULT_DNS_PORT = 53
DEFAULT_BIND_ADDRESS = "0.0.0.0"


@dataclass
class DNSQueryLog:
    """A logged DNS query."""
    timestamp: str
    query_name: str
    query_type: str
    client_ip: str
    sinkhole_response: str = DEFAULT_SINKHOLE_IP

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "query_name": self.query_name,
            "query_type": self.query_type,
            "client_ip": self.client_ip,
            "sinkhole_response": self.sinkhole_response,
        }


class FakeDNSServer:
    """DNS sinkhole server that resolves all queries to a fake IP.

    Listens for DNS queries on UDP port 53 and responds with
    a configurable sinkhole IP. All queries are logged for
    IOC extraction and DGA analysis.
    """

    def __init__(
        self,
        bind_address: str = DEFAULT_BIND_ADDRESS,
        port: int = DEFAULT_DNS_PORT,
        sinkhole_ip: str = DEFAULT_SINKHOLE_IP,
        log_dir: Optional[Path] = None,
    ) -> None:
        self.bind_address = bind_address
        self.port = port
        self.sinkhole_ip = sinkhole_ip
        self.log_dir = log_dir
        self.query_log: list[DNSQueryLog] = []
        self._running = False
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the fake DNS server in a background thread."""
        if self._running:
            return

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.settimeout(1.0)

        try:
            self._socket.bind((self.bind_address, self.port))
        except OSError as e:
            logger.error("Failed to bind DNS server on %s:%d: %s", self.bind_address, self.port, e)
            return

        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info("Fake DNS server started on %s:%d (sinkhole: %s)", self.bind_address, self.port, self.sinkhole_ip)

    def stop(self) -> None:
        """Stop the fake DNS server."""
        self._running = False
        if self._socket:
            self._socket.close()
            self._socket = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Fake DNS server stopped (%d queries logged)", len(self.query_log))

    def _serve(self) -> None:
        """Main DNS server loop."""
        while self._running:
            try:
                data, addr = self._socket.recvfrom(4096)
                response = self._handle_query(data, addr[0])
                if response:
                    self._socket.sendto(response, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logger.error("DNS server error: %s", e)

    def _handle_query(self, data: bytes, client_ip: str) -> Optional[bytes]:
        """Parse a DNS query and generate a sinkhole response.

        Args:
            data: Raw DNS query bytes.
            client_ip: Source IP of the query.

        Returns:
            DNS response bytes, or None on parse failure.
        """
        if len(data) < 12:
            return None

        # Parse DNS header
        transaction_id = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        question_count = struct.unpack("!H", data[4:6])[0]
        is_query = (flags & 0x8000) == 0

        if not is_query or question_count == 0:
            return None

        # Parse question section
        offset = 12
        query_name, offset = self._parse_name(data, offset)
        if query_name is None or offset + 4 > len(data):
            return None

        query_type_code = struct.unpack("!H", data[offset:offset + 2])[0]
        query_class = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        query_type = DNS_RECORD_TYPES.get(query_type_code, f"TYPE{query_type_code}")

        # Log the query
        log_entry = DNSQueryLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            query_name=query_name,
            query_type=query_type,
            client_ip=client_ip,
            sinkhole_response=self.sinkhole_ip,
        )
        self.query_log.append(log_entry)
        logger.info("DNS query: %s %s from %s → sinkhole %s", query_type, query_name, client_ip, self.sinkhole_ip)

        # Build response
        return self._build_response(
            transaction_id, data, offset, query_type_code, query_class
        )

    def _parse_name(self, data: bytes, offset: int) -> tuple[Optional[str], int]:
        """Parse a DNS domain name from query data.

        Args:
            data: Raw DNS data.
            offset: Current offset in the data.

        Returns:
            Tuple of (domain_name, new_offset).
        """
        labels: list[str] = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 0xC0:
                # Pointer compression — not handling for simplicity
                offset += 2
                break
            offset += 1
            if offset + length > len(data):
                return None, offset
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

        return ".".join(labels), offset

    def _build_response(
        self,
        transaction_id: int,
        query_data: bytes,
        question_end_offset: int,
        query_type: int,
        query_class: int,
    ) -> bytes:
        """Build a DNS response with sinkhole IP.

        Args:
            transaction_id: DNS transaction ID.
            query_data: Original query data (for question section).
            question_end_offset: End of the question section.
            query_type: DNS record type code.
            query_class: DNS class code.

        Returns:
            Complete DNS response bytes.
        """
        # Response header
        flags = 0x8180  # Standard response, no error, recursion available
        header = struct.pack(
            "!HHHHHH",
            transaction_id,  # ID
            flags,           # Flags
            1,               # Questions
            1,               # Answers
            0,               # Authority
            0,               # Additional
        )

        # Copy question section from query
        question_section = query_data[12:question_end_offset + 4]

        # Build answer section
        # Name pointer (refer back to question)
        answer_name = struct.pack("!H", 0xC00C)

        # For A records, respond with sinkhole IP
        if query_type == 1:  # A record
            answer_rdata = socket.inet_aton(self.sinkhole_ip)
            answer_rdlength = len(answer_rdata)
            answer = (
                answer_name +
                struct.pack("!HHI", query_type, query_class, 60) +  # type, class, TTL
                struct.pack("!H", answer_rdlength) +
                answer_rdata
            )
        elif query_type == 28:  # AAAA record
            # Return ::1 (loopback IPv6)
            answer_rdata = b"\x00" * 15 + b"\x01"
            answer = (
                answer_name +
                struct.pack("!HHI", query_type, query_class, 60) +
                struct.pack("!H", 16) +
                answer_rdata
            )
        else:
            # For other record types, respond with empty (NOERROR, no answer)
            return header + question_section

        return header + question_section + answer

    def get_queries(self) -> list[dict]:
        """Get all logged DNS queries as dicts.

        Returns:
            List of DNS query log dicts.
        """
        return [q.to_dict() for q in self.query_log]

    def get_domains(self) -> list[str]:
        """Get unique domain names from all logged queries.

        Returns:
            De-duplicated list of queried domains.
        """
        seen: set[str] = set()
        domains: list[str] = []
        for q in self.query_log:
            if q.query_name not in seen:
                seen.add(q.query_name)
                domains.append(q.query_name)
        return domains