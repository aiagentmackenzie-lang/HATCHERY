"""Network traffic capture management — tcpdump control and PCAP handling.

Manages tcpdump inside the sandbox container and processes captured PCAPs
for IOC extraction. Integrates with GHOSTWIRE for C2 beacon detection
when the GHOSTWIRE engine is available.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import GHOSTWIRE for C2 detection
GHOSTWIRE_PATH = Path("/Users/main/Security Apps/GHOSTWIRE")
HAS_GHOSTWIRE = False

try:
    import sys
    if str(GHOSTWIRE_PATH) not in sys.path:
        sys.path.insert(0, str(GHOSTWIRE_PATH))
    from engine.detection.beacon import BeaconDetector
    from engine.detection.dns_threats import DNSThreatDetector
    HAS_GHOSTWIRE = True
    logger.info("GHOSTWIRE integration available")
except ImportError:
    logger.debug("GHOSTWIRE not available — C2 detection disabled")


@dataclass
class NetworkConnection:
    """A single network connection extracted from traffic."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 0
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packet_count": self.packet_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class DNSQuery:
    """A DNS query extracted from traffic."""
    query: str
    query_type: str = "A"
    response_ips: list[str] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "query_type": self.query_type,
            "response_ips": self.response_ips,
            "timestamp": self.timestamp,
        }


@dataclass
class C2Detection:
    """C2 beacon detection result from GHOSTWIRE integration."""
    session_id: str
    dst_ip: str
    dst_port: int
    jitter_score: float = 0.0
    confidence: str = "LOW"
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "jitter_score": self.jitter_score,
            "confidence": self.confidence,
            "score": self.score,
            "reasons": self.reasons,
        }


@dataclass
class NetworkCaptureResult:
    """Complete network capture analysis result."""
    pcap_path: Optional[str] = None
    total_packets: int = 0
    connections: list[NetworkConnection] = field(default_factory=list)
    dns_queries: list[DNSQuery] = field(default_factory=list)
    http_requests: list[dict] = field(default_factory=list)
    c2_detections: list[C2Detection] = field(default_factory=list)
    network_iocs: list[dict] = field(default_factory=list)
    ghostwire_available: bool = False
    analysis_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "pcap_path": self.pcap_path,
            "total_packets": self.total_packets,
            "connections": [c.to_dict() for c in self.connections],
            "dns_queries": [d.to_dict() for d in self.dns_queries],
            "http_requests": self.http_requests,
            "c2_detections": [c.to_dict() for c in self.c2_detections],
            "network_iocs": self.network_iocs,
            "ghostwire_available": self.ghostwire_available,
            "analysis_time_ms": self.analysis_time_ms,
            "errors": self.errors,
        }


class NetworkCapture:
    """Analyze network traffic captured from the sandbox.

    Parses PCAP files for connections, DNS queries, and HTTP requests.
    When GHOSTWIRE is available, runs C2 beacon detection on the PCAP.
    """

    def analyze_pcap(self, pcap_path: Path) -> NetworkCaptureResult:
        """Analyze a PCAP file from the sandbox.

        Args:
            pcap_path: Path to the captured PCAP file.

        Returns:
            NetworkCaptureResult with extracted network IOCs.
        """
        import time

        result = NetworkCaptureResult(
            pcap_path=str(pcap_path),
            ghostwire_available=HAS_GHOSTWIRE,
        )

        if not pcap_path.exists():
            result.errors.append(f"PCAP not found: {pcap_path}")
            return result

        start = time.monotonic()

        try:
            # Use tshark for PCAP parsing if available
            result = self._parse_with_tshark(pcap_path, result)
        except Exception:
            # Fallback to raw PCAP parsing
            try:
                result = self._parse_with_scapy(pcap_path, result)
            except Exception as e:
                result.errors.append(f"PCAP parsing failed: {e}")

        # Run GHOSTWIRE C2 detection if available
        if HAS_GHOSTWIRE and pcap_path.exists():
            try:
                result = self._run_ghostwire(pcap_path, result)
            except Exception as e:
                result.errors.append(f"GHOSTWIRE analysis failed: {e}")

        # Extract network IOCs
        result.network_iocs = self._extract_network_iocs(result)

        elapsed = time.monotonic() - start
        result.analysis_time_ms = elapsed * 1000

        logger.info(
            "Network capture analysis: %d connections, %d DNS queries, %d C2 detections",
            len(result.connections),
            len(result.dns_queries),
            len(result.c2_detections),
        )
        return result

    def _parse_with_tshark(
        self, pcap_path: Path, result: NetworkCaptureResult
    ) -> NetworkCaptureResult:
        """Parse PCAP using tshark CLI (Wireshark's command-line tool).

        Args:
            pcap_path: Path to the PCAP.
            result: Result to populate.

        Returns:
            Updated NetworkCaptureResult.
        """
        # Get total packet count
        try:
            count_proc = subprocess.run(
                ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"],
                capture_output=True, text=True, timeout=30,
            )
            result.total_packets = len([l for l in count_proc.stdout.splitlines() if l.strip()])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Extract TCP connections
        try:
            conn_proc = subprocess.run(
                [
                    "tshark", "-r", str(pcap_path),
                    "-T", "fields",
                    "-e", "ip.src", "-e", "tcp.srcport",
                    "-e", "ip.dst", "-e", "tcp.dstport",
                    "-e", "tcp.stream",
                    "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                ],
                capture_output=True, text=True, timeout=30,
            )

            seen_streams: set[str] = set()
            for line in conn_proc.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 4 and parts[0]:
                    stream_key = "\t".join(parts[:4])
                    if stream_key not in seen_streams:
                        seen_streams.add(stream_key)
                        try:
                            result.connections.append(NetworkConnection(
                                src_ip=parts[0],
                                src_port=int(parts[1]) if parts[1] else 0,
                                dst_ip=parts[2],
                                dst_port=int(parts[3]) if parts[3] else 0,
                            ))
                        except (ValueError, IndexError):
                            pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("tshark not available for TCP analysis")

        # Extract DNS queries
        try:
            dns_proc = subprocess.run(
                [
                    "tshark", "-r", str(pcap_path),
                    "-T", "fields",
                    "-e", "dns.qry.name", "-e", "dns.qry.type",
                    "-e", "dns.a",
                    "-Y", "dns.flags.response==0",
                ],
                capture_output=True, text=True, timeout=30,
            )

            seen_queries: set[str] = set()
            for line in dns_proc.stdout.splitlines():
                parts = line.strip().split("\t")
                if parts and parts[0] and parts[0] not in seen_queries:
                    seen_queries.add(parts[0])
                    response_ips = parts[2].split(",") if len(parts) > 2 and parts[2] else []
                    result.dns_queries.append(DNSQuery(
                        query=parts[0],
                        query_type=parts[1] if len(parts) > 1 else "A",
                        response_ips=[ip.strip() for ip in response_ips if ip.strip()],
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("tshark not available for DNS analysis")

        # Extract HTTP requests
        try:
            http_proc = subprocess.run(
                [
                    "tshark", "-r", str(pcap_path),
                    "-T", "fields",
                    "-e", "http.request.method",
                    "-e", "http.host",
                    "-e", "http.request.uri",
                    "-e", "http.user_agent",
                    "-Y", "http.request",
                ],
                capture_output=True, text=True, timeout=30,
            )

            for line in http_proc.stdout.splitlines():
                parts = line.strip().split("\t")
                if parts and parts[0]:
                    result.http_requests.append({
                        "method": parts[0],
                        "host": parts[1] if len(parts) > 1 else "",
                        "uri": parts[2] if len(parts) > 2 else "",
                        "user_agent": parts[3] if len(parts) > 3 else "",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("tshark not available for HTTP analysis")

        return result

    def _parse_with_scapy(
        self, pcap_path: Path, result: NetworkCaptureResult
    ) -> NetworkCaptureResult:
        """Fallback: parse PCAP using scapy.

        Args:
            pcap_path: Path to the PCAP.
            result: Result to populate.

        Returns:
            Updated NetworkCaptureResult.
        """
        try:
            from scapy.all import rdpcap, TCP, DNS, IP, Raw

            packets = rdpcap(str(pcap_path))
            result.total_packets = len(packets)

            seen_connections: set[str] = set()

            for pkt in packets:
                if IP in pkt and TCP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport

                    conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                    if conn_key not in seen_connections:
                        seen_connections.add(conn_key)
                        result.connections.append(NetworkConnection(
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                        ))

                if DNS in pkt and pkt[DNS].qr == 0:
                    # DNS query
                    try:
                        qname = pkt[DNS].qd.qname.decode("utf-8", errors="replace")
                        if qname not in {d.query for d in result.dns_queries}:
                            result.dns_queries.append(DNSQuery(query=qname))
                    except Exception:
                        pass

        except ImportError:
            result.errors.append("Neither tshark nor scapy available for PCAP parsing")
        except Exception as e:
            result.errors.append(f"Scapy parsing error: {e}")

        return result

    def _run_ghostwire(
        self, pcap_path: Path, result: NetworkCaptureResult
    ) -> NetworkCaptureResult:
        """Run GHOSTWIRE C2 beacon detection on the PCAP.

        Args:
            pcap_path: Path to the PCAP file.
            result: Result to add C2 detections to.

        Returns:
            Updated NetworkCaptureResult.
        """
        try:
            from engine.parser.pcap import PCAPParser
            from engine.detection.beacon import BeaconDetector

            parser = PCAPParser()
            sessions = parser.parse(str(pcap_path))

            detector = BeaconDetector()
            for session in sessions:
                score = detector.analyze(session)
                if score.overall_score > 0.3:
                    result.c2_detections.append(C2Detection(
                        session_id=session.session_id,
                        dst_ip=session.dst_ip,
                        dst_port=session.dst_port,
                        jitter_score=score.iat_jitter,
                        confidence=score.confidence,
                        score=score.overall_score,
                        reasons=score.reasons,
                    ))

            logger.info(
                "GHOSTWIRE found %d C2 beacons in %s",
                len(result.c2_detections), pcap_path.name,
            )
        except Exception as e:
            logger.warning("GHOSTWIRE C2 detection failed: %s", e)
            result.errors.append(f"GHOSTWIRE C2 detection: {e}")

        return result

    def _extract_network_iocs(self, result: NetworkCaptureResult) -> list[dict]:
        """Extract network indicators of compromise from analysis results.

        Args:
            result: The analysis result.

        Returns:
            List of IOC dicts with type, value, and context.
        """
        iocs: list[dict] = []

        # IP addresses from connections
        seen_ips: set[str] = set()
        for conn in result.connections:
            if conn.dst_ip not in seen_ips and conn.dst_ip != "127.0.0.1":
                seen_ips.add(conn.dst_ip)
                iocs.append({
                    "type": "ip",
                    "value": conn.dst_ip,
                    "context": f"Connection to port {conn.dst_port}",
                })

        # Domains from DNS queries
        for dns in result.dns_queries:
            iocs.append({
                "type": "domain",
                "value": dns.query,
                "context": f"DNS {dns.query_type} query",
            })

        # URLs from HTTP requests
        for req in result.http_requests:
            if req.get("host") and req.get("uri"):
                url = f"{req['host']}{req['uri']}"
                iocs.append({
                    "type": "url",
                    "value": url,
                    "context": f"HTTP {req.get('method', 'GET')}",
                })

            # User-Agent as IOC
            if req.get("user_agent"):
                iocs.append({
                    "type": "user_agent",
                    "value": req["user_agent"],
                    "context": "HTTP User-Agent",
                })

        # C2 detections as high-priority IOCs
        for c2 in result.c2_detections:
            iocs.append({
                "type": "c2_beacon",
                "value": f"{c2.dst_ip}:{c2.dst_port}",
                "context": f"C2 beacon detected (jitter={c2.jitter_score:.4f}, confidence={c2.confidence})",
            })

        return iocs