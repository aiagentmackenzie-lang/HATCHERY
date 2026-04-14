"""Fake service manager — orchestrate all simulated network services.

Manages the lifecycle of fake DNS, HTTP, and SMTP servers.
Provides a unified interface for starting/stopping all services
and extracting IOCs from all service logs.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from engine.fake_services.dns_server import FakeDNSServer
from engine.fake_services.http_server import FakeHTTPServer
from engine.fake_services.smtp_server import FakeSMTPServer

logger = logging.getLogger(__name__)


@dataclass
class FakeServiceConfig:
    """Configuration for all fake services."""
    bind_address: str = "0.0.0.0"
    dns_port: int = 53
    http_port: int = 80
    smtp_port: int = 25
    sinkhole_ip: str = "127.0.0.1"
    log_dir: Optional[Path] = None

    def to_dict(self) -> dict:
        return {
            "bind_address": self.bind_address,
            "dns_port": self.dns_port,
            "http_port": self.http_port,
            "smtp_port": self.smtp_port,
            "sinkhole_ip": self.sinkhole_ip,
        }


@dataclass
class FakeServiceSummary:
    """Summary of all fake service activity."""
    dns_queries: int = 0
    http_requests: int = 0
    smtp_sessions: int = 0
    domains_queried: list[str] = field(default_factory=list)
    urls_requested: list[str] = field(default_factory=list)
    email_recipients: list[str] = field(default_factory=list)
    network_iocs: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dns_queries": self.dns_queries,
            "http_requests": self.http_requests,
            "smtp_sessions": self.smtp_sessions,
            "domains_queried": self.domains_queried,
            "urls_requested": self.urls_requested,
            "email_recipients": self.email_recipients,
            "network_iocs": self.network_iocs,
        }


class FakeServiceManager:
    """Orchestrate all fake internet services for the sandbox.

    Manages DNS, HTTP, and SMTP fake servers. Provides unified
    start/stop and IOC extraction from all service logs.
    """

    def __init__(self, config: Optional[FakeServiceConfig] = None) -> None:
        self.config = config or FakeServiceConfig()
        self.dns = FakeDNSServer(
            bind_address=self.config.bind_address,
            port=self.config.dns_port,
            sinkhole_ip=self.config.sinkhole_ip,
            log_dir=self.config.log_dir,
        )
        self.http = FakeHTTPServer(
            bind_address=self.config.bind_address,
            port=self.config.http_port,
            log_dir=self.config.log_dir,
        )
        self.smtp = FakeSMTPServer(
            bind_address=self.config.bind_address,
            port=self.config.smtp_port,
            log_dir=self.config.log_dir,
        )
        self._running = False

    def start_all(self) -> None:
        """Start all fake services."""
        if self._running:
            logger.warning("Fake services already running")
            return

        logger.info("Starting all fake services...")

        # Start services on non-privileged ports if needed
        # (DNS port 53 and SMTP port 25 may require root)
        try:
            self.dns.start()
        except Exception as e:
            logger.warning("DNS server failed to start (may need root): %s", e)

        try:
            self.http.start()
        except Exception as e:
            logger.warning("HTTP server failed to start: %s", e)

        try:
            self.smtp.start()
        except Exception as e:
            logger.warning("SMTP server failed to start (may need root): %s", e)

        self._running = True
        logger.info("Fake services started")

    def stop_all(self) -> None:
        """Stop all fake services."""
        if not self._running:
            return

        logger.info("Stopping all fake services...")
        self.dns.stop()
        self.http.stop()
        self.smtp.stop()
        self._running = False
        logger.info("Fake services stopped")

    def get_summary(self) -> FakeServiceSummary:
        """Get a summary of all fake service activity.

        Returns:
            FakeServiceSummary with counts and IOCs.
        """
        summary = FakeServiceSummary(
            dns_queries=len(self.dns.query_log),
            http_requests=len(self.http.request_log),
            smtp_sessions=len(self.smtp.session_log),
            domains_queried=self.dns.get_domains(),
            urls_requested=self.http.get_urls(),
            email_recipients=self.smtp.get_recipients(),
        )

        # Extract network IOCs from all services
        iocs: list[dict] = []

        # DNS domains
        for domain in summary.domains_queried:
            iocs.append({
                "type": "domain",
                "value": domain,
                "source": "fake_dns",
                "context": "DNS query during detonation",
            })

        # HTTP URLs and User-Agents
        for req in self.http.request_log:
            if req.host:
                iocs.append({
                    "type": "url",
                    "value": f"{req.host}{req.path}",
                    "source": "fake_http",
                    "context": f"HTTP {req.method} request",
                })
            if req.user_agent:
                iocs.append({
                    "type": "user_agent",
                    "value": req.user_agent,
                    "source": "fake_http",
                    "context": "HTTP User-Agent header",
                })

        # SMTP recipients (data exfiltration targets)
        for session in self.smtp.session_log:
            for recipient in session.recipients:
                iocs.append({
                    "type": "email",
                    "value": recipient,
                    "source": "fake_smtp",
                    "context": "SMTP recipient (possible exfiltration)",
                })
            if session.sender:
                iocs.append({
                    "type": "email",
                    "value": session.sender,
                    "source": "fake_smtp",
                    "context": "SMTP sender",
                })

        summary.network_iocs = iocs
        return summary

    def export_logs(self, output_dir: Path) -> None:
        """Export all service logs to JSON files.

        Args:
            output_dir: Directory to write log files.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # DNS log
        dns_path = output_dir / "dns_queries.json"
        dns_path.write_text(
            json.dumps(self.dns.get_queries(), indent=2),
            encoding="utf-8",
        )

        # HTTP log
        http_path = output_dir / "http_requests.json"
        http_path.write_text(
            json.dumps(self.http.get_requests(), indent=2),
            encoding="utf-8",
        )

        # SMTP log
        smtp_path = output_dir / "smtp_sessions.json"
        smtp_path.write_text(
            json.dumps(self.smtp.get_sessions(), indent=2),
            encoding="utf-8",
        )

        # Summary
        summary_path = output_dir / "fake_services_summary.json"
        summary_path.write_text(
            json.dumps(self.get_summary().to_dict(), indent=2),
            encoding="utf-8",
        )

        logger.info("Exported fake service logs to %s", output_dir)

    @property
    def is_running(self) -> bool:
        """Check if services are running."""
        return self._running