"""Tests for HATCHERY fake services (DNS, HTTP, SMTP)."""

import pytest
from pathlib import Path

from engine.fake_services.dns_server import FakeDNSServer, DNSQueryLog
from engine.fake_services.http_server import FakeHTTPServer, HTTPRequestLog, FakeHTTPHandler
from engine.fake_services.smtp_server import FakeSMTPServer, SMTPSessionLog
from engine.fake_services.service_manager import (
    FakeServiceManager,
    FakeServiceConfig,
    FakeServiceSummary,
)


class TestDNSQueryLog:
    """Test DNS query log dataclass."""

    def test_dns_query_log_creation(self):
        """Test creating a DNS query log entry."""
        log = DNSQueryLog(
            timestamp="2026-04-14T12:00:00",
            query_name="evil.com",
            query_type="A",
            client_ip="172.28.0.2",
        )
        assert log.query_name == "evil.com"
        assert log.sinkhole_response == "127.0.0.1"  # Default

    def test_dns_query_log_to_dict(self):
        """Test DNS query log serialization."""
        log = DNSQueryLog(
            timestamp="2026-04-14T12:00:00",
            query_name="test.evil.com",
            query_type="AAAA",
            client_ip="10.0.0.1",
            sinkhole_response="::1",
        )
        d = log.to_dict()
        assert d["query_name"] == "test.evil.com"
        assert d["query_type"] == "AAAA"
        assert d["client_ip"] == "10.0.0.1"
        assert d["sinkhole_response"] == "::1"


class TestFakeDNSServer:
    """Test fake DNS server (unit-level, no network)."""

    def test_dns_server_init_defaults(self):
        """Test DNS server initialization with defaults."""
        server = FakeDNSServer()
        assert server.port == 53
        assert server.sinkhole_ip == "127.0.0.1"
        assert server._running is False

    def test_dns_server_init_custom(self):
        """Test DNS server initialization with custom config."""
        server = FakeDNSServer(
            bind_address="192.168.1.1",
            port=5353,
            sinkhole_ip="10.0.0.1",
        )
        assert server.bind_address == "192.168.1.1"
        assert server.port == 5353
        assert server.sinkhole_ip == "10.0.0.1"

    def test_parse_dns_name(self):
        """Test DNS name parsing from raw bytes."""
        server = FakeDNSServer()
        # Build a simple DNS name: 3 "www" 4 "evil" 3 "com" 0
        name_bytes = bytes([3]) + b"www" + bytes([4]) + b"evil" + bytes([3]) + b"com" + bytes([0])
        # Prepend offset bytes (simulating position in a packet)
        data = b"\x00" * 12 + name_bytes

        name, offset = server._parse_name(data, 12)
        assert name == "www.evil.com"

    def test_parse_dns_name_truncated(self):
        """Test DNS name parsing with truncated data."""
        server = FakeDNSServer()
        name_bytes = bytes([3]) + b"ww"  # Truncated: says 3 but only 2 bytes
        data = b"\x00" * 12 + name_bytes

        name, offset = server._parse_name(data, 12)
        assert name is None  # Should return None for truncated data

    def test_get_domains_empty(self):
        """Test getting domains when no queries logged."""
        server = FakeDNSServer()
        assert server.get_domains() == []

    def test_get_queries_empty(self):
        """Test getting queries when none logged."""
        server = FakeDNSServer()
        assert server.get_queries() == []


class TestHTTPRequestLog:
    """Test HTTP request log dataclass."""

    def test_http_request_log_creation(self):
        """Test creating an HTTP request log."""
        log = HTTPRequestLog(
            timestamp="2026-04-14T12:00:00",
            method="GET",
            path="/api/check",
            host="evil.com",
            user_agent="Mozilla/5.0",
        )
        assert log.method == "GET"
        assert log.host == "evil.com"

    def test_http_request_log_to_dict(self):
        """Test HTTP request log serialization."""
        log = HTTPRequestLog(
            timestamp="2026-04-14T12:00:00",
            method="POST",
            path="/submit",
            host="c2.attacker.com",
            user_agent="CustomBot/1.0",
            content_type="application/json",
            content_length=42,
            body='{"data": "exfil"}',
            client_ip="172.28.0.2",
            response_code=200,
        )
        d = log.to_dict()
        assert d["method"] == "POST"
        assert d["host"] == "c2.attacker.com"
        assert d["response_code"] == 200

    def test_http_request_log_body_truncation(self):
        """Test that body is truncated in serialization."""
        long_body = "x" * 2000
        log = HTTPRequestLog(
            timestamp="2026-04-14T12:00:00",
            method="POST",
            path="/",
            host="evil.com",
            user_agent="",
            body=long_body,
        )
        d = log.to_dict()
        assert len(d["body"]) == 1000  # Capped at 1000 chars


class TestFakeHTTPServer:
    """Test fake HTTP server (unit-level, no network)."""

    def test_http_server_init_defaults(self):
        """Test HTTP server initialization with defaults."""
        server = FakeHTTPServer()
        assert server.port == 80
        assert server._running is False

    def test_http_server_init_custom(self):
        """Test HTTP server initialization with custom config."""
        server = FakeHTTPServer(bind_address="0.0.0.0", port=8080)
        assert server.bind_address == "0.0.0.0"
        assert server.port == 8080

    def test_get_urls_empty(self):
        """Test getting URLs when no requests logged."""
        server = FakeHTTPServer()
        assert server.get_urls() == []


class TestSMTPSessionLog:
    """Test SMTP session log dataclass."""

    def test_smtp_session_log_creation(self):
        """Test creating an SMTP session log."""
        log = SMTPSessionLog(
            timestamp="2026-04-14T12:00:00",
            client_ip="172.28.0.2",
            sender="malware@evil.com",
            recipients=["exfil@attacker.com"],
            subject="Stolen Data",
        )
        assert log.sender == "malware@evil.com"
        assert log.recipients == ["exfil@attacker.com"]

    def test_smtp_session_log_to_dict(self):
        """Test SMTP session log serialization."""
        log = SMTPSessionLog(
            timestamp="2026-04-14T12:00:00",
            client_ip="172.28.0.2",
            sender="malware@evil.com",
            recipients=["target@attacker.com"],
            subject="Data",
            body="Secret content",
        )
        d = log.to_dict()
        assert d["sender"] == "malware@evil.com"
        assert d["recipients"] == ["target@attacker.com"]
        assert d["subject"] == "Data"


class TestFakeSMTPServer:
    """Test fake SMTP server (unit-level, no network)."""

    def test_smtp_server_init_defaults(self):
        """Test SMTP server initialization with defaults."""
        server = FakeSMTPServer()
        assert server.port == 25
        assert server._running is False

    def test_smtp_server_init_custom(self):
        """Test SMTP server initialization with custom config."""
        server = FakeSMTPServer(bind_address="192.168.1.1", port=2525)
        assert server.bind_address == "192.168.1.1"
        assert server.port == 2525

    def test_get_recipients_empty(self):
        """Test getting recipients when no sessions logged."""
        server = FakeSMTPServer()
        assert server.get_recipients() == []

    def test_get_sessions_empty(self):
        """Test getting sessions when none logged."""
        server = FakeSMTPServer()
        assert server.get_sessions() == []


class TestFakeServiceConfig:
    """Test fake service configuration."""

    def test_default_config(self):
        """Test default service configuration."""
        config = FakeServiceConfig()
        assert config.bind_address == "0.0.0.0"
        assert config.dns_port == 53
        assert config.http_port == 80
        assert config.smtp_port == 25
        assert config.sinkhole_ip == "127.0.0.1"

    def test_custom_config(self):
        """Test custom service configuration."""
        config = FakeServiceConfig(
            bind_address="10.0.0.1",
            dns_port=5353,
            http_port=8080,
            smtp_port=2525,
            sinkhole_ip="10.0.0.2",
        )
        assert config.bind_address == "10.0.0.1"
        assert config.dns_port == 5353
        assert config.sinkhole_ip == "10.0.0.2"

    def test_config_to_dict(self):
        """Test config serialization."""
        config = FakeServiceConfig()
        d = config.to_dict()
        assert "bind_address" in d
        assert "dns_port" in d
        assert "http_port" in d


class TestFakeServiceManager:
    """Test fake service manager (unit-level, no network)."""

    def test_manager_init(self):
        """Test service manager initialization."""
        manager = FakeServiceManager()
        assert manager.dns is not None
        assert manager.http is not None
        assert manager.smtp is not None
        assert manager.is_running is False

    def test_manager_custom_config(self):
        """Test service manager with custom config."""
        config = FakeServiceConfig(
            bind_address="10.0.0.1",
            dns_port=5353,
            http_port=8080,
            smtp_port=2525,
            sinkhole_ip="10.0.0.2",
        )
        manager = FakeServiceManager(config=config)
        assert manager.dns.port == 5353
        assert manager.http.port == 8080
        assert manager.smtp.port == 2525

    def test_get_summary_empty(self):
        """Test getting a summary with no activity."""
        manager = FakeServiceManager()
        summary = manager.get_summary()
        assert isinstance(summary, FakeServiceSummary)
        assert summary.dns_queries == 0
        assert summary.http_requests == 0
        assert summary.smtp_sessions == 0
        assert summary.domains_queried == []
        assert summary.urls_requested == []
        assert summary.email_recipients == []

    def test_summary_to_dict(self):
        """Test summary serialization."""
        summary = FakeServiceSummary(
            dns_queries=5,
            http_requests=10,
            smtp_sessions=2,
            domains_queried=["evil.com"],
            urls_requested=["http://evil.com/p"],
            email_recipients=["exfil@evil.com"],
        )
        d = summary.to_dict()
        assert d["dns_queries"] == 5
        assert d["http_requests"] == 10
        assert d["smtp_sessions"] == 2


class TestFakeServiceExport:
    """Test fake service log export."""

    def test_export_logs(self, tmp_path):
        """Test exporting service logs to JSON files."""
        manager = FakeServiceManager()
        manager.export_logs(tmp_path)

        assert (tmp_path / "dns_queries.json").exists()
        assert (tmp_path / "http_requests.json").exists()
        assert (tmp_path / "smtp_sessions.json").exists()
        assert (tmp_path / "fake_services_summary.json").exists()

        # Verify JSON is valid
        import json
        for f in tmp_path.glob("*.json"):
            data = json.loads(f.read_text())
            assert isinstance(data, (dict, list))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])