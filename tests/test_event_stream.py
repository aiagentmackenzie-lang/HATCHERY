"""Tests for HATCHERY event stream aggregation."""

import pytest
from engine.monitor.event_stream import (
    EventStream,
    StreamEvent,
    EventSource,
    EventStreamStats,
)
from engine.monitor.strace_parser import StraceEvent, EventCategory, EventSeverity
from engine.monitor.file_watcher import FileEvent, FileEventType, FileEventSeverity
from engine.monitor.network_capture import NetworkConnection, DNSQuery


class TestEventStream:
    """Test event stream creation, filtering, and statistics."""

    def setup_method(self):
        self.stream = EventStream()

    def test_add_strace_event(self):
        """Test adding a strace event to the stream."""
        strace_event = StraceEvent(
            timestamp="12:00:00.123456",
            pid=1234,
            syscall="openat",
            args='AT_FDCWD, "/etc/passwd", O_RDONLY',
            return_value="3",
            category=EventCategory.FILE,
            severity=EventSeverity.HIGH,
            indicators=["Suspicious path in openat"],
        )

        event = self.stream.add_strace_event(strace_event)

        assert event.source == EventSource.STRACE
        assert event.event_type == "openat"
        assert event.category == "file"
        assert event.severity == "high"
        assert event.id.startswith("evt-")

    def test_add_file_event(self):
        """Test adding a file watcher event to the stream."""
        file_event = FileEvent(
            timestamp="2026-04-14T12:00:00",
            path="/tmp/payload",
            event_type=FileEventType.CREATE,
            severity=FileEventSeverity.MEDIUM,
            indicators=["Temp directory write (dropper behavior)"],
        )

        event = self.stream.add_file_event(file_event)

        assert event.source == EventSource.FILE_WATCH
        assert event.event_type == "create"
        assert event.category == "file"

    def test_add_network_connection(self):
        """Test adding a network connection to the stream."""
        conn = NetworkConnection(
            src_ip="172.28.0.2",
            src_port=45123,
            dst_ip="185.220.101.34",
            dst_port=443,
        )

        event = self.stream.add_network_connection(conn)

        assert event.source == EventSource.NETWORK
        assert event.event_type == "connection"
        assert event.severity == "high"  # Port 443

    def test_add_dns_query(self):
        """Test adding a DNS query to the stream."""
        dns = DNSQuery(
            query="evil.attacker.com",
            query_type="A",
            response_ips=["93.184.216.34"],
        )

        event = self.stream.add_dns_query(dns)

        assert event.source == EventSource.NETWORK
        assert event.event_type == "dns_query"
        assert event.category == "network"

    def test_add_custom_event(self):
        """Test adding a custom event to the stream."""
        event = self.stream.add_custom_event(
            event_type="yara_match",
            category="static",
            severity="high",
            data={"rule": "HATCHERY_SandboxEvasion_Sleep"},
            indicators=["YARA match"],
        )

        assert event.source == EventSource.SYSTEM
        assert event.event_type == "yara_match"
        assert event.severity == "high"

    def test_event_id_incrementing(self):
        """Test that event IDs increment properly."""
        event1 = self.stream.add_custom_event("a", "b", "low", {})
        event2 = self.stream.add_custom_event("a", "b", "low", {})

        assert event1.id != event2.id
        # IDs should be sequential
        num1 = int(event1.id.split("-")[1])
        num2 = int(event2.id.split("-")[1])
        assert num2 == num1 + 1

    def test_statistics_tracking(self):
        """Test that stream statistics are tracked correctly."""
        stats = EventStreamStats()

        # Add events from different sources
        strace_event = StraceEvent(
            timestamp="12:00:00.000000",
            pid=100,
            syscall="connect",
            args="...",
            return_value="0",
            category=EventCategory.NETWORK,
            severity=EventSeverity.HIGH,
        )
        self.stream.add_strace_event(strace_event)
        self.stream.add_custom_event("test", "system", "low", {})

        stats = self.stream.stats
        assert stats.total_events == 2
        assert "strace" in stats.events_by_source
        assert "system" in stats.events_by_source

    def test_get_events_with_filter(self):
        """Test filtering events by source."""
        # Add events from multiple sources
        self.stream.add_custom_event("a", "b", "low", {})
        strace_event = StraceEvent(
            timestamp="12:00:00.000000",
            pid=100,
            syscall="openat",
            args='...',
            return_value="3",
            category=EventCategory.FILE,
            severity=EventSeverity.LOW,
        )
        self.stream.add_strace_event(strace_event)

        # Filter by source
        strace_events = self.stream.get_events(source=EventSource.STRACE)
        assert len(strace_events) == 1
        assert strace_events[0].source == EventSource.STRACE

    def test_get_events_with_severity_filter(self):
        """Test filtering events by severity."""
        self.stream.add_custom_event("a", "b", "critical", {})
        self.stream.add_custom_event("c", "d", "low", {})

        critical_events = self.stream.get_events(severity="critical")
        assert len(critical_events) == 1
        assert critical_events[0].severity == "critical"

    def test_get_events_pagination(self):
        """Test event pagination with limit and offset."""
        for i in range(10):
            self.stream.add_custom_event(f"evt_{i}", "test", "low", {})

        page1 = self.stream.get_events(limit=5, offset=0)
        page2 = self.stream.get_events(limit=5, offset=5)

        assert len(page1) == 5
        assert len(page2) == 5

    def test_stream_event_to_dict(self):
        """Test StreamEvent serialization."""
        event = StreamEvent(
            id="evt-000001",
            timestamp="2026-04-14T12:00:00",
            source=EventSource.STRACE,
            event_type="connect",
            category="network",
            severity="high",
            data={"pid": 1234},
            indicators=["Suspicious connect"],
        )

        d = event.to_dict()
        assert d["id"] == "evt-000001"
        assert d["source"] == "strace"
        assert d["category"] == "network"
        assert d["severity"] == "high"

    def test_stream_event_to_sse(self):
        """Test SSE formatting."""
        event = StreamEvent(
            id="evt-000001",
            timestamp="2026-04-14T12:00:00",
            source=EventSource.NETWORK,
            event_type="connection",
            category="network",
            severity="medium",
            data={},
        )

        sse = event.to_sse()
        assert sse.startswith("data: ")
        assert "\n\n" in sse

    def test_timeline_ordering(self):
        """Test that timeline returns events sorted by timestamp."""
        _e1 = self.stream.add_custom_event("a", "b", "low", {}, timestamp="2026-01-01T10:00:00")
        _e2 = self.stream.add_custom_event("c", "d", "low", {}, timestamp="2026-01-01T09:00:00")

        timeline = self.stream.get_timeline()
        assert len(timeline) == 2

    def test_clear_stream(self):
        """Test clearing the event stream."""
        self.stream.add_custom_event("a", "b", "low", {})
        assert self.stream.stats.total_events == 1

        self.stream.clear()
        assert self.stream.stats.total_events == 0

    def test_network_port_443_high_severity(self):
        """Test that connections to port 443 get HIGH severity."""
        conn = NetworkConnection(
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="1.2.3.4",
            dst_port=443,
        )
        event = self.stream.add_network_connection(conn)
        assert event.severity == "high"

    def test_network_port_8080_high_severity(self):
        """Test that connections to port 8080 get HIGH severity."""
        conn = NetworkConnection(
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="1.2.3.4",
            dst_port=8080,
        )
        event = self.stream.add_network_connection(conn)
        assert event.severity == "high"

    def test_network_other_port_medium_severity(self):
        """Test that connections to other ports get MEDIUM severity."""
        conn = NetworkConnection(
            src_ip="10.0.0.1",
            src_port=54321,
            dst_ip="1.2.3.4",
            dst_port=9999,
        )
        event = self.stream.add_network_connection(conn)
        assert event.severity == "medium"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])