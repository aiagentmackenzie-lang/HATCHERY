"""SSE event aggregator — stream behavioral events to consumers.

Collects events from all monitoring sources (strace, inotify, network)
and aggregates them into a single chronological event stream.
Supports Server-Sent Events (SSE) for real-time dashboard updates
and batch retrieval for report generation.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Generator, Optional

from engine.monitor.strace_parser import StraceEvent, EventCategory, EventSeverity
from engine.monitor.file_watcher import FileEvent
from engine.monitor.network_capture import NetworkConnection, DNSQuery

logger = logging.getLogger(__name__)


class EventSource(str, Enum):
    """Source of a behavioral event."""
    STRACE = "strace"
    FILE_WATCH = "file_watch"
    NETWORK = "network"
    STATIC = "static"
    SYSTEM = "system"


@dataclass
class StreamEvent:
    """Unified behavioral event from any monitoring source."""
    id: str
    timestamp: str
    source: EventSource
    event_type: str
    category: str  # Maps to EventCategory value
    severity: str  # Maps to EventSeverity value
    data: dict = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source.value,
            "event_type": self.event_type,
            "category": self.category,
            "severity": self.severity,
            "data": self.data,
            "indicators": self.indicators,
        }

    def to_sse(self) -> str:
        """Format as Server-Sent Event message."""
        return f"data: {json.dumps(self.to_dict())}\n\n"


@dataclass
class EventStreamStats:
    """Statistics about the event stream."""
    total_events: int = 0
    events_by_source: dict[str, int] = field(default_factory=dict)
    events_by_category: dict[str, int] = field(default_factory=dict)
    events_by_severity: dict[str, int] = field(default_factory=dict)
    start_time: Optional[str] = None
    end_time: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_events,
            "events_by_source": self.events_by_source,
            "events_by_category": self.events_by_category,
            "events_by_severity": self.events_by_severity,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


class EventStream:
    """Aggregate and stream behavioral events from all monitoring sources.

    Collects events into a chronological stream and supports:
    - SSE generator for real-time dashboard consumption
    - Batch retrieval for report generation
    - Event filtering by source, category, severity
    - Statistics tracking
    """

    def __init__(self) -> None:
        self._events: list[StreamEvent] = []
        self._event_counter = 0
        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue] = []
        self._stats = EventStreamStats()

    @property
    def stats(self) -> EventStreamStats:
        """Current stream statistics."""
        return self._stats

    def _generate_id(self) -> str:
        """Generate a unique event ID."""
        self._event_counter += 1
        return f"evt-{self._event_counter:06d}"

    def _now_iso(self) -> str:
        """Current UTC timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()

    def _update_stats(self, event: StreamEvent) -> None:
        """Update stream statistics with a new event."""
        self._stats.total_events += 1
        self._stats.events_by_source[event.source.value] = (
            self._stats.events_by_source.get(event.source.value, 0) + 1
        )
        self._stats.events_by_category[event.category] = (
            self._stats.events_by_category.get(event.category, 0) + 1
        )
        self._stats.events_by_severity[event.severity] = (
            self._stats.events_by_severity.get(event.severity, 0) + 1
        )
        if self._stats.start_time is None:
            self._stats.start_time = event.timestamp
        self._stats.end_time = event.timestamp

    def _notify_subscribers(self, event: StreamEvent) -> None:
        """Push event to all subscriber queues."""
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                logger.debug("Subscriber queue full — dropping event %s", event.id)

    def add_strace_event(self, strace_event: StraceEvent) -> StreamEvent:
        """Add a strace event to the stream.

        Args:
            strace_event: Parsed strace event.

        Returns:
            The unified StreamEvent.
        """
        event = StreamEvent(
            id=self._generate_id(),
            timestamp=strace_event.timestamp,
            source=EventSource.STRACE,
            event_type=strace_event.syscall,
            category=strace_event.category.value,
            severity=strace_event.severity.value,
            data={
                "pid": strace_event.pid,
                "syscall": strace_event.syscall,
                "args": strace_event.args,
                "return_value": strace_event.return_value,
            },
            indicators=strace_event.indicators,
        )
        self._add_event(event)
        return event

    def add_file_event(self, file_event: FileEvent) -> StreamEvent:
        """Add a file watcher event to the stream.

        Args:
            file_event: Parsed file event.

        Returns:
            The unified StreamEvent.
        """
        event = StreamEvent(
            id=self._generate_id(),
            timestamp=file_event.timestamp,
            source=EventSource.FILE_WATCH,
            event_type=file_event.event_type.value,
            category="file",
            severity=file_event.severity.value,
            data={
                "path": file_event.path,
                "is_directory": file_event.is_directory,
                "file_hash": file_event.file_hash,
                "file_type": file_event.file_type,
            },
            indicators=file_event.indicators,
        )
        self._add_event(event)
        return event

    def add_network_connection(self, conn: NetworkConnection, timestamp: str = "") -> StreamEvent:
        """Add a network connection event to the stream.

        Args:
            conn: Network connection data.
            timestamp: Event timestamp.

        Returns:
            The unified StreamEvent.
        """
        event = StreamEvent(
            id=self._generate_id(),
            timestamp=timestamp or self._now_iso(),
            source=EventSource.NETWORK,
            event_type="connection",
            category="network",
            severity="high" if conn.dst_port in (443, 80, 8080) else "medium",
            data=conn.to_dict(),
            indicators=[],
        )
        self._add_event(event)
        return event

    def add_dns_query(self, dns: DNSQuery, timestamp: str = "") -> StreamEvent:
        """Add a DNS query event to the stream.

        Args:
            dns: DNS query data.
            timestamp: Event timestamp.

        Returns:
            The unified StreamEvent.
        """
        event = StreamEvent(
            id=self._generate_id(),
            timestamp=timestamp or self._now_iso(),
            source=EventSource.NETWORK,
            event_type="dns_query",
            category="network",
            severity="medium",
            data=dns.to_dict(),
            indicators=[],
        )
        self._add_event(event)
        return event

    def add_custom_event(
        self,
        event_type: str,
        category: str,
        severity: str,
        data: dict,
        indicators: Optional[list[str]] = None,
        timestamp: Optional[str] = None,
    ) -> StreamEvent:
        """Add a custom event to the stream.

        Args:
            event_type: Type of event.
            category: Event category.
            severity: Severity level.
            data: Event data.
            indicators: Suspicious indicators.
            timestamp: Event timestamp.

        Returns:
            The unified StreamEvent.
        """
        event = StreamEvent(
            id=self._generate_id(),
            timestamp=timestamp or self._now_iso(),
            source=EventSource.SYSTEM,
            event_type=event_type,
            category=category,
            severity=severity,
            data=data,
            indicators=indicators or [],
        )
        self._add_event(event)
        return event

    def _add_event(self, event: StreamEvent) -> None:
        """Add an event to the stream (thread-safe).

        Args:
            event: The event to add.
        """
        with self._lock:
            self._events.append(event)
            self._update_stats(event)
        self._notify_subscribers(event)

    def get_events(
        self,
        source: Optional[EventSource] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[StreamEvent]:
        """Retrieve events with optional filtering.

        Args:
            source: Filter by event source.
            category: Filter by category.
            severity: Filter by severity.
            limit: Maximum events to return.
            offset: Number of events to skip.

        Returns:
            List of matching StreamEvents.
        """
        with self._lock:
            filtered = self._events

        if source is not None:
            filtered = [e for e in filtered if e.source == source]
        if category is not None:
            filtered = [e for e in filtered if e.category == category]
        if severity is not None:
            filtered = [e for e in filtered if e.severity == severity]

        return filtered[offset:offset + limit]

    def get_sse_generator(
        self,
        source: Optional[EventSource] = None,
    ) -> Generator[str, None, None]:
        """Create an SSE generator for real-time event streaming.

        Use with FastAPI's StreamingResponse for dashboard consumption.

        Args:
            source: Optional filter by source.

        Yields:
            SSE-formatted event strings.
        """
        q: queue.Queue = queue.Queue(maxsize=1000)
        self._subscribers.append(q)

        try:
            while True:
                try:
                    event = q.get(timeout=30)
                    if source is None or event.source == source:
                        yield event.to_sse()
                except queue.Empty:
                    # Send keep-alive
                    yield ": keepalive\n\n"
        finally:
            self._subscribers.remove(q)

    def get_timeline(self) -> list[dict]:
        """Get the complete chronological event timeline.

        Returns:
            List of event dicts sorted by timestamp.
        """
        with self._lock:
            events = sorted(self._events, key=lambda e: e.timestamp)
        return [e.to_dict() for e in events]

    def clear(self) -> None:
        """Clear all events and reset statistics."""
        with self._lock:
            self._events.clear()
            self._event_counter = 0
            self._stats = EventStreamStats()
        for q in self._subscribers:
            while not q.empty():
                try:
                    q.get_nowait()
                except queue.Empty:
                    break