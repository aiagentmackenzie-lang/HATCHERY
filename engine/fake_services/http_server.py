"""Fake HTTP server — respond to malware HTTP/HTTPS requests.

Returns generic 200 OK responses to trick malware into thinking
its C2 server is alive. Captures all request data (URLs, headers,
POST bodies, User-Agents) for IOC extraction.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DEFAULT_BIND_ADDRESS = "0.0.0.0"


@dataclass  # noqa: F821 — dataclass is used below
class HTTPRequestLog:
    """A logged HTTP request."""
    timestamp: str
    method: str
    path: str
    host: str
    user_agent: str
    content_type: str = ""
    content_length: int = 0
    body: str = ""
    client_ip: str = ""
    response_code: int = 200

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "body": self.body[:1000],  # Cap body size in logs
            "client_ip": self.client_ip,
            "response_code": self.response_code,
        }


# Import dataclass properly (avoid the forward reference issue)
from dataclasses import dataclass as _dc

@_dc
class HTTPRequestLog:
    """A logged HTTP request."""
    timestamp: str = ""
    method: str = ""
    path: str = ""
    host: str = ""
    user_agent: str = ""
    content_type: str = ""
    content_length: int = 0
    body: str = ""
    client_ip: str = ""
    response_code: int = 200

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "user_agent": self.user_agent,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "body": self.body[:1000],
            "client_ip": self.client_ip,
            "response_code": self.response_code,
        }


class FakeHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures all requests and returns fake responses."""

    # Shared reference to the server's request log (set by FakeHTTPServer)
    request_log: list[HTTPRequestLog] = []

    def log_message(self, format: str, *args) -> None:
        """Override to use our logger instead of stderr."""
        logger.debug("HTTP: %s", format % args)

    def _capture_request(self, method: str) -> None:
        """Capture request details and log them.

        Args:
            method: HTTP method (GET, POST, etc.).
        """
        content_length = int(self.headers.get("Content-Length", 0))
        body = ""
        if content_length > 0:
            try:
                raw_body = self.rfile.read(min(content_length, 65536))
                body = raw_body.decode("utf-8", errors="replace")
            except Exception:
                body = "<read error>"

        log_entry = HTTPRequestLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method,
            path=self.path,
            host=self.headers.get("Host", ""),
            user_agent=self.headers.get("User-Agent", ""),
            content_type=self.headers.get("Content-Type", ""),
            content_length=content_length,
            body=body,
            client_ip=self.client_address[0],
        )
        self.request_log.append(log_entry)

        logger.info(
            "HTTP %s %s from %s (UA: %s)",
            method, self.path, self.client_address[0],
            self.headers.get("User-Agent", "none"),
        )

    def _send_fake_response(self) -> None:
        """Send a generic 200 OK response to the client."""
        # Return a generic HTML page that looks like a real server
        response_body = b"""<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1><p>Server is running.</p></body></html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._capture_request("GET")
        self._send_fake_response()

    def do_POST(self) -> None:
        """Handle POST requests."""
        self._capture_request("POST")
        self._send_fake_response()

    def do_PUT(self) -> None:
        """Handle PUT requests."""
        self._capture_request("PUT")
        self._send_fake_response()

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        self._capture_request("DELETE")
        self._send_fake_response()

    def do_HEAD(self) -> None:
        """Handle HEAD requests."""
        self._capture_request("HEAD")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        """Handle OPTIONS requests (CORS preflight)."""
        self._capture_request("OPTIONS")
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self.end_headers()


class FakeHTTPServer:
    """Fake HTTP server that captures all requests and returns generic responses.

    Runs in a background thread. All requests are logged for IOC extraction.
    """

    def __init__(
        self,
        bind_address: str = DEFAULT_BIND_ADDRESS,
        port: int = DEFAULT_HTTP_PORT,
        log_dir: Optional[Path] = None,
    ) -> None:
        self.bind_address = bind_address
        self.port = port
        self.log_dir = log_dir
        self.request_log: list[HTTPRequestLog] = []
        self._running = False
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the fake HTTP server in a background thread."""
        if self._running:
            return

        # Share the request log with the handler
        FakeHTTPHandler.request_log = self.request_log

        try:
            self._server = HTTPServer(
                (self.bind_address, self.port),
                FakeHTTPHandler,
            )
        except OSError as e:
            logger.error("Failed to bind HTTP server on %s:%d: %s", self.bind_address, self.port, e)
            return

        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info("Fake HTTP server started on %s:%d", self.bind_address, self.port)

    def stop(self) -> None:
        """Stop the fake HTTP server."""
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Fake HTTP server stopped (%d requests logged)", len(self.request_log))

    def _serve(self) -> None:
        """Main HTTP server loop."""
        try:
            self._server.serve_forever()
        except Exception as e:
            if self._running:
                logger.error("HTTP server error: %s", e)

    def get_requests(self) -> list[dict]:
        """Get all logged HTTP requests as dicts."""
        return [r.to_dict() for r in self.request_log]

    def get_urls(self) -> list[str]:
        """Get unique URLs from all logged requests."""
        seen: set[str] = set()
        urls: list[str] = []
        for r in self.request_log:
            url = f"{r.host}{r.path}" if r.host else r.path
            if url not in seen:
                seen.add(url)
                urls.append(url)
        return urls