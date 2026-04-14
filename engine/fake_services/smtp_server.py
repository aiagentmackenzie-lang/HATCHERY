"""Fake SMTP server — accept and log all email from malware.

Accepts all SMTP connections and captures email data including
recipients, subjects, and attachments. Useful for detecting
data exfiltration and spam-sending malware.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    import aiosmtpd.controller
    import aiosmtpd.handlers
    HAS_AIOSMTPD = True
except ImportError:
    HAS_AIOSMTPD = False
    logger.debug("aiosmtpd not available — using socket-based SMTP fallback")

DEFAULT_SMTP_PORT = 25
DEFAULT_BIND_ADDRESS = "0.0.0.0"


@dataclass
class SMTPSessionLog:
    """A logged SMTP session with all captured data."""
    timestamp: str = ""
    client_ip: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    subject: str = ""
    body: str = ""
    raw_data: str = ""
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "client_ip": self.client_ip,
            "sender": self.sender,
            "recipients": self.recipients,
            "subject": self.subject,
            "body": self.body[:5000],  # Cap body size
            "raw_data": self.raw_data[:10000],
            "attachments": self.attachments,
        }


class SMTPMessageHandler:
    """Handler that captures all SMTP messages for logging.

    Used with aiosmtpd when available, or as a standalone processor.
    """

    def __init__(self, session_log: list[SMTPSessionLog]) -> None:
        self.session_log = session_log

    async def handle_DATA(self, server, session, envelope) -> str:
        """Process received email data.

        Args:
            server: SMTP server instance.
            session: Client session info.
            envelope: Message envelope with sender/recipients/data.

        Returns:
            "250 OK" to accept the message.
        """
        import email
        from email import policy

        raw_data = envelope.content
        if isinstance(raw_data, bytes):
            raw_str = raw_data.decode("utf-8", errors="replace")
        else:
            raw_str = str(raw_data)

        # Parse the email
        msg = email.message_from_string(raw_str, policy=policy.default)
        subject = str(msg.get("Subject", ""))
        body = ""
        attachments: list[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")
            except Exception:
                body = raw_str

        log_entry = SMTPSessionLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=getattr(session, "peer", ("unknown",))[0],
            sender=envelope.mail_from,
            recipients=list(envelope.rcpt_tos),
            subject=subject,
            body=body,
            raw_data=raw_str,
            attachments=attachments,
        )
        self.session_log.append(log_entry)

        logger.info(
            "SMTP: %s → %s (subject: %s, attachments: %d)",
            envelope.mail_from, envelope.rcpt_tos, subject, len(attachments),
        )

        return "250 OK Message accepted"


class FakeSMTPServer:
    """Fake SMTP server that accepts all mail and logs it.

    Uses aiosmtpd when available for full SMTP protocol support.
    Falls back to a simple socket-based implementation.
    """

    def __init__(
        self,
        bind_address: str = DEFAULT_BIND_ADDRESS,
        port: int = DEFAULT_SMTP_PORT,
        log_dir: Optional[Path] = None,
    ) -> None:
        self.bind_address = bind_address
        self.port = port
        self.log_dir = log_dir
        self.session_log: list[SMTPSessionLog] = []
        self._running = False
        self._controller = None
        self._thread: Optional[threading.Thread] = None
        self._socket_server = None

    def start(self) -> None:
        """Start the fake SMTP server."""
        if self._running:
            return

        if HAS_AIOSMTPD:
            self._start_aiosmtpd()
        else:
            self._start_socket_smtp()

        self._running = True

    def _start_aiosmtpd(self) -> None:
        """Start using aiosmtpd (full SMTP protocol)."""
        handler = SMTPMessageHandler(self.session_log)
        from aiosmtpd.controller import Controller

        self._controller = Controller(
            handler,
            hostname=self.bind_address,
            port=self.port,
        )
        self._controller.start()
        logger.info("Fake SMTP server started on %s:%d (aiosmtpd)", self.bind_address, self.port)

    def _start_socket_smtp(self) -> None:
        """Start a simple socket-based SMTP server (fallback)."""
        import socket

        try:
            self._socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket_server.settimeout(1.0)
            self._socket_server.bind((self.bind_address, self.port))
            self._socket_server.listen(5)
        except OSError as e:
            logger.error("Failed to bind SMTP server: %s", e)
            return

        self._thread = threading.Thread(target=self._serve_socket, daemon=True)
        self._thread.start()
        logger.info("Fake SMTP server started on %s:%d (socket fallback)", self.bind_address, self.port)

    def _serve_socket(self) -> None:
        """Simple SMTP server loop using raw sockets."""
        import socket

        while self._running:
            try:
                conn, addr = self._socket_server.accept()
                handler_thread = threading.Thread(
                    target=self._handle_smtp_connection,
                    args=(conn, addr[0]),
                    daemon=True,
                )
                handler_thread.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_smtp_connection(self, conn: "socket.socket", client_ip: str) -> None:
        """Handle a single SMTP connection with minimal protocol compliance.

        Args:
            conn: TCP connection.
            client_ip: Client IP address.
        """
        import re

        session = SMTPSessionLog(
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=client_ip,
        )
        data_buffer = []
        in_data_mode = False
        sender = ""
        recipients: list[str] = []

        try:
            conn.sendall(b"220 hatchery-smtp ESMTP Postfix\r\n")

            while True:
                try:
                    raw = conn.recv(4096)
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    break

                if in_data_mode:
                    if line == ".":
                        in_data_mode = False
                        session.sender = sender
                        session.recipients = recipients
                        session.raw_data = "\n".join(data_buffer)

                        # Parse subject from raw data
                        for data_line in data_buffer:
                            if data_line.lower().startswith("subject:"):
                                session.subject = data_line[8:].strip()

                        self.session_log.append(session)
                        conn.sendall(b"250 OK\r\n")
                    else:
                        data_buffer.append(line)
                elif line.upper().startswith("EHLO") or line.upper().startswith("HELO"):
                    conn.sendall(b"250-hatchery-smtp\r\n250 OK\r\n")
                elif line.upper().startswith("MAIL FROM:"):
                    sender = line[10:].strip().strip("<>")
                    conn.sendall(b"250 OK\r\n")
                elif line.upper().startswith("RCPT TO:"):
                    rcpt = line[8:].strip().strip("<>")
                    recipients.append(rcpt)
                    conn.sendall(b"250 OK\r\n")
                elif line.upper() == "DATA":
                    in_data_mode = True
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                elif line.upper() == "QUIT":
                    conn.sendall(b"221 Bye\r\n")
                    break
                elif line.upper() == "RSET":
                    sender = ""
                    recipients = []
                    conn.sendall(b"250 OK\r\n")
                else:
                    conn.sendall(b"250 OK\r\n")

        except Exception as e:
            logger.debug("SMTP connection error: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stop the fake SMTP server."""
        self._running = False
        if self._controller:
            self._controller.stop()
            self._controller = None
        if self._socket_server:
            self._socket_server.close()
            self._socket_server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Fake SMTP server stopped (%d sessions logged)", len(self.session_log))

    def get_sessions(self) -> list[dict]:
        """Get all logged SMTP sessions as dicts."""
        return [s.to_dict() for s in self.session_log]

    def get_recipients(self) -> list[str]:
        """Get unique recipient addresses."""
        seen: set[str] = set()
        result: list[str] = []
        for s in self.session_log:
            for r in s.recipients:
                if r not in seen:
                    seen.add(r)
                    result.append(r)
        return result