"""Fake internet services — simulate network environment for malware detonation.

When malware detects it can't reach the internet, it often exits or
refuses to detonate. These fake services simulate a real network:
- DNS (port 53): Resolves everything to our sinkhole
- HTTP (port 80/443): Returns generic responses to trick C2 check-ins
- SMTP (port 25): Accepts and logs all mail
- Service manager: Orchestrates all fakes

Based on INetSim's approach — make malware think it's on a real network.
"""

from engine.fake_services.dns_server import FakeDNSServer
from engine.fake_services.http_server import FakeHTTPServer
from engine.fake_services.smtp_server import FakeSMTPServer
from engine.fake_services.service_manager import FakeServiceManager

__all__ = [
    "FakeDNSServer",
    "FakeHTTPServer",
    "FakeSMTPServer",
    "FakeServiceManager",
]