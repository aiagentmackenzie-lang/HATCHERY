"""Docker container sandbox — isolate and detonate malware samples.

Manages the full container lifecycle: create isolated container,
execute the sample with strace attached, timeout and kill, then
capture artifacts for analysis.
"""

from engine.sandbox.container import ContainerManager
from engine.sandbox.network import NetworkIsolator

__all__ = ["ContainerManager", "NetworkIsolator"]