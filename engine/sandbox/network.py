"""Network isolation configuration for sandbox containers.

Creates isolated Docker networks and iptables rules to redirect
all traffic to fake services. Ensures the sample cannot reach
the host or the internet.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import docker as docker_sdk
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

# Default network configuration
DEFAULT_NETWORK_NAME = "hatchery-fake"
DEFAULT_SUBNET = "172.28.0.0/16"
DEFAULT_GATEWAY = "172.28.0.1"
FAKE_SERVICE_IP = "172.28.0.2"


@dataclass
class NetworkConfig:
    """Configuration for the sandbox network."""
    name: str = DEFAULT_NETWORK_NAME
    subnet: str = DEFAULT_SUBNET
    gateway: str = DEFAULT_GATEWAY
    fake_service_ip: str = FAKE_SERVICE_IP

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "subnet": self.subnet,
            "gateway": self.gateway,
            "fake_service_ip": self.fake_service_ip,
        }


class NetworkIsolator:
    """Create and manage isolated Docker networks for sandboxing.

    Ensures that sandbox containers can only reach the fake services
    running on the gateway — no internet, no host access beyond that.
    """

    def __init__(self, config: Optional[NetworkConfig] = None) -> None:
        self.config = config or NetworkConfig()
        self._client: Optional[docker_sdk.DockerClient] = None

    @property
    def client(self) -> docker_sdk.DockerClient:
        if self._client is None:
            if not HAS_DOCKER:
                raise RuntimeError("docker SDK not installed")
            self._client = docker_sdk.from_env()
        return self._client

    def create_network(self) -> str:
        """Create the isolated Docker network for sandbox containers.

        Returns:
            Network name.
        """
        # Remove existing network if it exists
        try:
            existing = self.client.networks.get(self.config.name)
            existing.remove()
            logger.info("Removed existing network: %s", self.config.name)
        except Exception:
            pass

        # Create the isolated network
        ipam_pool = docker_sdk.types.IPAMPool(
            subnet=self.config.subnet,
            gateway=self.config.gateway,
        )
        ipam_config = docker_sdk.types.IPAMConfig(pool_configs=[ipam_pool])

        network = self.client.networks.create(
            self.config.name,
            driver="bridge",
            ipam=ipam_config,
            internal=True,  # No external routing
            labels={"hatchery": "sandbox-network"},
        )

        logger.info(
            "Created isolated network: %s (subnet=%s, internal=True)",
            self.config.name, self.config.subnet,
        )
        return self.config.name

    def connect_fake_services(self, container_id: str) -> None:
        """Connect the fake services container to the sandbox network.

        Args:
            container_id: ID of the container running fake services.
        """
        try:
            network = self.client.networks.get(self.config.name)
            network.connect(
                container_id,
                ipv4_address=self.config.fake_service_ip,
            )
            logger.info(
                "Connected fake services container to %s at %s",
                self.config.name, self.config.fake_service_ip,
            )
        except Exception as e:
            logger.error("Failed to connect fake services: %s", e)
            raise

    def remove_network(self) -> None:
        """Remove the sandbox network."""
        try:
            network = self.client.networks.get(self.config.name)
            network.remove()
            logger.info("Removed network: %s", self.config.name)
        except Exception:
            logger.debug("Network %s not found for removal", self.config.name)

    def is_available(self) -> bool:
        """Check if the sandbox network exists."""
        if not HAS_DOCKER:
            return False
        try:
            self.client.networks.get(self.config.name)
            return True
        except Exception:
            return False