"""
Agent runtime configuration. Values can be overridden via CLI args or env vars.
"""
from __future__ import annotations

import os
import platform
import socket
import uuid


class AgentConfig:
    def __init__(
        self,
        server_url: str | None = None,
        api_key: str | None = None,
        output_path: str | None = None,
        target_level: int = 3,
        machine_label: str | None = None,
    ):
        self.server_url: str | None = server_url or os.environ.get("E8_SERVER_URL")
        self.api_key: str | None = api_key or os.environ.get("E8_API_KEY")
        self.output_path: str | None = output_path
        self.target_level: int = target_level
        self.machine_id: str = self._stable_machine_id()
        self.machine_label: str = machine_label or socket.gethostname()
        self.os_name: str = platform.system()          # "Windows" | "Linux" | "Darwin"
        self.os_version: str = platform.version()
        self.os_release: str = platform.release()
        self.fqdn: str = socket.getfqdn()

    @staticmethod
    def _stable_machine_id() -> str:
        """Return a stable machine identifier (hostname-based UUID)."""
        hostname = socket.gethostname()
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, hostname))

    def push_mode(self) -> bool:
        return self.server_url is not None

    def standalone_mode(self) -> bool:
        return self.output_path is not None

    def machine_info(self) -> dict:
        return {
            "machine_id": self.machine_id,
            "machine_label": self.machine_label,
            "fqdn": self.fqdn,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_release": self.os_release,
        }
