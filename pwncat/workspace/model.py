"""Validated identifiers and immutable observations."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from . import WorkspaceError


def workspace_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", value):
        raise WorkspaceError(
            "Workspace names must be 1–32 letters, digits, '-' or '_'."
        )
    return value


def pane_id(value: str) -> str:
    if not re.fullmatch(r"%[0-9]+", value):
        raise WorkspaceError("Use a pane ID such as %0 (see 'panes').")
    return value


def safe_text(value: object) -> str:
    """Do not let metadata or exception messages control the local terminal."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(value))


@dataclass(frozen=True)
class WorkspaceRef:
    name: str
    uuid: str
    server_epoch: str
    socket_path: str


@dataclass(frozen=True)
class ForwardRule:
    local_port: int
    remote_port: int
    destination_ip: str

    def __post_init__(self):
        if any(
            type(port) is not int or not 1 <= port <= 65535
            for port in (self.local_port, self.remote_port)
        ):
            raise WorkspaceError(
                "Saved forward ports must be integers between 1 and 65535."
            )
        try:
            if not isinstance(self.destination_ip, str) or "%" in self.destination_ip:
                raise ValueError
            address = ipaddress.ip_address(self.destination_ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            object.__setattr__(self, "destination_ip", str(address))
        except ValueError:
            raise WorkspaceError(
                "A saved forward requires a literal destination IP."
            ) from None


@dataclass(frozen=True)
class ReverseForwardRule:
    remote_port: int
    local_port: int
    bind_ip: str = "127.0.0.1"

    def __post_init__(self):
        if any(type(port) is not int or not 1 <= port <= 65535 for port in (self.remote_port, self.local_port)):
            raise WorkspaceError("Saved reverse forward ports must be between 1 and 65535.")
        if self.bind_ip not in ("127.0.0.1", "0.0.0.0"):
            raise WorkspaceError("Saved reverse bind IP must be 127.0.0.1 or 0.0.0.0.")


@dataclass(frozen=True)
class ListenerRule:
    host: str
    port: int
    platform: str | None = None
    count: int | None = None
    ssl: bool = False
    ssl_cert: str | None = None
    ssl_key: str | None = None
    drop_duplicate: bool = False

    def __post_init__(self):
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise WorkspaceError("Saved listener port must be between 1 and 65535.")
        try:
            if not isinstance(self.host, str) or not self.host or any(ord(c) < 32 for c in self.host):
                raise ValueError
            try:
                ipaddress.ip_address(self.host)
            except ValueError:
                if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", self.host):
                    raise
        except ValueError:
            raise WorkspaceError("Invalid saved listener host.") from None
        if self.platform is not None and (not isinstance(self.platform, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.platform)):
            raise WorkspaceError("Invalid saved listener platform.")
        if self.count is not None and (type(self.count) is not int or self.count < 1):
            raise WorkspaceError("Saved listener count must be positive.")
        if type(self.ssl) is not bool or type(self.drop_duplicate) is not bool:
            raise WorkspaceError("Invalid saved listener options.")
        if (self.ssl_cert is not None or self.ssl_key is not None) and not self.ssl:
            raise WorkspaceError("Saved listener SSL paths require SSL.")
        for path in (self.ssl_cert, self.ssl_key):
            if path is not None and (not isinstance(path, str) or not path.startswith("/") or any(ord(c) < 32 for c in path)):
                raise WorkspaceError("Saved listener SSL paths must be absolute.")


@dataclass(frozen=True)
class Pane:
    id: str
    pid: int
    width: int
    height: int
    active: bool
    dead: bool
    directory: str
    window_id: str = ""
