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
class Pane:
    id: str
    pid: int
    width: int
    height: int
    active: bool
    dead: bool
    directory: str
    window_id: str = ""
