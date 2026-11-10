"""Reusable helpers for modules that manage a live workspace."""

from __future__ import annotations

import time
from dataclasses import dataclass

from pwncat.modules import BaseModule, ModuleFailed
from pwncat.workspace import WorkspaceError
from pwncat.workspace.model import ListenerRule


@dataclass(frozen=True)
class ListenerConfig:
    host: str
    port: int
    platform: str
    protocol: str = "socket"
    ssl: bool = False


@dataclass(frozen=True)
class LocalForwardConfig:
    local_port: int
    destination_ip: str
    remote_port: int


@dataclass(frozen=True)
class ReverseForwardConfig:
    remote_port: int
    local_port: int
    bind_ip: str = "127.0.0.1"


class WorkspaceModule(BaseModule):
    """Base for custom modules that inspect and repair workspace state.

    Subclasses provide ``run``; this class contains no target-specific setup.
    """

    @staticmethod
    def workspace_context(session):
        manager = session.manager
        backend = getattr(manager, "workspace_backend", None)
        console = getattr(manager, "workspace_console", None)
        state = getattr(manager, "workspace_state", None)
        if backend is None or console is None or state is None:
            raise ModuleFailed("Run this module from a workspace console.")
        return manager, backend, console, state

    @staticmethod
    def remote(connection, argv, *, timeout=10, limit=2 * 1024 * 1024):
        try:
            return connection.execute(argv, timeout=timeout, limit=limit)
        except WorkspaceError as exc:
            raise ModuleFailed(str(exc)) from exc

    @staticmethod
    def capture(backend, pane, *, join_wrapped=False):
        args = ["capture-pane", "-p"]
        if join_wrapped:
            args.append("-J")
        rows = backend.request(*args, "-t", pane)
        return b"\n".join(rows).decode("utf-8", "replace").rstrip()

    @staticmethod
    def last_line(value):
        return next((line.strip() for line in reversed(value.splitlines()) if line.strip()), "")

    @staticmethod
    def set_window_option(backend, pane, name, value):
        backend.request("set-option", "-w", "-t", pane, name, value)

    def ensure_listener(self, manager, state, config: ListenerConfig):
        """Reuse a matching listener, or start and optionally save one."""
        from pwncat.manager import ListenerState

        def remember():
            # Saved listener rules currently restore plain socket listeners only.
            if (
                config.protocol == "socket"
                and not config.ssl
                and state.listener_settings is not None
            ):
                state.listener_settings.remember(
                    ListenerRule(config.host, config.port, config.platform)
                )

        for listener in manager.listeners:
            if listener.state is ListenerState.RUNNING and listener.address[1] == config.port:
                if (
                    listener.address != (config.host, config.port)
                    or listener.platform != config.platform
                    or listener.protocol != config.protocol
                    or listener.ssl != config.ssl
                ):
                    raise ModuleFailed(
                        f"Port {config.port} already has a different pwncat listener."
                    )
                remember()
                return False

        listener = manager.create_listener(
            protocol=config.protocol,
            host=config.host,
            port=config.port,
            platform=config.platform,
            ssl=config.ssl,
        )
        deadline = time.monotonic() + 3
        while listener.state is ListenerState.STOPPED and time.monotonic() < deadline:
            time.sleep(0.01)
        if listener.state is not ListenerState.RUNNING:
            listener.stop()
            raise ModuleFailed(f"Pwncat listener failed: {listener.failure_exception}")
        try:
            remember()
        except Exception:
            listener.stop()
            raise
        return True

    @staticmethod
    def ensure_local_forward(console, config: LocalForwardConfig):
        manager = console.backend.connection.local_forwards()
        current = next(
            (
                entry
                for entry in manager.list()
                if entry.local_port == config.local_port and entry.running
            ),
            None,
        )
        if current:
            if (current.destination_ip, current.remote_port) != (
                config.destination_ip,
                config.remote_port,
            ):
                raise ModuleFailed(f"Local port {config.local_port} has a different forward.")
            if console.state.forward_settings is not None:
                console.state.forward_settings.remember(manager, current)
            return False
        console.forward(
            [
                "add",
                str(config.local_port),
                config.destination_ip,
                str(config.remote_port),
            ]
        )
        return True

    @staticmethod
    def ensure_reverse_forward(console, config: ReverseForwardConfig):
        manager = console.backend.connection.reverse_forwards()
        current = next(
            (
                entry
                for entry in manager.list()
                if entry.remote_port == config.remote_port and entry.running
            ),
            None,
        )
        if current:
            if (current.local_port, current.bind_ip) != (config.local_port, config.bind_ip):
                raise ModuleFailed(f"Remote port {config.remote_port} has a different forward.")
            if console.state.forward_settings is not None:
                console.state.forward_settings.remember_reverse(manager, current)
            return False
        console.forward(
            [
                "reverse",
                "add",
                str(config.remote_port),
                str(config.local_port),
                config.bind_ip,
            ]
        )
        return True
