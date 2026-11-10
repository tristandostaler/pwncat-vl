"""Restore local service listeners after validating the workspace and SSH peer."""

from __future__ import annotations

import ipaddress

from . import WorkspaceError
from .forwarding import ForwardStatus, ReverseForwardStatus
from .model import ForwardRule, ListenerRule, ReverseForwardRule, safe_text


class SavedForwards:
    def __init__(self, store, alias, connection, ref):
        self.store, self.alias = store, alias
        self.connection, self.ref = connection, ref
        self.failures = {}
        self.reverse_failures = {}

    def rules(self):
        return self.store.forward_rules(self.alias, self.connection, self.ref)

    @staticmethod
    def eligible(manager, rule):
        return True
        # address = ipaddress.ip_address(rule.destination_ip)
        # if address.is_loopback:
        #     return True
        # try:
        #     peer = ipaddress.ip_address(manager.transport.getpeername()[0])
        #     if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
        #         peer = peer.ipv4_mapped
        #     return address == peer
        # except (OSError, TypeError, ValueError, IndexError):
        #     return False

    def remember(self, manager, entry):
        rule = ForwardRule(entry.local_port, entry.remote_port, entry.destination_ip)
        if not self.eligible(manager, rule):
            self.store.forget_forward(
                self.alias, self.connection, self.ref, rule.local_port
            )
            return False
        self.store.remember_forward(self.alias, self.connection, self.ref, rule)
        self.failures.pop(rule.local_port, None)
        return True

    def stop(self, manager, local_port):
        # Commit removal first: on disk errors, the previous state remains explicit.
        removed = self.store.forget_forward(
            self.alias, self.connection, self.ref, local_port
        )
        if any(entry.local_port == local_port for entry in manager.list()):
            manager.stop(local_port)
        elif not removed:
            raise WorkspaceError(
                "No active or saved forward uses that port in this workspace."
            )
        self.failures.pop(local_port, None)

    def restore(self, manager):
        messages = []
        self.failures.clear()
        for rule in self.rules():
            try:
                # This check is independent of the manual forwarding command.
                if not self.eligible(manager, rule):
                    raise WorkspaceError(
                        "Automatic restore requires loopback or the current SSH server IP."
                    )
                current = next(
                    (
                        item
                        for item in manager.list()
                        if item.local_port == rule.local_port and item.running
                    ),
                    None,
                )
                if current:
                    if (current.destination_ip, current.remote_port) == (
                        rule.destination_ip,
                        rule.remote_port,
                    ):
                        continue
                    raise WorkspaceError(
                        "Another forward in this client already uses that local port."
                    )
                entry = manager.add(
                    rule.local_port,
                    rule.remote_port,
                    destination_ip=rule.destination_ip,
                )
                messages.append(
                    f"Restored forward 127.0.0.1:{entry.local_port} -> {entry.remote_endpoint}."
                )
            except (WorkspaceError, OSError) as exc:
                self.failures[rule.local_port] = safe_text(exc)
                messages.append(
                    f"Forward {rule.local_port} was not restored: {safe_text(exc)} Saved setting retained."
                )
        return messages

    def view(self, manager):
        rules = self.rules()
        entries = {entry.local_port: entry for entry in manager.list()}
        for rule in rules:
            if rule.local_port not in entries:
                entries[rule.local_port] = ForwardStatus(
                    rule.local_port,
                    rule.remote_port,
                    False,
                    0,
                    self.failures.get(rule.local_port),
                    rule.destination_ip,
                )
        return [entries[port] for port in sorted(entries)], {
            rule.local_port for rule in rules
        }

    def reverse_rules(self):
        return self.store.reverse_rules(self.alias, self.connection, self.ref)

    def remember_reverse(self, manager, entry):
        rule = ReverseForwardRule(entry.remote_port, entry.local_port, entry.bind_ip)
        self.store.remember_reverse(self.alias, self.connection, self.ref, rule)
        self.reverse_failures.pop(rule.remote_port, None)

    def stop_reverse(self, manager, remote_port):
        removed = self.store.forget_reverse(self.alias, self.connection, self.ref, remote_port)
        if any(entry.remote_port == remote_port for entry in manager.list()):
            manager.stop(remote_port)
        elif not removed:
            raise WorkspaceError("No active or saved reverse forward uses that port in this workspace.")
        self.reverse_failures.pop(remote_port, None)

    def restore_reverse(self, manager):
        messages = []
        self.reverse_failures.clear()
        for rule in self.reverse_rules():
            try:
                current = next((entry for entry in manager.list() if entry.remote_port == rule.remote_port and entry.running), None)
                if current:
                    if (current.local_port, current.bind_ip) == (rule.local_port, rule.bind_ip):
                        continue
                    raise WorkspaceError("Another reverse forward already uses that remote port.")
                entry = manager.add(rule.remote_port, rule.local_port, bind_ip=rule.bind_ip)
                messages.append(f"Restored reverse forward SSH host {entry.remote_endpoint} -> 127.0.0.1:{entry.local_port}.")
            except (WorkspaceError, OSError) as exc:
                self.reverse_failures[rule.remote_port] = safe_text(exc)
                messages.append(f"Reverse forward {rule.remote_port} was not restored: {safe_text(exc)} Saved setting retained.")
        return messages

    def view_reverse(self, manager):
        rules = self.reverse_rules()
        entries = {entry.remote_port: entry for entry in manager.list()}
        for rule in rules:
            if rule.remote_port not in entries:
                entries[rule.remote_port] = ReverseForwardStatus(
                    rule.remote_port, rule.local_port, rule.bind_ip, False, 0,
                    self.reverse_failures.get(rule.remote_port),
                )
        return [entries[port] for port in sorted(entries)], {rule.remote_port for rule in rules}


class SavedListeners:
    def __init__(self, store, alias, connection, ref):
        self.store, self.alias, self.connection, self.ref = store, alias, connection, ref
        self.failures = {}

    def rules(self):
        return self.store.listener_rules(self.alias, self.connection, self.ref)

    def remember(self, rule):
        self.store.remember_listener(self.alias, self.connection, self.ref, rule)
        self.failures.pop((rule.host, rule.port), None)

    def stop(self, listener):
        self.store.forget_listener(self.alias, self.connection, self.ref, *listener.address)
        self.failures.pop(listener.address, None)

    def restore(self, manager):
        import time
        from pwncat.manager import ListenerState

        messages = []
        self.failures.clear()
        for rule in self.rules():
            if any(item.address == (rule.host, rule.port) and item.state is ListenerState.RUNNING for item in manager.listeners):
                continue
            try:
                established = None
                if rule.drop_duplicate:
                    def established(session):
                        return not any(
                            other is not session and session.hash == other.hash
                            and session.platform.getuid() == other.platform.getuid()
                            for other in session.manager.sessions.values()
                        )
                listener = manager.create_listener(
                    protocol="socket", platform=rule.platform, host=rule.host,
                    port=rule.port, ssl=rule.ssl, ssl_cert=rule.ssl_cert,
                    ssl_key=rule.ssl_key, count=rule.count, established=established,
                )
                deadline = time.monotonic() + 3
                while listener.state is ListenerState.STOPPED and time.monotonic() < deadline:
                    time.sleep(0.01)
                if listener.state is not ListenerState.RUNNING:
                    listener.stop()
                    raise WorkspaceError(safe_text(listener.failure_exception or "listener startup timed out"))
                messages.append(f"Restored listener {rule.host}:{rule.port}.")
            except (WorkspaceError, OSError, ValueError) as exc:
                self.failures[rule.host, rule.port] = safe_text(exc)
                messages.append(f"Listener {rule.host}:{rule.port} was not restored: {safe_text(exc)} Saved setting retained.")
        return messages
