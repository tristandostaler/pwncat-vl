"""Restore local service listeners after validating the workspace and SSH peer."""

from __future__ import annotations

import ipaddress

from . import WorkspaceError
from .forwarding import ForwardStatus
from .model import ForwardRule, safe_text


class SavedForwards:
    def __init__(self, store, alias, connection, ref):
        self.store, self.alias = store, alias
        self.connection, self.ref = connection, ref
        self.failures = {}

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
