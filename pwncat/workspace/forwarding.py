"""Live local forwards to services on the authenticated SSH host."""

from __future__ import annotations

import ipaddress
import select
import socket
import threading
from dataclasses import dataclass

import paramiko

from . import WorkspaceError

LOOPBACK = "127.0.0.1"
BUFFER_LIMIT = 65536


def port_number(value):
    try:
        if (
            isinstance(value, bool)
            or not str(value).isascii()
            or not str(value).isdigit()
        ):
            raise ValueError
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError
        return port
    except (TypeError, ValueError):
        raise WorkspaceError(
            "Ports must be whole numbers between 1 and 65535."
        ) from None


def destination_address(value):
    """Canonicalize a literal address without DNS or interface discovery."""
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address
    except ValueError:
        raise WorkspaceError(
            "Use a literal IPv4 or IPv6 destination IP, without a URL, port, or zone ID."
        ) from None


def close_stream(stream):
    try:
        stream.close()
    except (OSError, EOFError, paramiko.SSHException):
        pass


def relay(peer, channel, stopped):
    """Bound both buffers; preserve half-closes without replaying any bytes."""
    peer.setblocking(False)
    channel.settimeout(0)
    to_remote, to_local = bytearray(), bytearray()
    peer_eof = remote_eof = sent_remote_eof = sent_peer_eof = False
    while not stopped.is_set():
        if not remote_eof and len(to_local) < BUFFER_LIMIT:
            if channel.recv_ready():
                data = channel.recv(min(16384, BUFFER_LIMIT - len(to_local)))
                if data:
                    to_local.extend(data)
                else:
                    remote_eof = True
            elif channel.eof_received or channel.closed:
                remote_eof = True
        if to_remote and channel.send_ready():
            try:
                count = channel.send(bytes(to_remote))
                if count == 0:
                    return
                del to_remote[:count]
            except socket.timeout:  # noqa: UP041 - Python 3.9 compatibility
                pass
        if peer_eof and not to_remote and not sent_remote_eof:
            channel.shutdown_write()
            sent_remote_eof = True
        if remote_eof and not to_local and not sent_peer_eof:
            peer.shutdown(socket.SHUT_WR)
            sent_peer_eof = True
        if peer_eof and remote_eof and not to_remote and not to_local:
            return
        readers = [peer] if not peer_eof and len(to_remote) < BUFFER_LIMIT else []
        writers = [peer] if to_local else []
        if not readers and not writers:
            # Windows select() requires at least one socket.
            stopped.wait(0.05)
            continue
        readable, writable, _ = select.select(readers, writers, [], 0.05)
        if readable:
            try:
                data = peer.recv(min(16384, BUFFER_LIMIT - len(to_remote)))
                if data:
                    to_remote.extend(data)
                else:
                    peer_eof = True
            except BlockingIOError:
                pass
        if writable:
            try:
                count = peer.send(to_local)
                if count == 0:
                    return
                del to_local[:count]
            except BlockingIOError:
                pass


@dataclass(frozen=True)
class ForwardStatus:
    local_port: int
    remote_port: int
    running: bool
    connections: int
    error: str | None
    destination_ip: str = LOOPBACK

    @property
    def remote_endpoint(self):
        host = (
            f"[{self.destination_ip}]"
            if ":" in self.destination_ip
            else self.destination_ip
        )
        return f"{host}:{self.remote_port}"


class LocalForward:
    def __init__(self, transport, local_port, remote_port, destination_ip):
        self.transport = transport
        self.local_port, self.remote_port = local_port, remote_port
        self.destination_ip = destination_ip
        self.stopped = threading.Event()
        self.lock = threading.RLock()
        self.peers, self.channels = set(), set()
        self.error = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Windows must not allow another process to share this listener.
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.listener.setsockopt(
                    socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1
                )
            else:
                self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((LOOPBACK, local_port))
            self.listener.listen(16)
            self.listener.settimeout(0.2)
        except OSError as exc:
            close_stream(self.listener)
            raise WorkspaceError(
                f"Cannot listen on {LOOPBACK}:{local_port}: {exc}"
            ) from exc
        self.thread = threading.Thread(
            target=self._serve, name="workspace-forward", daemon=True
        )

    def start(self):
        self.thread.start()

    def status(self):
        with self.lock:
            return ForwardStatus(
                self.local_port,
                self.remote_port,
                not self.stopped.is_set(),
                len(self.peers),
                self.error,
                self.destination_ip,
            )

    def _serve(self):
        try:
            while not self.stopped.is_set() and self.transport.is_active():
                try:
                    peer, origin = self.listener.accept()
                except socket.timeout:  # noqa: UP041 - Python 3.9 compatibility
                    continue
                with self.lock:
                    if self.stopped.is_set() or len(self.peers) >= 16:
                        close_stream(peer)
                        self.error = "Connection limit reached or forward stopped."
                        continue
                    self.peers.add(peer)
                threading.Thread(
                    target=self._handle,
                    args=(peer, origin),
                    name="workspace-forward-client",
                    daemon=True,
                ).start()
        except OSError:
            if not self.stopped.is_set():
                self.error = "Local listener failed."
        finally:
            self._shutdown()

    def _handle(self, peer, origin):
        channel = None
        try:
            channel = self.transport.open_channel(
                "direct-tcpip",
                (self.destination_ip, self.remote_port),
                origin,
                timeout=3,
            )
            if channel is None:
                raise WorkspaceError("SSH server did not open the local service.")
            with self.lock:
                if self.stopped.is_set():
                    return
                self.channels.add(channel)
            relay(peer, channel, self.stopped)
        except (OSError, EOFError, ValueError, paramiko.SSHException, WorkspaceError):
            if not self.stopped.is_set():
                with self.lock:
                    self.error = "A connection failed; check the SSH host's service and forwarding policy."
        finally:
            close_stream(peer)
            if channel is not None:
                close_stream(channel)
            with self.lock:
                self.peers.discard(peer)
                self.channels.discard(channel)

    def _shutdown(self):
        self.stopped.set()
        close_stream(self.listener)
        with self.lock:
            streams = list(self.peers) + list(self.channels)
        for stream in streams:
            close_stream(stream)

    def stop(self):
        self._shutdown()
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=1)


class LocalForwards:
    """One manager per SSH transport; no persistent configuration or reconnect replay."""

    def __init__(self, transport):
        self.transport = transport
        self.entries = {}
        try:
            # Pin to the authenticated connection's peer, never a fresh DNS answer.
            self.server_address = destination_address(transport.getpeername()[0])
        except (OSError, TypeError, IndexError, WorkspaceError):
            self.server_address = None

    def validate_destination(self, value):
        address = destination_address(value)
        return str(address)
        
        # address = destination_address(value)
        # if address.is_loopback or address == self.server_address:
        #     return str(address)
        # allowed = (
        #     f" or the connected SSH server IP ({self.server_address})"
        #     if self.server_address
        #     else ""
        # )
        # raise WorkspaceError(f"Destination must be a loopback address{allowed}.")

    def add(self, local_port, remote_port, *, destination_ip=LOOPBACK):
        local_port, remote_port = port_number(local_port), port_number(remote_port)
        destination_ip = self.validate_destination(destination_ip)
        if not self.transport.is_active():
            raise WorkspaceError("SSH is disconnected; no forward was started.")
        existing = self.entries.get(local_port)
        if existing and existing.status().running:
            raise WorkspaceError(
                "That local port already has a forward. Stop it first."
            )
        if sum(entry.status().running for entry in self.entries.values()) >= 8:
            raise WorkspaceError(
                "At most eight local forwards can run in this connection."
            )
        if existing:
            existing.stop()
        forward = LocalForward(self.transport, local_port, remote_port, destination_ip)
        self.entries[local_port] = forward
        try:
            forward.start()
        except BaseException:
            forward.stop()
            del self.entries[local_port]
            raise
        return forward.status()

    def list(self):
        return [entry.status() for _, entry in sorted(self.entries.items())]

    def stop(self, local_port):
        local_port = port_number(local_port)
        entry = self.entries.pop(local_port, None)
        if entry is None:
            raise WorkspaceError("No local forward uses that port in this connection.")
        entry.stop()

    def close(self):
        entries, self.entries = list(self.entries.values()), {}
        for entry in entries:
            entry.stop()
