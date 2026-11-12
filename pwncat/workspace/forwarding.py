"""Live TCP forwards over the authenticated workspace SSH connection."""

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


@dataclass(frozen=True)
class ReverseForwardStatus:
    remote_port: int
    local_port: int
    bind_ip: str
    running: bool
    connections: int
    error: str | None

    @property
    def remote_endpoint(self):
        host = f"[{self.bind_ip}]" if ":" in self.bind_ip else self.bind_ip
        return f"{host}:{self.remote_port}"


class ReverseForward:
    """SSH server listener whose incoming channels reach local loopback."""

    def __init__(self, transport, remote_port, local_port, bind_ip):
        self.transport = transport
        self.remote_port, self.local_port = remote_port, local_port
        self.bind_ip = bind_ip
        self.stopped = threading.Event()
        self.lock = threading.RLock()
        self.peers, self.channels = set(), set()
        self.error = None

    def start(self, handler):
        try:
            assigned = self.transport.request_port_forward(
                self.bind_ip, self.remote_port, handler=handler
            )
        except (OSError, EOFError, paramiko.SSHException) as exc:
            raise WorkspaceError(
                "SSH server refused the reverse listener or its port is unavailable: "
                + str(exc)
            ) from exc
        if assigned != self.remote_port:
            try:
                self.transport.cancel_port_forward(self.bind_ip, assigned)
            except (OSError, EOFError, paramiko.SSHException):
                pass
            self.stopped.set()
            raise WorkspaceError("SSH server assigned a different remote port.")

    def status(self):
        with self.lock:
            return ReverseForwardStatus(
                self.remote_port,
                self.local_port,
                self.bind_ip,
                not self.stopped.is_set() and self.transport.is_active(),
                len(self.channels),
                self.error,
            )

    def _incoming(self, channel, _origin, _server):
        with self.lock:
            if self.stopped.is_set() or len(self.channels) >= 16:
                close_stream(channel)
                self.error = "Connection limit reached or forward stopped."
                return
            self.channels.add(channel)
        threading.Thread(
            target=self._handle,
            args=(channel,),
            name="workspace-reverse-forward-client",
            daemon=True,
        ).start()

    def _handle(self, channel):
        peer = None
        try:
            peer = socket.create_connection((LOOPBACK, self.local_port), timeout=3)
            with self.lock:
                if self.stopped.is_set():
                    return
                self.peers.add(peer)
            relay(peer, channel, self.stopped)
        except (OSError, EOFError, ValueError, paramiko.SSHException):
            if not self.stopped.is_set():
                with self.lock:
                    self.error = "A connection failed; check the local listener and SSH connection."
        finally:
            if peer is not None:
                close_stream(peer)
            close_stream(channel)
            with self.lock:
                self.peers.discard(peer)
                self.channels.discard(channel)

    def stop(self):
        if self.stopped.is_set():
            return
        self.stopped.set()
        try:
            if self.transport.is_active():
                self.transport.cancel_port_forward(self.bind_ip, self.remote_port)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        with self.lock:
            streams = list(self.peers) + list(self.channels)
        for stream in streams:
            close_stream(stream)


class ReverseForwards:
    """Reverse forwards belong only to the current SSH transport."""

    def __init__(self, transport):
        self.transport = transport
        self.entries = {}
        self.lock = threading.RLock()

    def _incoming(self, channel, origin, server):
        with self.lock:
            entry = self.entries.get(server[1])
            if entry is None or not entry.status().running:
                close_stream(channel)
                return
        entry._incoming(channel, origin, server)

    def add(self, remote_port, local_port, *, bind_ip=LOOPBACK):
        remote_port, local_port = port_number(remote_port), port_number(local_port)
        address = destination_address(bind_ip)
        if str(address) not in (LOOPBACK, "0.0.0.0"):
            raise WorkspaceError("Reverse bind IP must be 127.0.0.1 or 0.0.0.0.")
        bind_ip = str(address)
        if not self.transport.is_active():
            raise WorkspaceError("SSH is disconnected; no reverse forward was started.")
        with self.lock:
            existing = self.entries.get(remote_port)
            if existing and existing.status().running:
                raise WorkspaceError("That remote port already has a reverse forward. Stop it first.")
            if sum(entry.status().running for entry in self.entries.values()) >= 8:
                raise WorkspaceError("At most eight reverse forwards can run per SSH connection.")
            if existing:
                existing.stop()
            forward = ReverseForward(self.transport, remote_port, local_port, bind_ip)
            self.entries[remote_port] = forward
            try:
                # paramiko-ng has one handler per transport, so every request
                # must install the same dispatcher for all forwarded ports.
                forward.start(self._incoming)
            except Exception:
                self.entries.pop(remote_port, None)
                if self.entries and self.transport.is_active():
                    self.transport._tcp_handler = self._incoming
                raise
            return forward.status()

    def list(self):
        with self.lock:
            return [entry.status() for _, entry in sorted(self.entries.items())]

    def stop(self, remote_port):
        remote_port = port_number(remote_port)
        with self.lock:
            entry = self.entries.pop(remote_port, None)
            if entry is None:
                raise WorkspaceError("No reverse forward uses that remote port in this connection.")
            entry.stop()
            if self.entries and self.transport.is_active():
                # cancel_port_forward clears paramiko-ng's transport-wide handler.
                self.transport._tcp_handler = self._incoming

    def close(self):
        with self.lock:
            entries, self.entries = list(self.entries.values()), {}
            for entry in entries:
                entry.stop()
