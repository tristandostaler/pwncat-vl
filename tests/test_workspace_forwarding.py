"""Local-only forwarding over disposable SSH, including lifecycle and half-closes."""

import socket
import socketserver
import threading
import time
from unittest.mock import Mock

import paramiko
import pytest

from pwncat.workspace import WorkspaceError
from pwncat.workspace.console import ConsoleState, WorkspaceConsole
from pwncat.workspace.forwarding import (
    ForwardStatus,
    LocalForwards,
    destination_address,
    port_number,
)
from pwncat.workspace.ssh import SSHConnection, SSHProfile


def wait_until(predicate):
    deadline = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(0.02)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def receive_all(stream):
    chunks = []
    while True:
        data = stream.recv(16384)
        if not data:
            return b"".join(chunks)
        chunks.append(data)


class ReplyAfterEOF(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            data = receive_all(self.request)
            self.request.sendall(b"reply:" + data)
        except OSError:
            pass


class Policy(paramiko.ServerInterface):
    def __init__(self, server):
        self.server = server
        self.destinations = {}

    def check_auth_publickey(self, username, key):
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "test" and key == self.server.key
            else paramiko.AUTH_FAILED
        )

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        self.server.requests.append(destination)
        if self.server.deny or destination != ("127.0.0.1", self.server.service_port):
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        self.destinations[chanid] = destination
        return paramiko.OPEN_SUCCEEDED


class SSHServer:
    def __init__(self, key, service_port):
        self.key, self.service_port = key, service_port
        self.deny = False
        self.requests, self.transports = [], []
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(5)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                peer, _ = self.listener.accept()
            except socket.timeout:  # noqa: UP041 - Python 3.9 compatibility
                continue
            except OSError:
                return
            transport = paramiko.Transport(peer)
            self.transports.append(transport)
            transport.add_server_key(self.key)
            policy = Policy(self)
            try:
                transport.start_server(server=policy)
            except (EOFError, paramiko.SSHException):
                transport.close()
                continue
            threading.Thread(
                target=self.channels, args=(transport, policy), daemon=True
            ).start()

    def channels(self, transport, policy):
        while transport.is_active() and not self.stopped.is_set():
            channel = transport.accept(0.1)
            if channel is not None:
                threading.Thread(
                    target=self.handle,
                    args=(channel, policy.destinations.pop(channel.get_id(), None)),
                    daemon=True,
                ).start()

    @staticmethod
    def pump(source, destination):
        try:
            while True:
                data = source.recv(16384)
                if not data:
                    if isinstance(destination, paramiko.Channel):
                        destination.shutdown_write()
                    else:
                        destination.shutdown(socket.SHUT_WR)
                    return
                destination.sendall(data)
        except (OSError, EOFError):
            pass

    def handle(self, channel, destination):
        peer = None
        channel.settimeout(5)
        try:
            if destination is None:
                while True:
                    data = channel.recv(16384)
                    if not data:
                        return
                    channel.sendall(data)
            else:
                peer = socket.create_connection(destination, timeout=5)
                upload = threading.Thread(
                    target=self.pump, args=(channel, peer), daemon=True
                )
                upload.start()
                self.pump(peer, channel)
                upload.join(timeout=1)
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            channel.close()
            if peer:
                peer.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=1)


@pytest.fixture(scope="module")
def ssh_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def host(tmp_path, ssh_key):
    service = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ReplyAfterEOF)
    service.daemon_threads = True
    thread = threading.Thread(
        target=service.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    )
    thread.start()
    server = SSHServer(ssh_key, service.server_address[1])
    identity, known_hosts = tmp_path / "identity", tmp_path / "known_hosts"
    ssh_key.write_private_key_file(str(identity))
    identity.chmod(0o600)
    known_hosts.write_text(
        f"[127.0.0.1]:{server.port} {ssh_key.get_name()} {ssh_key.get_base64()}\n"
    )
    connection = SSHConnection(
        SSHProfile("127.0.0.1", "test", server.port, str(identity), str(known_hosts))
    )
    try:
        connection.connect()
        yield server, connection
    finally:
        connection.close()
        server.close()
        service.shutdown()
        service.server_close()
        thread.join(timeout=1)


@pytest.mark.parametrize(
    "value", [0, -1, 65536, True, "22.0", "host:80", "", " 80", "٨٠"]
)
def test_port_validation_rejects_destinations_and_invalid_numbers(value):
    with pytest.raises(WorkspaceError, match="Ports"):
        port_number(value)


@pytest.mark.parametrize("explicit_ip", [False, True])
def test_live_console_forward_preserves_ssh_session_and_half_closes(
    host, capsys, explicit_ip
):
    server, connection = host
    transport = connection.client.get_transport()
    control = transport.open_session()
    control.settimeout(5)
    backend = Mock()
    backend.connection = connection
    backend.pane.return_value.id = "%0"
    console = WorkspaceConsole(backend, ConsoleState(selected="%0"))
    local_port = free_port()
    destination = "127.0.0.1 " if explicit_ip else ""
    console.execute(f"forward add {local_port} {destination}{server.service_port}")
    assert console.execute("resume") == "resume"
    assert connection.client.get_transport() is transport
    payload = bytes(range(256)) * 2048
    with socket.create_connection(("127.0.0.1", local_port), timeout=5) as peer:
        peer.sendall(payload)
        peer.shutdown(socket.SHUT_WR)
        assert receive_all(peer) == b"reply:" + payload
    assert server.requests == [("127.0.0.1", server.service_port)]
    assert connection.local_forwards().list()[0].destination_ip == "127.0.0.1"
    console.execute("forward list")
    assert f"127.0.0.1:{local_port}" in capsys.readouterr().out
    console.execute(f"forward stop {local_port}")
    assert connection.local_forwards().list() == []
    control.sendall(b"same-session")
    assert control.recv(100) == b"same-session"
    assert connection.active()
    control.close()


@pytest.mark.parametrize(
    "value",
    [
        "example.com",
        "http://192.0.2.20",
        "192.0.2.20:80",
        "192.0.2.999",
        "2130706433",
        "fe80::1%eth0",
        "",
        123,
        None,
    ],
)
def test_destination_must_be_a_literal_ip(value):
    with pytest.raises(WorkspaceError, match="literal IPv4 or IPv6"):
        destination_address(value)


@pytest.mark.parametrize(
    "peer, destination, expected",
    [
        ("192.0.2.20", "192.0.2.20", "192.0.2.20"),
        ("192.0.2.20", "::ffff:192.0.2.20", "192.0.2.20"),
        ("::ffff:192.0.2.20", "192.0.2.20", "192.0.2.20"),
        ("2001:db8::20", "2001:0DB8:0:0:0:0:0:20", "2001:db8::20"),
        ("192.0.2.20", "127.0.0.1", "127.0.0.1"),
        ("192.0.2.20", "::1", "::1"),
    ],
)
def test_destination_is_matched_to_pinned_ssh_peer(peer, destination, expected):
    transport = Mock()
    transport.getpeername.return_value = (peer, 22)
    manager = LocalForwards(transport)
    # A later DNS change or another connection cannot change this manager's peer.
    transport.getpeername.return_value = ("203.0.113.40", 22)
    assert manager.validate_destination(destination) == expected
    with pytest.raises(WorkspaceError, match="connected SSH server IP"):
        manager.validate_destination("203.0.113.40")
    transport.getpeername.assert_called_once()


def test_rejected_destination_creates_no_listener_or_ssh_channel(monkeypatch):
    transport = Mock()
    transport.getpeername.return_value = ("192.0.2.20", 22)
    listener = Mock()
    monkeypatch.setattr("pwncat.workspace.forwarding.LocalForward", listener)
    manager = LocalForwards(transport)
    with pytest.raises(WorkspaceError, match="192.0.2.20"):
        manager.add(8080, 80, destination_ip="203.0.113.40")
    listener.assert_not_called()
    transport.open_channel.assert_not_called()
    assert manager.list() == []


def test_unavailable_peer_information_preserves_only_loopback_destinations():
    transport = Mock()
    transport.getpeername.side_effect = OSError("socket closed")
    manager = LocalForwards(transport)
    assert manager.validate_destination("127.0.0.1") == "127.0.0.1"
    with pytest.raises(WorkspaceError, match="loopback"):
        manager.validate_destination("192.0.2.20")


def test_console_passes_server_ip_to_channel_and_displays_it(capsys):
    transport = Mock()
    transport.getpeername.return_value = ("192.0.2.20", 22)
    # Record the request without ever contacting the documentation-only IP.
    transport.open_channel.side_effect = paramiko.ChannelException(1, "test denial")
    manager = LocalForwards(transport)
    backend = Mock()
    backend.connection.local_forwards.return_value = manager
    console = WorkspaceConsole(backend)
    local_port = free_port()
    try:
        console.execute(f"forward add {local_port} 192.0.2.20 80")
        with socket.create_connection(("127.0.0.1", local_port), timeout=5) as peer:
            assert peer.recv(1) == b""
        assert transport.open_channel.call_args.args[:2] == (
            "direct-tcpip",
            ("192.0.2.20", 80),
        )
        assert manager.list()[0].destination_ip == "192.0.2.20"
        console.execute("forward list")
        assert "SSH host 192.0.2.20:80" in capsys.readouterr().out
    finally:
        manager.close()


def test_ipv6_destination_is_unambiguous_in_status():
    status = ForwardStatus(8080, 80, True, 0, None, "2001:db8::20")
    assert status.remote_endpoint == "[2001:db8::20]:80"


def test_busy_port_and_duplicate_forward_preserve_existing_listener(host):
    server, connection = host
    manager = connection.local_forwards()
    local_port = free_port()
    manager.add(local_port, server.service_port)
    with pytest.raises(WorkspaceError, match="already has a forward"):
        manager.add(local_port, 12345)
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        with pytest.raises(WorkspaceError, match="Cannot listen"):
            manager.add(occupied.getsockname()[1], server.service_port)
    assert len(manager.list()) == 1
    assert manager.list()[0].remote_port == server.service_port
    assert connection.active()


def test_stop_closes_active_clients_and_releases_port(host):
    server, connection = host
    manager = connection.local_forwards()
    local_port = free_port()
    manager.add(local_port, server.service_port)
    with socket.create_connection(("127.0.0.1", local_port), timeout=5) as peer:
        wait_until(lambda: manager.list()[0].connections == 1)
        manager.stop(local_port)
        assert peer.recv(1) == b""
    # Explicitly starting it again works on the same SSH connection.
    manager.add(local_port, server.service_port)
    assert manager.list()[0].running


def test_ssh_loss_closes_listener_and_reconnect_does_not_restore_it(host):
    server, connection = host
    manager = connection.local_forwards()
    local_port = free_port()
    manager.add(local_port, server.service_port)
    connection.client.get_transport().close()
    wait_until(lambda: not manager.list()[0].running)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", local_port), timeout=1)
    connection.connect()
    assert connection.local_forwards().list() == []
    assert server.requests == []


def test_ssh_policy_denial_reports_error_without_closing_session(host):
    server, connection = host
    server.deny = True
    manager = connection.local_forwards()
    local_port = free_port()
    manager.add(local_port, server.service_port)
    with socket.create_connection(("127.0.0.1", local_port), timeout=5) as peer:
        assert peer.recv(1) == b""
    wait_until(lambda: manager.list()[0].error is not None)
    assert "forwarding policy" in manager.list()[0].error
    assert connection.active()


def test_closing_owner_closes_forwards(host):
    server, connection = host
    manager = connection.local_forwards()
    local_port = free_port()
    manager.add(local_port, server.service_port)
    connection.close()
    assert manager.list() == []
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", local_port), timeout=1)


@pytest.fixture
def persistent_console(host, tmp_path, monkeypatch):
    from pwncat.workspace.model import WorkspaceRef
    from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
    from pwncat.workspace.saved_forwards import SavedForwards

    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    _server, connection = host
    store = ProfileStore()
    ref = WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket")
    store.save(SavedWorkspace("lab", connection.profile, False, False, ref))
    settings = SavedForwards(store, "lab", connection.profile, ref)
    backend = Mock()
    backend.connection = connection
    console = WorkspaceConsole(backend, ConsoleState(forward_settings=settings))
    return console, settings, store


def test_saved_forward_reopens_on_fresh_connection_and_stop_removes_it(
    host, persistent_console
):
    server, connection = host
    console, settings, store = persistent_console
    local_port = free_port()
    console.execute(f"forward add {local_port} {server.service_port}")
    assert store.get("lab").forwards[0].local_port == local_port
    connection.close()
    connection.connect()
    manager = connection.local_forwards()
    assert "Restored forward" in settings.restore(manager)[0]
    with socket.create_connection(("127.0.0.1", local_port), timeout=5) as peer:
        peer.sendall(b"fresh request")
        peer.shutdown(socket.SHUT_WR)
        assert receive_all(peer) == b"reply:fresh request"
    assert server.requests == [("127.0.0.1", server.service_port)]
    console.execute(f"forward stop {local_port}")
    assert store.get("lab").forwards == ()
    connection.close()
    connection.connect()
    assert settings.restore(connection.local_forwards()) == []
    assert connection.local_forwards().list() == []


def test_restore_busy_listener_is_retained_and_can_be_removed(
    host, persistent_console, capsys
):
    server, connection = host
    console, settings, store = persistent_console
    local_port = free_port()
    console.execute(f"forward add {local_port} {server.service_port}")
    connection.close()
    connection.connect()
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", local_port))
        occupied.listen(1)
        assert "not restored" in settings.restore(connection.local_forwards())[0]
        console.execute("forward list")
        output = capsys.readouterr().out
        assert "stopped" in output and "saved" in output
        assert len(store.get("lab").forwards) == 1
        console.execute(f"forward stop {local_port}")
        assert store.get("lab").forwards == ()
        assert occupied.getsockname()[1] == local_port


def test_failed_rule_save_rolls_back_new_listener(
    host, persistent_console, monkeypatch
):
    server, connection = host
    console, _settings, store = persistent_console
    monkeypatch.setattr(
        "pwncat.workspace.profiles.os.replace", Mock(side_effect=OSError("disk full"))
    )
    local_port = free_port()
    with pytest.raises(WorkspaceError, match="new listener was stopped"):
        console.execute(f"forward add {local_port} {server.service_port}")
    assert connection.local_forwards().list() == []
    assert store.get("lab").forwards == ()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", local_port), timeout=1)
