"""Real tmux plus disposable loopback SSH. Set PWNCAT_TEST_TMUX or install tmux."""

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from workspace_support import LoopbackSSH

from pwncat.workspace import IdentityMismatch, WorkspaceError
from pwncat.workspace.files import FileService
from pwncat.workspace.ssh import SSHConnection, SSHProfile
from pwncat.workspace.tmux import TmuxWorkspace


@pytest.fixture
def host(monkeypatch):
    tmux = os.environ.get("PWNCAT_TEST_TMUX") or shutil.which("tmux")
    version = (
        subprocess.run([tmux, "-V"], capture_output=True, text=True, check=True).stdout
        if tmux
        else ""
    )
    match = re.search(r"(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups())) < (3, 3):
        if os.environ.get("PWNCAT_REQUIRE_TMUX"):
            pytest.fail("Workspace CI requires real tmux 3.3+")
        pytest.skip("Real tmux required; set PWNCAT_TEST_TMUX")
    home = Path(tempfile.mkdtemp(prefix="pww-", dir="/tmp"))
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(home / "local-profiles"))
    monkeypatch.setenv("PWNCAT_WORKSPACE_SCREEN_DISABLE", "1")
    server = LoopbackSSH(home, tmux)
    profile = SSHProfile(
        "127.0.0.1", "test", server.port, server.identity, server.known_hosts
    )
    try:
        yield home, server, profile
    finally:
        for path in home.glob(".pwncat-workspaces/*/tmux.sock"):
            subprocess.run(
                [tmux, "-N", "-S", str(path), "kill-server"],
                check=False,
                capture_output=True,
                timeout=5,
            )
        server.close()
        shutil.rmtree(home)


def test_real_workspace_survives_disconnect_with_panes_and_history(host):
    home, _server, profile = host
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    ref = backend.create("demo", history="private")
    try:
        first = backend.panes()[0]
        second_id = backend.split(first.id)[0].decode()
        backend.request(
            "send-keys",
            "-t",
            first.id,
            "-l",
            "export WORKSPACE_TEST=one; cd /; printf 'FIRST_PANE\\n'",
        )
        backend.request("send-keys", "-t", first.id, "Enter")
        backend.request(
            "send-keys",
            "-t",
            second_id,
            "-l",
            "export WORKSPACE_TEST=two; printf 'SECOND_PANE\\n'",
        )
        backend.request("send-keys", "-t", second_id, "Enter")
        deadline = time.monotonic() + 5
        while True:
            panes = backend.panes()
            if next(p for p in panes if p.id == first.id).directory == "/":
                break
            assert time.monotonic() < deadline
            time.sleep(0.05)
        before = {p.id: p.pid for p in panes}
        time.sleep(1.1)  # Socket read timeouts must not kill an idle control client.
        assert {p.id: p.pid for p in backend.panes()} == before
        _server.transports[0].close()  # Abrupt transport loss, not orderly tmux detach.
        backend.close()
        connection.close()
        connection = SSHConnection(profile).connect()
        backend = TmuxWorkspace(connection)
        assert backend.load("demo", expected=ref) == ref
        assert {p.id: p.pid for p in backend.panes()} == before
        capture = b"\n".join(backend.request("capture-pane", "-p", "-t", first.id))
        assert b"FIRST_PANE" in capture
        history_files = list(home.glob(".pwncat-workspaces/demo/history/*.history"))
        assert len(history_files) == 2
        assert any("WORKSPACE_TEST=one" in p.read_text() for p in history_files)
        assert all(p.stat().st_mode & 0o077 == 0 for p in history_files)
        # SFTP never writes to the pane's input stream.
        source, remote, downloaded = (
            home / "source",
            home / "remote",
            home / "downloaded",
        )
        source.write_bytes(bytes(range(256)) * 1024)
        service = FileService(connection.filesystem())
        uploaded = service.upload(str(source), str(remote))
        assert service.download(str(remote), str(downloaded)) == uploaded
        assert downloaded.read_bytes() == source.read_bytes()
        assert {p.id: p.pid for p in backend.panes()} == before
    finally:
        backend.close()
        connection.close()


def test_real_history_defaults_to_memory_and_restart_is_not_adopted(host):
    home, server, profile = host
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    ref = backend.create("demo")
    try:
        pane = backend.panes()[0]
        backend.request("send-keys", "-t", pane.id, "-l", "printf 'MEMORY_ONLY\\n'")
        backend.request("send-keys", "-t", pane.id, "Enter")
        assert not list(home.glob(".pwncat-workspaces/demo/history/*.history"))
        backend.destroy()
        with pytest.raises(WorkspaceError, match="not running"):
            backend.load("demo")
        # A different server on the same socket must not be mistaken for recovery.
        connection.execute(
            [
                server.tmux,
                "-S",
                ref.socket_path,
                "-f",
                "/dev/null",
                "new-session",
                "-d",
                "-s",
                "workspace",
                "/bin/sh",
            ]
        )
        with pytest.raises(IdentityMismatch):
            backend.load("demo", expected=ref)
    finally:
        backend.close()
        connection.close()


def test_real_unknown_host_key_is_rejected(host):
    home, _, profile = host
    from dataclasses import replace

    unknown = home / "empty_known_hosts"
    unknown.write_text("")
    connection = SSHConnection(replace(profile, known_hosts=str(unknown)))
    with pytest.raises(WorkspaceError, match="host key"):
        connection.connect()
    assert not connection.active()


def test_native_display_detaches_without_exiting_panes(host):
    _, _, profile = host
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    backend.create("display")
    channel = None
    try:
        before = backend.panes()[0]
        channel = backend.display((100, 30))
        channel.settimeout(5)
        data = channel.recv(65536)
        assert b"\x1b" in data  # Real native tmux terminal output.
        assert backend.panes()[0].width == 100
        with pytest.raises(WorkspaceError, match="Another display"):
            backend.display((80, 24))
        channel.sendall(b"\x02d")  # Native tmux detach, not shell exit.
        deadline = time.monotonic() + 5
        while not channel.exit_status_ready():
            if channel.recv_ready():
                channel.recv(65536)
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert channel.recv_exit_status() == 0
        after = backend.panes()[0]
        assert (after.id, after.pid, after.dead) == (before.id, before.pid, False)
    finally:
        if channel:
            channel.close()
        backend.close()
        connection.close()


def test_real_changed_host_key_stops_connection(host):
    from unittest.mock import Mock

    import paramiko

    _home, server, profile = host
    different = paramiko.RSAKey.generate(2048)
    Path(profile.known_hosts).write_text(
        f"[127.0.0.1]:{server.port} {different.get_name()} {different.get_base64()}\n"
    )
    confirm = Mock(return_value=True)
    connection = SSHConnection(profile, confirm_host_key=confirm)
    with pytest.raises(WorkspaceError, match="identity/authentication"):
        connection.connect()
    assert not connection.active()
    confirm.assert_not_called()


@pytest.mark.parametrize("custom_file", [False, True])
def test_cli_accepts_unknown_key_and_reconnects_without_prompt(
    host, monkeypatch, capsys, custom_file
):
    import io
    import sys

    from pwncat.workspace.cli import main
    from pwncat.workspace.hostkeys import fingerprint

    class TerminalInput(io.StringIO):
        def isatty(self):
            return True

    home, server, profile = host
    monkeypatch.setenv("HOME", str(home))
    known_hosts = (
        home / "new-known-hosts" if custom_file else home / ".ssh" / "known_hosts"
    )
    options = ["--known-hosts", str(known_hosts)] if custom_file else []
    monkeypatch.setattr(sys, "stdin", TerminalInput("yes\n"))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "-i",
                profile.identity,
                *options,
                "new",
                "first-use",
                "--no-attach",
            ]
        )
        == 0
    )
    assert fingerprint(server.host_key) in capsys.readouterr().err
    assert known_hosts.exists()
    saved = known_hosts.read_bytes()
    # A later command resolves the local name and no longer needs a terminal
    # or any confirmation input for this trusted server key.
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert main(["status", "first-use"]) == 0
    assert "Trust this host" not in capsys.readouterr().err
    assert known_hosts.read_bytes() == saved


def test_declined_host_key_stops_before_authentication(host, monkeypatch):
    from dataclasses import replace
    from unittest.mock import Mock

    import paramiko

    home, _server, profile = host
    known_hosts = home / "declined-known-hosts"
    auth = Mock(side_effect=AssertionError("Authentication must not run"))
    monkeypatch.setattr(paramiko.SSHClient, "_auth", auth)
    connection = SSHConnection(
        replace(profile, known_hosts=str(known_hosts)),
        confirm_host_key=lambda *_: False,
    )
    with pytest.raises(WorkspaceError, match="not accepted"):
        connection.connect()
    assert not known_hosts.exists()
    assert not connection.active()
    auth.assert_not_called()


def test_cli_create_list_split_and_destroy(host, capsys):
    from pwncat.workspace.cli import main

    home, server, profile = host
    common = [
        f"test@127.0.0.1:{server.port}",
        "-i",
        profile.identity,
        "--known-hosts",
        profile.known_hosts,
    ]
    assert main([*common, "new", "cli", "--no-attach"]) == 0
    assert main([*common, "archive", "cli"]) == 1
    assert "still running" in capsys.readouterr().err
    assert main([*common, "list"]) == 0
    assert "cli  running" in capsys.readouterr().out
    assert main([*common, "split", "cli", "%0"]) == 0
    assert main([*common, "panes", "cli"]) == 0
    assert "%1" in capsys.readouterr().out
    assert main([*common, "status", "cli"]) == 0
    assert "SSH / file account: test@127.0.0.1" in capsys.readouterr().out
    assert main(["destroy", "cli", "--yes"]) == 0
    directory = home / ".pwncat-workspaces/cli"
    manifest = (directory / "manifest.json").read_bytes()
    history = directory / "history/retained.history"
    history.write_text("retained command history\n")
    history.chmod(0o600)
    assert main(["new", "cli", "--no-attach"]) == 1
    assert "archive the stopped workspace" in capsys.readouterr().err
    assert main(["archive", "cli"]) == 0
    archived = list((home / ".pwncat-workspaces/.archives").iterdir())
    assert len(archived) == 1
    assert (archived[0] / "manifest.json").read_bytes() == manifest
    assert (
        archived[0] / "history/retained.history"
    ).read_text() == "retained command history\n"
    assert (archived[0] / "history/retained.history").stat().st_mode & 0o077 == 0
    assert not directory.exists()
    assert main(["new", "cli", "--no-attach"]) == 0
    assert (directory / "manifest.json").read_bytes() != manifest


@pytest.mark.parametrize("reset", ["missing", "stopped"])
def test_saved_attachment_recovers_after_remote_reset(host, monkeypatch, reset):
    from unittest.mock import Mock

    from pwncat.workspace.cli import main
    from pwncat.workspace.profiles import ProfileStore

    home, server, profile = host
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "-i",
                profile.identity,
                "--known-hosts",
                profile.known_hosts,
                "new",
                "reset",
                "--no-attach",
                "--history",
                "private",
            ]
        )
        == 0
    )
    original = ProfileStore().get("reset")
    assert main(["destroy", "reset", "--yes"]) == 0
    directory = home / ".pwncat-workspaces/reset"
    if reset == "missing":
        shutil.rmtree(directory)
    else:
        (directory / "history/retained.history").write_text("history before reset\n")

    interact = Mock()
    monkeypatch.setattr("pwncat.workspace.cli.interact", interact)
    assert main(["attach", "reset"]) == 0
    interact.assert_called_once()
    recovered = ProfileStore().get("reset")
    assert recovered.connection == original.connection
    assert recovered.ref.uuid != original.ref.uuid
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    try:
        assert backend.load("reset", expected=recovered.ref) == recovered.ref
        assert not backend.panes()[0].dead
        if reset == "stopped":
            archived = list((home / ".pwncat-workspaces/.archives").iterdir())
            assert len(archived) == 1
            assert (
                archived[0] / "history/retained.history"
            ).read_text() == "history before reset\n"
            assert backend.store.load("reset")["history"] == "private"
    finally:
        backend.close()
        connection.close()


def test_console_selection_windows_and_transfers(host, tmp_path, capsys):
    from pwncat.workspace.console import WorkspaceConsole

    home, _, profile = host
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    backend.create("console")
    console = WorkspaceConsole(backend)
    try:
        first = backend.panes()[0]
        console.execute("help")
        assert "Select a pane" in capsys.readouterr().out
        console.execute("help select")
        assert "select %ID" in capsys.readouterr().out
        console.execute('window "files and logs"')
        second = console.selected()
        assert second.window_id != first.window_id
        console.execute("split vertical")
        third = console.selected()
        assert third.window_id == second.window_id
        assert third.id != second.id
        console.execute("select " + first.id)
        assert backend.current_pane() == first.id
        console.execute("select " + third.id)
        assert console.execute("resume") == "resume"
        assert backend.current_pane() == third.id
        before = {p.id: p.pid for p in backend.panes()}

        local = tmp_path / "local files"
        local.mkdir()
        original_cwd = os.getcwd()
        console.execute("lcd " + shlex.quote(str(local)))
        assert os.getcwd() == original_cwd
        assert console.state.local_directory == str(local)
        content = bytes(range(256)) * 1024
        (local / "source file").write_bytes(content)
        remote = str(home / "remote file")
        console.execute('upload "source file" ' + shlex.quote(remote))
        console.execute("download " + shlex.quote(remote) + ' "copy file"')
        assert (local / "copy file").read_bytes() == content
        assert {p.id: p.pid for p in backend.panes()} == before
        console.execute("status")
        output = capsys.readouterr().out
        assert "SSH / file account: test@127.0.0.1" in output
        assert "Selected pane: " + third.id in output
        assert "Observed directory:" in output

        backend.request("kill-pane", "-t", third.id)
        with pytest.raises(WorkspaceError, match="no longer exists"):
            console.execute("resume")
        assert console.state.selected == third.id
        console.execute("select " + first.id)
        assert console.execute("resume") == "resume"
        assert backend.current_pane() == first.id
        assert console.execute("detach") == "detach"
        assert backend.pane(first.id).pid == first.pid
    finally:
        backend.close()
        connection.close()


def test_console_cli_exits_cleanly_on_eof_and_keeps_shell(host, monkeypatch):
    from pwncat.workspace.cli import main

    _, server, profile = host
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    backend.create("console")
    before = backend.panes()[0]
    inputs = iter(["help", "status", "split vertical"])

    def read(_prompt):
        try:
            return next(inputs)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", read)
    try:
        assert (
            main(
                [
                    f"test@127.0.0.1:{server.port}",
                    "-i",
                    profile.identity,
                    "--known-hosts",
                    profile.known_hosts,
                    "console",
                    "console",
                ]
            )
            == 0
        )
        assert len(backend.panes()) == 2
        assert backend.pane(before.id).pid == before.pid
    finally:
        backend.close()
        connection.close()


@pytest.mark.parametrize("entry", ["console", "attach"])
def test_interactive_cli_roundtrip_between_console_and_tmux(host, entry):
    import fcntl
    import pty
    import select
    import struct
    import sys
    import termios

    from pwncat.workspace.cli import main

    _, server, profile = host
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    backend.create("keyboard")
    original = backend.panes()[0]
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "-i",
                profile.identity,
                "--known-hosts",
                profile.known_hosts,
                "status",
                "keyboard",
            ]
        )
        == 0
    )
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "pwncat",
            "workspace",
            entry,
            "keyboard",
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env={**os.environ, "TERM": "xterm-256color", "PROMPT_TOOLKIT_NO_CPR": "1"},
        start_new_session=True,
    )
    os.close(slave)

    pending = bytearray()

    def expect(fragment):
        deadline = time.monotonic() + 10
        while fragment not in pending:
            assert time.monotonic() < deadline, bytes(pending)
            if select.select([master], [], [], 0.1)[0]:
                try:
                    pending.extend(os.read(master, 65536))
                except OSError:
                    pytest.fail(f"Interactive CLI exited early: {bytes(pending)!r}")
        end = pending.index(fragment) + len(fragment)
        output = bytes(pending[:end])
        del pending[:end]
        return output

    try:
        if entry == "attach":
            expect(b"\x1b[?1049h")
            os.write(master, b"\x07p")
        expect(b"[workspace:keyboard:%0]")
        os.write(master, b"color on\r")
        colored = expect(b"Colors: on (enabled).")
        assert b"\x1b[1;35m" in colored
        expect(b"[workspace:keyboard:%0]")
        os.write(master, b"hel\t")
        expect(b"help")
        os.write(master, b"\r")
        expect(b"Show workspace commands and usage.")
        expect(b"[workspace:keyboard:%0]")
        os.write(master, b"split horizontal\x03")  # Ctrl+C discards unfinished input.
        expect(b"[workspace:keyboard:%0]")
        os.write(master, b"resume\r")
        expect(b"\x1b[?1049h")  # Native tmux takes the terminal.
        os.write(master, b"\x07p")
        expect(b"[workspace:keyboard:%0]")
        os.write(master, b"split vertical\r")
        expect(b"Created %1")
        expect(b"[workspace:keyboard:%1]")
        os.write(master, b"select %0\r")
        expect(b"Selected %0")
        expect(b"[workspace:keyboard:%0]")
        os.write(master, b"detach\r")
        assert process.wait(timeout=5) == 0
        assert len(backend.panes()) == 2
        assert backend.pane(original.id).pid == original.pid
        from pwncat.workspace.console_history import ConsoleHistory
        from pwncat.workspace.profiles import ProfileStore

        store = ProfileStore()
        saved = store.get("keyboard")
        history = ConsoleHistory(store, "keyboard", saved.connection, saved.ref).load()
        assert "help" in history and "split vertical" in history
        assert history[-1] == "detach"
        assert "split horizontal" not in history  # Ctrl+C discarded pending input.
        if entry == "console":
            # A genuinely new CLI process must expose persisted commands to Up.
            os.close(master)
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
            pending.clear()
            process = subprocess.Popen(
                [sys.executable, "-m", "pwncat", "workspace", "console", "keyboard"],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env={
                    **os.environ,
                    "TERM": "xterm-256color",
                    "PROMPT_TOOLKIT_NO_CPR": "1",
                },
                start_new_session=True,
            )
            os.close(slave)
            expect(b"[workspace:keyboard:%0]")
            os.write(master, b"\x1b[A")
            expect(b"detach")
            os.write(master, b"\r")
            assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        os.close(master)
        backend.close()
        connection.close()


@pytest.mark.parametrize("action", ["attach", "console"])
def test_cli_restores_saved_forward_after_loading_workspace(host, monkeypatch, action):
    import socket

    from pwncat.workspace.cli import main
    from pwncat.workspace.model import ForwardRule
    from pwncat.workspace.profiles import ProfileStore

    _home, server, profile = host
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "-i",
                profile.identity,
                "--known-hosts",
                profile.known_hosts,
                "new",
                "saved-forward",
                "--no-attach",
            ]
        )
        == 0
    )
    store = ProfileStore()
    saved = store.get("saved-forward")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    rule = ForwardRule(port, 80, "127.0.0.1")
    store.remember_forward(saved.alias, saved.connection, saved.ref, rule)
    observed = []

    def display(channel, connection):
        observed.extend(connection.local_forwards().list())
        channel.close()
        return "detach"

    def console(instance):
        observed.extend(instance.backend.connection.local_forwards().list())
        return "detach"

    monkeypatch.setattr("pwncat.workspace.cli.display", display)
    monkeypatch.setattr("pwncat.workspace.cli.WorkspaceConsole.run", console)
    assert main([action, "saved-forward"]) == 0
    assert len(observed) == 1 and observed[0].running
    assert observed[0].local_port == port
    assert store.get(saved.alias).forwards == (rule,)
    # Detach closes the listener while retaining only its settings.
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1)


def test_password_profile_prompts_again_on_short_attach_without_storing_secret(
    host, monkeypatch
):
    from unittest.mock import Mock

    from pwncat.workspace.cli import main
    from pwncat.workspace.profiles import ProfileStore

    _, server, profile = host
    server.password = "workspace-fixture-password"
    prompt = Mock(return_value=server.password)
    monkeypatch.setattr("pwncat.workspace.cli.getpass.getpass", prompt)
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "--known-hosts",
                profile.known_hosts,
                "new",
                "password",
                "--password",
                "--no-attach",
            ]
        )
        == 0
    )
    stored = ProfileStore().get("password")
    assert stored.password_prompt
    assert stored.connection.identity is None
    assert server.password not in (ProfileStore().root / "password.json").read_text()
    assert main(["status", "password"]) == 0
    attach = Mock()
    monkeypatch.setattr("pwncat.workspace.cli.interact", attach)
    assert main(["attach", "password"]) == 0
    assert attach.call_args.args[0].ref == stored.ref
    assert prompt.call_count == 3


def test_local_alias_maps_to_remote_name_and_forget_keeps_remote_workspace(host):
    from pwncat.workspace.cli import main
    from pwncat.workspace.profiles import ProfileStore

    _, server, profile = host
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "-i",
                profile.identity,
                "--known-hosts",
                profile.known_hosts,
                "new",
                "remote",
                "--alias",
                "desk",
                "--no-attach",
            ]
        )
        == 0
    )
    saved = ProfileStore().get("desk")
    assert saved.ref.name == "remote"
    assert main(["status", "desk"]) == 0
    assert main(["forget", "desk"]) == 0
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    try:
        assert backend.load("remote", expected=saved.ref) == saved.ref
        assert not backend.panes()[0].dead
    finally:
        backend.close()
        connection.close()


def test_saved_name_rejects_an_out_of_band_replacement(host, capsys):
    from pwncat.workspace.cli import main
    from pwncat.workspace.profiles import ProfileStore

    _, server, profile = host
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "-i",
                profile.identity,
                "--known-hosts",
                profile.known_hosts,
                "new",
                "replace",
                "--no-attach",
            ]
        )
        == 0
    )
    original = ProfileStore().get("replace").ref
    connection = SSHConnection(profile).connect()
    backend = TmuxWorkspace(connection)
    try:
        backend.load("replace")
        backend.destroy()
        backend.archive("replace")
        replacement = backend.create("replace")
        assert replacement.uuid != original.uuid
        assert main(["status", "replace"]) == 1
        assert "Workspace server changed" in capsys.readouterr().err
        assert main(["archive", "replace"]) == 1
        assert "identity changed" in capsys.readouterr().err
        assert ProfileStore().get("replace").ref == original
        assert not backend.panes()[0].dead
    finally:
        backend.close()
        connection.close()


@pytest.mark.parametrize("save_action", ["new", "attach", "status"])
def test_saved_credentials_reconnect_without_prompt_and_can_be_removed(
    host, monkeypatch, save_action
):
    from unittest.mock import Mock

    from test_workspace_credentials import MemoryVault

    from pwncat.workspace.cli import main
    from pwncat.workspace.profiles import ProfileStore

    _, server, profile = host
    server.password = "fixture-save-once-password"
    vault = MemoryVault()
    monkeypatch.setattr("pwncat.workspace.credentials.native_backend", lambda: vault)
    prompt = Mock(return_value=server.password)
    monkeypatch.setattr("pwncat.workspace.cli.getpass.getpass", prompt)
    monkeypatch.setattr("pwncat.workspace.cli.interact", Mock())
    common = [
        f"test@127.0.0.1:{server.port}",
        "--known-hosts",
        profile.known_hosts,
        "--password",
    ]
    if save_action == "new":
        assert main([*common, "new", "saved", "--save-credentials", "--no-attach"]) == 0
    else:
        assert main([*common, "new", "saved", "--no-attach"]) == 0
        assert main([save_action, "saved", "--save-credentials"]) == 0
    count = prompt.call_count
    saved = ProfileStore().get("saved")
    assert saved.credential_ref and vault.values
    assert server.password not in (ProfileStore().root / "saved.json").read_text()
    prompt.side_effect = AssertionError("saved credentials must not prompt")
    assert main(["attach", "saved"]) == 0
    assert main(["status", "saved"]) == 0
    assert prompt.call_count == count
    assert main(["forget-credentials", "saved"]) == 0
    assert not vault.values
    assert ProfileStore().get("saved").credential_ref is None
    prompt.side_effect = None
    assert main(["status", "saved"]) == 0
    assert prompt.call_count == count + 1


def test_failed_authentication_never_saves_credentials(host, monkeypatch):
    from unittest.mock import Mock

    from test_workspace_credentials import MemoryVault

    from pwncat.workspace.cli import main
    from pwncat.workspace.profiles import ProfileStore

    _, server, profile = host
    server.password = "expected-fixture"
    vault = MemoryVault()
    monkeypatch.setattr("pwncat.workspace.credentials.native_backend", lambda: vault)
    monkeypatch.setattr(
        "pwncat.workspace.cli.getpass.getpass", Mock(return_value="wrong-fixture")
    )
    assert (
        main(
            [
                f"test@127.0.0.1:{server.port}",
                "--known-hosts",
                profile.known_hosts,
                "new",
                "failed",
                "--password",
                "--save-credentials",
                "--no-attach",
            ]
        )
        == 1
    )
    assert not vault.values
    assert ProfileStore().get("failed") is None
