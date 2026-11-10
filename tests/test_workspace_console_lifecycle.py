"""Returning to tmux suspends the console without destroying its sessions."""

import io
import os
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.manager import InteractiveExit, Manager, Session
from pwncat.workspace import ConnectionLost, WorkspaceError
from pwncat.workspace.cli import interact
from pwncat.workspace.console import WorkspaceConsole
from pwncat.workspace.terminal import InputFilter


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    backend = Mock()
    backend.current_pane.return_value = "%0"
    backend.pane.return_value = SimpleNamespace(id="%0")
    backend.connection.active.return_value = True
    managers, actions, channels, database_closes = [], [], [], []

    def session(manager, channel):
        result = Session.__new__(Session)
        result.id = manager.session_id
        manager.session_id += 1
        result.manager = manager
        result.platform = SimpleNamespace(
            channel=channel, name="linux", getuid=Mock(return_value=1000)
        )
        result.hash = "fixture-host"
        result.current_user = Mock(return_value=None)
        result._progress = None
        manager.sessions[result.id] = result
        manager.target = result
        return result

    def make_manager():
        manager = Manager(config=io.StringIO('set -g db "memory://"\n'))
        managers.append(manager)
        close_database = Mock(wraps=manager.db.close)
        database_closes.append(close_database)
        manager.db.close = close_database
        manager.create_session = Mock(
            side_effect=lambda *, channel, **_: session(manager, channel)
        )

        def prompt(**_):
            if not actions:
                pytest.fail("console unexpectedly requested another command")
            action = actions.pop(0)
            return action(manager) if callable(action) else action

        # Keep the actual command parser and interactive loop. Only terminal
        # input and SSH session creation are substituted.
        manager.parser.prompt = Mock(prompt=Mock(side_effect=prompt))
        return manager

    def channel(_):
        result = Mock()
        channels.append(result)
        return result

    factory = Mock(side_effect=make_manager)
    monkeypatch.setattr("pwncat.workspace.console.Manager", factory)
    monkeypatch.setattr("pwncat.workspace.platform.WorkspaceChannel", channel)
    confirm = Mock(side_effect=AssertionError("resume must not ask to close sessions"))
    monkeypatch.setattr("pwncat.manager.confirm", confirm)
    with (tmp_path / "input").open("w+") as stdin:
        monkeypatch.setattr("sys.stdin", stdin)
        yield SimpleNamespace(
            backend=backend,
            managers=managers,
            actions=actions,
            channels=channels,
            factory=factory,
            session=session,
            stdin=stdin,
            confirm=confirm,
            database_closes=database_closes,
        )
    for manager in managers:
        manager.db.close()


def test_resume_retains_selected_session_aliases_and_open_channels(runtime):
    selected_channel = Mock()

    def select_second(manager):
        runtime.session(manager, selected_channel)
        return "sessions 1"

    runtime.actions.extend(
        ["alias kept status", select_second, "resume", "resume", "detach"]
    )
    console = WorkspaceConsole(runtime.backend)
    assert console.run() == "resume"
    manager = runtime.managers[0]
    selected = manager.target
    assert selected.id == 1

    assert console.run() == "resume"
    assert console._manager is manager
    assert manager.target is selected
    assert manager.parser.aliases["kept"] == "status"
    assert len(manager.sessions) == 2
    manager.create_session.assert_called_once()
    runtime.factory.assert_called_once()
    runtime.channels[0].close.assert_not_called()
    selected_channel.close.assert_not_called()
    runtime.database_closes[0].assert_not_called()
    runtime.confirm.assert_not_called()
    os.fstat(runtime.stdin.fileno())

    assert console.run() == "detach"
    assert console._manager is None
    assert not manager.sessions
    runtime.channels[0].close.assert_called_once()
    selected_channel.close.assert_called_once()
    runtime.database_closes[0].assert_called_once()
    console.close()  # Outer-loop cleanup is idempotent.
    runtime.database_closes[0].assert_called_once()


def test_ctrl_q_detaches_and_later_attach_starts_in_display(runtime, monkeypatch):
    def ctrl_q(_):
        raise InteractiveExit

    runtime.actions.append(ctrl_q)
    display = Mock(return_value="detach")
    monkeypatch.setattr("pwncat.workspace.cli.display", display)
    interact(runtime.backend, Mock(), start_console=True)
    display.assert_not_called()
    runtime.channels[0].close.assert_called_once()
    assert not runtime.managers[0].sessions
    interact(runtime.backend, Mock(), start_console=False)
    display.assert_called_once()
    runtime.factory.assert_called_once()
    runtime.confirm.assert_not_called()


def test_managed_ctrl_q_parks_same_manager_and_selected_session(runtime, monkeypatch):
    monkeypatch.setattr("pwncat.workspace.local_screen.managed", lambda: True)
    parked = Mock()
    monkeypatch.setattr("pwncat.workspace.local_screen.park", parked)

    def ctrl_q(_):
        raise InteractiveExit

    def after_reattach(manager):
        assert manager is runtime.managers[0]
        assert manager.target is selected
        return "detach"

    runtime.actions.extend([ctrl_q, after_reattach])
    console = WorkspaceConsole(runtime.backend)
    assert console.run() == "park"
    selected = runtime.managers[0].target
    assert selected is not None
    runtime.channels[0].close.assert_not_called()
    assert console.run() == "detach"
    runtime.factory.assert_called_once()
    runtime.managers[0].create_session.assert_called_once()
    runtime.channels[0].close.assert_called_once()


def test_detach_is_refused_during_background_transfer_without_closing_sessions(runtime, monkeypatch):
    runtime.actions.extend(["detach", "detach"])
    console = WorkspaceConsole(runtime.backend)
    active = Mock(return_value=True)
    monkeypatch.setattr(console.transfers, "active", active)
    assert console.run() == "busy"
    assert console._manager is runtime.managers[0]
    runtime.channels[0].close.assert_not_called()
    active.return_value = False
    assert console.run() == "detach"
    runtime.channels[0].close.assert_called_once()


def test_background_transfer_progress_appears_in_console_toolbar(runtime):
    from prompt_toolkit.formatted_text import to_formatted_text
    from pwncat.workspace.background_transfers import TransferStatus

    console = WorkspaceConsole(runtime.backend)
    manager = console.prepare_manager()
    console.transfers._status = TransferStatus(
        1, "download", 2, "/remote", "/local", "running",
        transferred=512, total=1024, phase="copying",
    )
    rendered = manager.parser._render_toolbar()
    line = "".join(text for _style, text in to_formatted_text(rendered))
    assert "Transfer 1" in line
    assert "50.0%" in line
    assert "copying" in line
    console.close()


def test_interact_parks_managed_console_without_closing_sessions(runtime, monkeypatch):
    monkeypatch.setattr("pwncat.workspace.local_screen.managed", lambda: True)
    parked = Mock()
    monkeypatch.setattr("pwncat.workspace.local_screen.park", parked)

    def ctrl_q(_):
        raise InteractiveExit

    runtime.actions.extend([ctrl_q, "detach"])
    interact(runtime.backend, Mock(), start_console=True)
    parked.assert_called_once()
    runtime.factory.assert_called_once()
    runtime.managers[0].create_session.assert_called_once()
    runtime.channels[0].close.assert_called_once()


def test_attach_restores_listener_owner_without_opening_pwncat_shell(runtime, monkeypatch):
    settings = Mock()
    settings.rules.return_value = [object()]
    settings.restore.return_value = []
    display = Mock(return_value="detach")
    monkeypatch.setattr("pwncat.workspace.cli.display", display)
    interact(runtime.backend, Mock(), listener_settings=settings)
    settings.restore.assert_called_once_with(runtime.managers[0])
    display.assert_called_once()
    assert runtime.channels == []
    runtime.managers[0].create_session.assert_not_called()


def test_sessions_list_handles_unresolved_user_before_and_after_resume(
    runtime, monkeypatch, capsys
):
    print_exception = Mock()
    monkeypatch.setattr("pwncat.util.console.print_exception", print_exception)
    runtime.actions.extend(["sessions", "resume"])
    console = WorkspaceConsole(runtime.backend)
    assert console.run() == "resume"
    manager = runtime.managers[0]
    selected = manager.target

    def list_again(current_manager):
        assert current_manager is manager
        assert current_manager.target is selected
        return "sessions --list"

    runtime.actions.extend([list_again, "detach"])
    assert console.run() == "detach"
    print_exception.assert_not_called()
    assert capsys.readouterr().out.count("unknown (ID: 1000)") == 2
    runtime.factory.assert_called_once()


@pytest.mark.parametrize("display_exit", ["palette", "detach", "interrupt"])
def test_workspace_display_roundtrip_and_cleanup(runtime, monkeypatch, display_exit):
    runtime.actions.extend(["resume", "detach"])

    def display(*_):
        runtime.channels[0].close.assert_not_called()
        assert runtime.managers[0].target is not None
        os.fstat(runtime.stdin.fileno())
        if display_exit == "interrupt":
            raise KeyboardInterrupt
        keys = b"\x07p" if display_exit == "palette" else b"\x07d"
        return InputFilter().feed(keys)[1]

    monkeypatch.setattr("pwncat.workspace.cli.display", display)
    if display_exit == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            interact(runtime.backend, Mock(), start_console=True)
    else:
        interact(runtime.backend, Mock(), start_console=True)
    runtime.factory.assert_called_once()
    runtime.managers[0].create_session.assert_called_once()
    runtime.channels[0].close.assert_called_once()
    runtime.database_closes[0].assert_called_once()
    runtime.backend.close.assert_called_once()
    runtime.backend.connection.close.assert_called_once()


def test_connection_loss_releases_old_console_before_reconnect(runtime, monkeypatch):
    runtime.actions.extend(["resume", "detach"])
    connection, replacement = Mock(), Mock()
    replacement.current_pane.return_value = "%0"
    replacement.connection.active.return_value = True
    monkeypatch.setattr("pwncat.workspace.cli.time.sleep", Mock())
    monkeypatch.setattr(
        "pwncat.workspace.cli.SSHConnection", Mock(return_value=connection)
    )
    monkeypatch.setattr(
        "pwncat.workspace.cli.TmuxWorkspace", Mock(return_value=replacement)
    )

    def connect():
        runtime.channels[0].close.assert_called_once()
        runtime.database_closes[0].assert_called_once()

    connection.connect.side_effect = connect
    monkeypatch.setattr(
        "pwncat.workspace.cli.display",
        Mock(side_effect=[ConnectionLost("test disconnect"), "palette"]),
    )
    interact(runtime.backend, Mock(), start_console=True)
    assert len(runtime.managers) == 2
    assert not runtime.managers[0].sessions
    replacement.load.assert_called_once_with(
        runtime.backend.ref.name, expected=runtime.backend.ref
    )
    for channel in runtime.channels:
        channel.close.assert_called_once()


def test_failed_console_bootstrap_closes_channel_and_manager(runtime):
    original_factory = runtime.factory.side_effect

    def broken_manager():
        manager = original_factory()
        manager.create_session.side_effect = ValueError(
            "fixture initialization failure"
        )
        return manager

    runtime.factory.side_effect = broken_manager
    console = WorkspaceConsole(runtime.backend)
    with pytest.raises(WorkspaceError, match="fixture initialization failure"):
        console.run()
    assert console._manager is None
    runtime.channels[0].close.assert_called_once()
    runtime.database_closes[0].assert_called_once()


@pytest.mark.parametrize("confirm_exit", [True, False])
def test_interactive_reentry_preserves_caller_stdin(
    tmp_path, monkeypatch, confirm_exit
):
    manager = Manager.__new__(Manager)
    manager.sessions = {0: object()}
    manager.listeners = []
    manager.log = Mock()
    descriptors = []

    def leave():
        descriptors.append(sys.stdin.fileno())
        raise InteractiveExit

    manager.parser = SimpleNamespace(
        run=leave,
        prompt=None,
        setup_prompt=lambda: setattr(manager.parser, "prompt", sys.stdin),
    )
    confirm = Mock(return_value=True)
    monkeypatch.setattr("pwncat.manager.confirm", confirm)
    with (tmp_path / "input").open("w+") as original:
        monkeypatch.setattr("sys.stdin", original)
        for _ in range(2):
            manager.interactive(confirm_exit=confirm_exit)
            assert sys.stdin is original
            assert manager.parser.prompt is original
            os.fstat(original.fileno())
            assert not manager.interactive_running
            with pytest.raises(OSError):
                os.fstat(descriptors[-1])
    assert confirm.call_count == (2 if confirm_exit else 0)


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX terminal")
def test_real_keyboard_input_works_after_resume(tmp_path):
    import pty
    import select

    # Exercise PromptSession's cached terminal input in a separate process.
    # Session creation is local and simulated; no SSH connection is opened.
    script = """
import io
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pwncat.manager import Manager, Session
from pwncat.workspace.console import WorkspaceConsole

backend = Mock()
backend.current_pane.return_value = "%0"
backend.pane.return_value = SimpleNamespace(id="%0")
backend.connection.active.return_value = True
manager = Manager(config=io.StringIO('set -g db "memory://"\\n'))
def create_session(*, channel, **kwargs):
    session = Session.__new__(Session)
    session.id, session.manager, session._progress = 0, manager, None
    session.platform = SimpleNamespace(channel=channel)
    manager.sessions[0] = session
    manager.target = session
    return session
manager.create_session = create_session
with patch("pwncat.workspace.console.Manager", return_value=manager), \\
     patch("pwncat.workspace.platform.WorkspaceChannel", return_value=Mock()):
    console = WorkspaceConsole(backend)
    try:
        assert console.run() == "resume"
        selected = manager.target
        print("RETURNED_TO_PANE", flush=True)
        assert manager.parser.aliases["kept"] == "status"
        assert selected.platform.channel.close.call_count == 0
        assert console.run() == "detach"
        assert selected.platform.channel.close.call_count == 1
    finally:
        console.close()
"""
    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=tmp_path,
            start_new_session=True,
            env={
                **os.environ,
                "TERM": "xterm-256color",
                "PROMPT_TOOLKIT_NO_CPR": "1",
                "XDG_CONFIG_HOME": str(tmp_path),
                "XDG_DATA_HOME": str(tmp_path),
            },
        )
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    pending = bytearray()

    def expect(fragment):
        deadline = time.monotonic() + 5
        while fragment not in pending:
            assert time.monotonic() < deadline, bytes(pending)
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    pytest.fail(f"Console exited early: {bytes(pending)!r}")
                assert data, bytes(pending)
                pending.extend(data)
        end = pending.index(fragment) + len(fragment)
        del pending[:end]

    try:
        expect(b"$")
        os.write(master, b"alias kept status\r")
        expect(b"$")
        os.write(master, b"resume\r")
        expect(b"RETURNED_TO_PANE")
        expect(b"$")
        os.write(master, b"alias\r")
        expect(b"kept")
        expect(b"status")
        expect(b"$")
        os.write(master, b"detach\r")
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        os.close(master)
