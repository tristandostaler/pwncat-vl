"""Workspace invariants: framing, privacy, identity, publication and CLI isolation."""

import errno
import hashlib
import json
import os
import stat
from pathlib import Path
from unittest.mock import Mock

import pytest

from pwncat.workspace import IdentityMismatch, OutcomeUnknown, WorkspaceError
from pwncat.workspace.cli import main
from pwncat.workspace.files import FileService
from pwncat.workspace.model import safe_text, workspace_name
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.protocol import (
    ControlClient,
    ControlParser,
    Response,
    command_line,
)
from pwncat.workspace.ssh import SSHConnection, SSHProfile
from pwncat.workspace.state import StateStore
from pwncat.workspace.terminal import InputFilter
from pwncat.workspace.tmux import TmuxWorkspace


@pytest.fixture(autouse=True)
def isolated_workspace_profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))


@pytest.fixture
def saved_workspace():
    from pwncat.workspace.model import WorkspaceRef

    return SavedWorkspace(
        "lab",
        SSHProfile(
            "server.example",
            "test",
            2222,
            "/private/key",
            "/private/known_hosts",
            password="fixture-password-secret",
            passphrase="fixture-passphrase-secret",
        ),
        True,
        True,
        WorkspaceRef(
            "lab", "a" * 32, "123:100", "/home/test/.pwncat-workspaces/lab/tmux.sock"
        ),
    )


def test_profile_roundtrip_private_permissions_and_no_secrets(saved_workspace):
    store = ProfileStore()
    store.save(saved_workspace)
    path = store.root / "lab.json"
    raw = path.read_text()
    assert "fixture-password-secret" not in raw
    assert "fixture-passphrase-secret" not in raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    recovered = store.get("lab")
    assert recovered.ref == saved_workspace.ref
    assert recovered.password_prompt and recovered.passphrase_prompt
    assert recovered.connection.password is None
    assert recovered.connection.passphrase is None
    assert recovered.connection.identity == "/private/key"


def test_profile_refuses_destination_collision_and_identity_change(saved_workspace):
    from dataclasses import replace

    store = ProfileStore()
    store.save(saved_workspace)
    original = (store.root / "lab.json").read_bytes()
    with pytest.raises(WorkspaceError, match="another destination"):
        store.save(
            replace(saved_workspace, connection=SSHProfile("elsewhere.example", "test"))
        )
    changed = replace(saved_workspace, ref=replace(saved_workspace.ref, uuid="b" * 32))
    with pytest.raises(IdentityMismatch):
        store.save(changed)
    assert (store.root / "lab.json").read_bytes() == original
    store.save(changed, replace_identity=True)
    assert store.get("lab").ref.uuid == "b" * 32


def test_profile_rejects_symlinks_and_preserves_corrupt_data(saved_workspace, tmp_path):
    store = ProfileStore()
    store.save(saved_workspace)
    path = store.root / "lab.json"
    external = tmp_path / "outside"
    external.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(external)
    with pytest.raises(WorkspaceError, match="private"):
        store.get("lab")
    path.unlink()
    path.write_text("{invalid json")
    path.chmod(0o600)
    with pytest.raises(WorkspaceError, match="Invalid saved"):
        store.save(saved_workspace)
    assert path.read_text() == "{invalid json"


def test_profile_failed_publish_keeps_original(saved_workspace, monkeypatch):
    from dataclasses import replace

    store = ProfileStore()
    store.save(saved_workspace)
    original = (store.root / "lab.json").read_bytes()
    monkeypatch.setattr(
        "pwncat.workspace.profiles.os.replace", Mock(side_effect=OSError("disk full"))
    )
    with pytest.raises(OSError, match="disk full"):
        store.save(replace(saved_workspace, password_prompt=False))
    assert (store.root / "lab.json").read_bytes() == original
    assert not list(store.root.glob(".write-*"))


@pytest.mark.parametrize(
    "argv, expected_password",
    [
        (["attach", "lab"], True),
        (["test@server.example:2222", "attach", "lab"], True),
        (["attach", "lab", "--no-password"], False),
        (["--no-password", "attach", "lab"], False),
        (["test@server.example:2222", "--password", "attach", "lab"], True),
        (["test@server.example:2222", "attach", "lab", "--password"], True),
    ],
)
def test_saved_auth_settings_and_option_positions(
    saved_workspace, argv, expected_password
):
    from pwncat.workspace.cli import parser, resolve_connection, uses_saved_name

    store = ProfileStore()
    store.save(saved_workspace)
    args = parser(saved_name=uses_saved_name(argv)).parse_args(argv)
    alias, remote, profile, ask_password, _ask_passphrase, expected = (
        resolve_connection(args, store)
    )
    assert (alias, remote, profile.host, profile.port) == (
        "lab",
        "lab",
        "server.example",
        2222,
    )
    assert ask_password is expected_password
    assert expected == saved_workspace.ref


def test_local_list_forget_and_missing_alias_never_connect(
    saved_workspace, monkeypatch, capsys
):
    store = ProfileStore()
    store.save(saved_workspace)
    connector, prompt = Mock(), Mock()
    monkeypatch.setattr("pwncat.workspace.cli.SSHConnection", connector)
    monkeypatch.setattr("pwncat.workspace.cli.getpass.getpass", prompt)
    assert main(["list"]) == 0
    assert "lab  test@server.example:2222" in capsys.readouterr().out
    assert main(["forget", "lab"]) == 0
    assert store.get("lab") is None
    assert main(["attach", "lab"]) == 1
    assert "No saved workspace" in capsys.readouterr().err
    connector.assert_not_called()
    prompt.assert_not_called()


def test_alias_collision_is_rejected_before_authentication(
    saved_workspace, monkeypatch
):
    ProfileStore().save(saved_workspace)
    connector, prompt = Mock(), Mock()
    monkeypatch.setattr("pwncat.workspace.cli.SSHConnection", connector)
    monkeypatch.setattr("pwncat.workspace.cli.getpass.getpass", prompt)
    assert (
        main(["test@different.example", "--password", "new", "lab", "--no-attach"]) == 1
    )
    connector.assert_not_called()
    prompt.assert_not_called()


class LocalSFTP:
    """Exercise real filesystem semantics without a remote target."""

    lstat = staticmethod(os.lstat)
    chmod = staticmethod(os.chmod)
    mkdir = staticmethod(os.mkdir)
    remove = staticmethod(os.unlink)
    rmdir = staticmethod(os.rmdir)
    posix_rename = staticmethod(os.replace)

    @staticmethod
    def open(path, mode):
        return open(path, "xb" if mode == "wx" else mode)

    @staticmethod
    def rename(source, destination):
        if os.path.lexists(destination):
            raise FileExistsError(errno.EEXIST, "File exists", destination)
        os.rename(source, destination)


@pytest.mark.parametrize("step", [1, 2, 7, 4096])
def test_control_chunking(step):
    wire = (
        b"%begin 1 2 1\nhello\n%end 1 2 1\n%window-add @3\n"
        b"%begin 1 4 1\nbad request\n%error 1 4 1\n"
    )
    parser = ControlParser()
    events = []
    for offset in range(0, len(wire), step):
        events.extend(parser.feed(wire[offset : offset + step]))
    assert events == [
        Response(True, (b"hello",)),
        b"%window-add @3",
        Response(False, (b"bad request",)),
    ]


@pytest.mark.parametrize(
    "wire",
    [
        b"banner\n",
        b"%end 1 2 1\n",
        b"%begin 1 2 1\n%end 1 3 1\n",
        b"%begin 1 2 1\n%begin 1 3 1\n",
        b"x" * (ControlParser.MAX_BYTES + 1),
    ],
)
def test_control_rejects_corrupt_or_unbounded_input(wire):
    with pytest.raises(WorkspaceError):
        ControlParser().feed(wire)


def test_control_encode_does_not_allow_record_injection():
    assert b"\\$HOME" in command_line(["rename-window", "$HOME; echo bad"])
    with pytest.raises(WorkspaceError):
        command_line(["name\nkill-server"])


@pytest.mark.parametrize("failure", [TimeoutError, KeyboardInterrupt])
def test_no_replay_on_missing_reply(failure):
    client = object.__new__(ControlClient)
    import threading

    client.writer = threading.Lock()
    client.failure = None
    client.stopped = threading.Event()
    client.channel = Mock()
    client._response = Mock(side_effect=failure())
    client.close = Mock()
    with pytest.raises(OutcomeUnknown):
        client.request("split-window", "-t", "%0")
    client.channel.sendall.assert_called_once()
    client.close.assert_called_once()


def test_input_prefix_fragmentation_and_no_replay():
    keys = InputFilter()
    assert keys.feed(b"hello\x1d") == (b"hello", None)
    assert keys.feed(b"pnever-send-this") == (b"", "palette")
    assert keys.feed(b"\x1d\x1d") == (b"\x1d", None)
    assert keys.feed(b"\x1dx") == (b"\x1dx", None)
    assert keys.feed(b"\x1ddignored") == (b"", "detach")


@pytest.mark.parametrize("prefix", [b"\x07", b"\x1d"])
@pytest.mark.parametrize("action", [b"p", b"P", b"\x10"])
def test_console_shortcut_supports_non_bracket_key_and_held_control(prefix, action):
    keys = InputFilter()
    assert keys.feed(prefix) == (b"", None)
    assert keys.feed(action + b"discard") == (b"", "palette")
    assert keys.feed(prefix + prefix) == (prefix, None)


def test_profile_rejects_url_password_and_supports_ipv6():
    with pytest.raises(WorkspaceError):
        SSHProfile.parse("ssh://user:secret@host")
    profile = SSHProfile.parse("ssh://user@[::1]:2222", password="hidden")
    assert (profile.host, profile.user, profile.port) == ("::1", "user", 2222)
    assert "hidden" not in repr(profile)


@pytest.mark.parametrize(
    "name", ["../escape", "", "foo/bar", "bad\nname", "name;cmd", "x" * 33]
)
def test_workspace_identifiers_are_not_paths_or_commands(name):
    with pytest.raises(WorkspaceError):
        workspace_name(name)


def test_metadata_is_not_terminal_output():
    assert "\x1b" not in safe_text("title\x1b]52;c;abcd\x07")


def test_console_colors_metadata_without_interpreting_markup(monkeypatch):
    from io import StringIO

    from rich.console import Console

    from pwncat.workspace.console import detail

    output = StringIO()
    colored = Console(
        file=output,
        force_terminal=True,
        width=120,
        color_system="standard",
        no_color=False,
    )
    monkeypatch.setattr("pwncat.workspace.console.Console", lambda **_: colored)
    detail("Workspace", "[red]literal\x1b]52;c;secret\x07")
    rendered = output.getvalue()
    assert "\x1b[1;36m" in rendered
    assert "[red]literal" in rendered
    assert "\x1b]52" not in rendered


def test_transfer_binary_roundtrip_and_modes(tmp_path):
    source, remote, target = [
        tmp_path / name for name in ("source", "remote", "target")
    ]
    content = bytes(range(256)) * 1000
    source.write_bytes(content)
    service = FileService(LocalSFTP())
    uploaded = service.upload(str(source), str(remote))
    downloaded = service.download(str(remote), str(target))
    assert uploaded == downloaded
    assert uploaded.sha256 == hashlib.sha256(content).hexdigest()
    assert target.read_bytes() == content
    assert stat.S_IMODE(remote.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".workspace-*"))


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_sftp_transfer_reports_bytes_and_verification_phase(tmp_path, direction):
    source, target = tmp_path / "src", tmp_path / "dst"
    source.write_bytes(bytes(range(256)) * 300)
    counts, phases = [], []
    result = getattr(FileService(LocalSFTP()), direction)(
        str(source), str(target),
        progress=counts.append,
        status=lambda phase, total: phases.append((phase, total)),
    )
    assert counts and counts[-1] == result.size == source.stat().st_size
    assert counts == sorted(counts)
    assert phases == [
        ("copying", result.size),
        ("verifying", result.size),
        ("publishing", result.size),
    ]


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_transfer_no_clobber_and_explicit_overwrite(tmp_path, direction):
    source, target = tmp_path / "src", tmp_path / "dst"
    source.write_bytes(b"new")
    target.write_bytes(b"old")
    transfer = getattr(FileService(LocalSFTP()), direction)
    with pytest.raises(WorkspaceError, match="exists"):
        transfer(str(source), str(target))
    assert target.read_bytes() == b"old"
    transfer(str(source), str(target), overwrite=True)
    assert target.read_bytes() == b"new"


def test_interrupted_upload_preserves_destination(tmp_path):
    source, target = tmp_path / "src", tmp_path / "dst"
    source.write_bytes(b"new" * 100)
    target.write_bytes(b"old")

    def cancel(_):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        FileService(LocalSFTP()).upload(
            str(source), str(target), overwrite=True, progress=cancel
        )
    assert target.read_bytes() == b"old"
    assert not list(tmp_path.glob(".workspace-*"))


def test_symlink_destination_is_refused(tmp_path):
    source, target, alias = tmp_path / "src", tmp_path / "dst", tmp_path / "link"
    source.write_bytes(b"new")
    target.write_bytes(b"old")
    alias.symlink_to(target)
    with pytest.raises(WorkspaceError, match="regular file"):
        FileService(LocalSFTP()).upload(str(source), str(alias), overwrite=True)
    assert target.read_bytes() == b"old"


def test_state_rejects_symlink_and_corruption(tmp_path):
    store = StateStore(LocalSFTP(), str(tmp_path), os.getuid())
    store.private_directory(store.root, create=True)
    directory = Path(store.directory("test"))
    directory.mkdir(mode=0o700)
    external = tmp_path / "external"
    external.write_text("{}")
    (directory / "manifest.json").symlink_to(external)
    with pytest.raises(WorkspaceError, match="Unsafe"):
        store.load("test")
    (directory / "manifest.json").unlink()
    store.save("test", {"version": 99})
    with pytest.raises(WorkspaceError, match="Invalid"):
        store.load("test")
    assert json.loads((directory / "manifest.json").read_text()) == {"version": 99}


def test_reattach_rejects_reused_server_identity():
    backend = object.__new__(TmuxWorkspace)
    backend.store = Mock()
    backend.store.load.return_value = {"uuid": "a" * 32, "server_epoch": "1:100"}
    backend.store.directory.return_value = "/private/test"
    backend._identity = Mock(return_value=("a" * 32, "2:200"))
    with pytest.raises(IdentityMismatch):
        backend.load("test")


def test_workspace_cli_requires_explicit_destroy(monkeypatch):
    connector = Mock()
    monkeypatch.setattr("pwncat.workspace.cli.SSHConnection", connector)
    assert main(["user@localhost", "destroy", "example"]) == 2
    connector.assert_not_called()


def test_workspace_dispatch_never_constructs_legacy_manager(monkeypatch):
    import pwncat.__main__ as entry
    import pwncat.manager as legacy_manager

    manager = Mock(side_effect=AssertionError("legacy Manager must not be constructed"))
    handler = Mock(return_value=7)
    monkeypatch.setattr(legacy_manager, "Manager", manager)
    monkeypatch.setattr("pwncat.workspace.cli.main", handler)
    monkeypatch.setattr("sys.argv", ["pwncat-vl", "workspace", "--help"])
    assert entry.main() == 7
    handler.assert_called_once_with(["--help"])
    manager.assert_not_called()


def test_connection_closes_client_and_sftp():
    connection = SSHConnection(SSHProfile("localhost", "test"))
    client, sftp = Mock(), Mock()
    connection.client, connection.sftp = client, sftp
    connection.close()
    client.close.assert_called_once()
    sftp.close.assert_called_once()


@pytest.mark.parametrize("result", [(0, b"123\n", b""), (2, b"", b"ps: unsupported")])
def test_archive_refuses_live_or_unverifiable_process(result):
    backend = object.__new__(TmuxWorkspace)
    backend.store, backend.connection = Mock(), Mock()
    backend.store.load.return_value = {"server_epoch": "123:100"}
    backend.store.directory.return_value = "/private/lab"
    backend.binary = "/usr/bin/tmux"
    backend.connection.execute.side_effect = [
        (1, b"", b"no server running on /private/lab/tmux.sock\n"),
        result,
    ]
    with pytest.raises(WorkspaceError, match="Cannot confirm"):
        backend.archive("lab")
    backend.store.archive.assert_not_called()


@pytest.mark.parametrize("close_failure", [None, EOFError])
def test_terminal_restores_modes_and_signal_handlers_on_error(
    monkeypatch, close_failure
):
    import pty
    import signal
    import termios

    from pwncat.workspace.terminal import display

    master, slave = pty.openpty()
    stdin = os.fdopen(os.dup(slave), "r")
    stdout = os.fdopen(os.dup(slave), "w")
    original = termios.tcgetattr(slave)
    handlers = {
        s: signal.getsignal(s) for s in (signal.SIGWINCH, signal.SIGTERM, signal.SIGHUP)
    }
    channel = Mock()
    channel.close.side_effect = close_failure
    try:
        monkeypatch.setattr("sys.stdin", stdin)
        monkeypatch.setattr("sys.stdout", stdout)
        monkeypatch.setattr(
            "pwncat.workspace.terminal.select.select",
            Mock(side_effect=KeyboardInterrupt),
        )
        with pytest.raises(KeyboardInterrupt):
            display(channel, Mock())
        restored = termios.tcgetattr(slave)
        # macOS sets PENDIN while returning to canonical mode; it is transient.
        restored[3] &= ~getattr(termios, "PENDIN", 0)
        original[3] &= ~getattr(termios, "PENDIN", 0)
        assert restored == original
        assert {s: signal.getsignal(s) for s in handlers} == handlers
        channel.close.assert_called_once()
    finally:
        stdin.close()
        stdout.close()
        os.close(slave)
        os.close(master)


@pytest.mark.parametrize(
    "address, options",
    [
        ("user@localhost:0", {}),
        ("user@localhost", {"port": 0}),
        ("user@local\nhost", {}),
        ("ssh://user%0a@host", {}),
    ],
)
def test_invalid_profile_values_are_not_silently_normalized(address, options):
    with pytest.raises(WorkspaceError):
        SSHProfile.parse(address, **options)


def test_reconnect_refuses_different_workspace_without_replaying_input(monkeypatch):
    from pwncat.workspace import ConnectionLost
    from pwncat.workspace.cli import interact
    from pwncat.workspace.model import WorkspaceRef

    backend = Mock()
    backend.ref = WorkspaceRef("test", "a" * 32, "1:100", "/private/socket")
    backend.display.side_effect = ConnectionLost("dropped")
    replacement = Mock()
    replacement.load.side_effect = IdentityMismatch("different server")
    connector = Mock()
    monkeypatch.setattr(
        "pwncat.workspace.cli.SSHConnection", Mock(return_value=connector)
    )
    monkeypatch.setattr(
        "pwncat.workspace.cli.TmuxWorkspace", Mock(return_value=replacement)
    )
    monkeypatch.setattr("pwncat.workspace.cli.time.sleep", Mock())
    with pytest.raises(IdentityMismatch):
        interact(backend, SSHProfile("localhost", "test"))
    replacement.load.assert_called_once_with("test", expected=backend.ref)
    replacement.display.assert_not_called()
    replacement.create.assert_not_called()
    connector.close.assert_called_once()


@pytest.mark.parametrize(
    "line",
    [
        "run",
        "select not-a-pane",
        "split diagonal",
        "window one two",
        "upload a /b --bad",
        "resume extra",
        "forward add 8080 other-host:8000",
        "forward add 8080 8000 extra",
        "forward add 8080 example.com 80",
        "forward add 8080 192.0.2.20 80 extra",
        "forward stop",
        "forward socks 1080",
        "forward reverse 8080 8000",
    ],
)
def test_console_rejects_unsupported_commands_before_remote_action(line):
    from pwncat.workspace.console import WorkspaceConsole

    backend = Mock()
    with pytest.raises(WorkspaceError):
        WorkspaceConsole(backend).execute(line)
    assert not backend.mock_calls


def test_console_missing_selected_pane_never_falls_back():
    from pwncat.workspace.console import ConsoleState, WorkspaceConsole

    backend = Mock()
    backend.pane.side_effect = WorkspaceError("Pane no longer exists")
    state = ConsoleState(selected="%7")
    with pytest.raises(WorkspaceError, match="no longer exists"):
        WorkspaceConsole(backend, state).execute("split")
    assert state.selected == "%7"
    backend.current_pane.assert_not_called()
    backend.split.assert_not_called()


def test_console_transfer_eof_reports_loss_instead_of_detaching(monkeypatch, capsys):
    from pwncat.workspace import ConnectionLost
    from pwncat.workspace.console import WorkspaceConsole

    backend = Mock()
    backend.current_pane.return_value = "%0"
    backend.connection.active.return_value = False
    console = WorkspaceConsole(backend)
    console.status = Mock()
    console.execute = Mock(side_effect=EOFError("transfer interrupted"))
    monkeypatch.setattr("builtins.input", Mock(return_value="upload a /b"))
    with pytest.raises(ConnectionLost, match="not replayed"):
        console.run()
    console.execute.assert_called_once_with("upload a /b")
    assert "transfer interrupted" in capsys.readouterr().out


def test_console_reconnect_keeps_local_state_without_replaying(monkeypatch, tmp_path):
    from pwncat.workspace import ConnectionLost
    from pwncat.workspace.cli import interact
    from pwncat.workspace.model import WorkspaceRef

    backend, replacement, connection = Mock(), Mock(), Mock()
    backend.ref = WorkspaceRef("test", "a" * 32, "1:100", "/private/socket")
    consoles = [Mock(), Mock()]
    consoles[0].run.side_effect = ConnectionLost("lost")
    consoles[1].run.return_value = "detach"
    states = []

    def console_factory(_backend, state):
        states.append(state)
        if len(states) == 1:
            state.local_directory = str(tmp_path)
            state.history.append_string("panes")
            state.color_mode = "on"
        return consoles[len(states) - 1]

    monkeypatch.setattr("pwncat.workspace.cli.WorkspaceConsole", console_factory)
    monkeypatch.setattr(
        "pwncat.workspace.cli.SSHConnection", Mock(return_value=connection)
    )
    monkeypatch.setattr(
        "pwncat.workspace.cli.TmuxWorkspace", Mock(return_value=replacement)
    )
    monkeypatch.setattr("pwncat.workspace.cli.time.sleep", Mock())
    interact(backend, SSHProfile("localhost", "test"), start_console=True)
    assert len(states) == 2 and states[0] is states[1]
    assert states[1].local_directory == str(tmp_path)
    assert states[1].history.get_strings() == ["panes"]
    assert states[1].color_mode == "on"
    for console in consoles:
        console.run.assert_called_once()
    replacement.load.assert_called_once_with("test", expected=backend.ref)
    replacement.create.assert_not_called()
