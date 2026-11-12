"""Live local workspace clients can be parked and reattached by identity."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.workspace import WorkspaceError
from pwncat.workspace import local_screen


def test_screen_name_is_stable_and_scoped_to_connection():
    connection = SimpleNamespace(host="server.example", user="user", port=22)
    name = local_screen.session_name("lab", connection, "lab")
    assert name == local_screen.session_name("lab", connection, "lab")
    assert name != local_screen.session_name(
        "lab", SimpleNamespace(host="other.example", user="user", port=22), "lab"
    )


def test_existing_screen_lookup_requires_exact_name(monkeypatch):
    output = "There is a screen on:\n\t123.pwncat-lab-abcd\t(Detached)\n\t456.pwncat-lab-abcd-old\t(Attached)\n"
    monkeypatch.setattr(local_screen.subprocess, "run", Mock(return_value=SimpleNamespace(stdout=output)))
    assert local_screen._existing("screen", "pwncat-lab-abcd") == (
        "123.pwncat-lab-abcd", "Detached"
    )


def test_detached_client_is_reattached_without_starting_another(monkeypatch):
    monkeypatch.setattr(local_screen.shutil, "which", lambda _: "/usr/bin/screen")
    monkeypatch.setattr(local_screen, "_existing", lambda *_: ("123.pwncat-lab", "Detached"))
    call = Mock(return_value=0)
    monkeypatch.setattr(local_screen.subprocess, "call", call)
    connection = SimpleNamespace(host="server.example", user="user", port=22)
    assert local_screen.attach_or_start(["attach", "lab"], "lab", connection, "lab") == 0
    command = call.call_args.args[0]
    assert command[:2] == ["/usr/bin/screen", "-c"]
    assert command[-2:] == ["-r", "123.pwncat-lab"]


def test_attached_client_requires_takeover(monkeypatch):
    monkeypatch.setattr(local_screen.shutil, "which", lambda _: "/usr/bin/screen")
    monkeypatch.setattr(local_screen, "_existing", lambda *_: ("123.pwncat-lab", "Attached"))
    connection = SimpleNamespace(host="server.example", user="user", port=22)
    with pytest.raises(WorkspaceError, match="--takeover"):
        local_screen.attach_or_start(["attach", "lab"], "lab", connection, "lab")
    call = Mock(return_value=0)
    monkeypatch.setattr(local_screen.subprocess, "call", call)
    local_screen.attach_or_start(["attach", "lab"], "lab", connection, "lab", takeover=True)
    command = call.call_args.args[0]
    assert command[:2] == ["/usr/bin/screen", "-c"]
    assert command[-3:] == ["-d", "-r", "123.pwncat-lab"]


def test_new_client_runs_inside_screen_with_inner_marker(monkeypatch):
    monkeypatch.setattr(local_screen.shutil, "which", lambda _: "/usr/bin/screen")
    monkeypatch.setattr(local_screen, "_existing", lambda *_: None)
    call = Mock(return_value=0)
    monkeypatch.setattr(local_screen.subprocess, "call", call)
    connection = SimpleNamespace(host="server.example", user="user", port=22)
    local_screen.attach_or_start(["attach", "lab"], "lab", connection, "lab")
    command = call.call_args.args[0]
    assert command[:2] == ["/usr/bin/screen", "-c"]
    assert command[3:5] == ["-m", "-S"]
    assert command[-4:] == ["-m", "pwncat.workspace.screen_client", "attach", "lab"]
    assert call.call_args.kwargs["env"][local_screen.INNER] == "1"


def test_screen_uses_short_compatible_term_for_long_terminal_name(monkeypatch):
    original = "rxvt-unicode-256color"
    monkeypatch.setenv("TERM", original)
    monkeypatch.setattr(local_screen.shutil, "which", lambda _: "/usr/bin/screen")
    monkeypatch.setattr(local_screen, "_existing", lambda *_: None)
    call = Mock(return_value=0)
    monkeypatch.setattr(local_screen.subprocess, "call", call)
    connection = SimpleNamespace(host="server.example", user="user", port=22)

    local_screen.attach_or_start(["new", "lab"], "lab", connection, "lab")

    assert call.call_args.kwargs["env"]["TERM"] == "xterm-256color"
    assert local_screen.os.environ["TERM"] == original


def test_park_detaches_only_the_current_screen(monkeypatch):
    monkeypatch.setenv(local_screen.INNER, "1")
    monkeypatch.setenv("STY", "123.pwncat-lab")
    monkeypatch.setattr(local_screen.shutil, "which", lambda _: "/usr/bin/screen")
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(local_screen.subprocess, "run", run)
    local_screen.park()
    run.assert_called_once_with(
        ["/usr/bin/screen", "-S", "123.pwncat-lab", "-X", "detach"],
        capture_output=True, text=True, timeout=5,
    )


def test_attach_reattaches_local_client_before_ssh_authentication(monkeypatch):
    from pwncat.workspace import cli

    connection = SimpleNamespace(host="server.example", user="user", port=22)
    monkeypatch.setattr(cli, "ProfileStore", lambda: object())
    monkeypatch.setattr(cli, "resolve_connection", lambda *_: (
        "lab", "lab", connection, False, False, None,
    ))
    monkeypatch.setattr(cli.local_screen, "available", lambda: True)
    attach = Mock(return_value=0)
    monkeypatch.setattr(cli.local_screen, "attach_or_start", attach)
    authenticate = Mock(side_effect=AssertionError("SSH authentication must not run"))
    monkeypatch.setattr(cli, "authenticate_profile", authenticate)
    assert cli.main(["attach", "lab"]) == 0
    attach.assert_called_once_with(
        ["attach", "lab"], "lab", connection, "lab", takeover=False, new=False,
    )
    authenticate.assert_not_called()
