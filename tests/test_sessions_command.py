"""Session listings tolerate an account missing from the user records."""

from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from pwncat.commands import sessions


@pytest.mark.parametrize("arguments", [[], ["--list"]])
@pytest.mark.parametrize("identity", [0, 1001, "S-1-5-21-100-200-300-1001", None])
def test_missing_username_keeps_every_session_visible(monkeypatch, arguments, identity):
    known = Mock(
        hash="known-host",
        current_user=Mock(return_value=SimpleNamespace(name="fixture-user")),
    )
    missing = Mock(hash="other-host", current_user=Mock(return_value=None))
    for session, uid in [(known, 1000), (missing, identity)]:
        session.platform = SimpleNamespace(
            name="linux" if isinstance(uid, int) else "windows",
            channel=Mock(),
            getuid=Mock(return_value=uid),
        )
    manager = SimpleNamespace(sessions={0: known, 1: missing}, target=missing)
    output = StringIO()
    monkeypatch.setattr(
        sessions, "console", Console(file=output, width=220, color_system=None)
    )
    command = sessions.Command(manager)

    command.run(manager, command.parser.parse_args(arguments))

    rendered = output.getvalue()
    assert "Active Sessions" in rendered
    assert "fixture-user" in rendered
    expected = "unknown" if identity is None else f"unknown (ID: {identity})"
    assert expected in rendered
    assert "known-host" in rendered and "other-host" in rendered
    assert "*1" in rendered
    assert manager.target is missing
    assert manager.sessions == {0: known, 1: missing}
    known.platform.getuid.assert_not_called()
    missing.platform.getuid.assert_called_once()
    for session in (known, missing):
        session.current_user.assert_called_once()
        session.close.assert_not_called()
        session.platform.channel.close.assert_not_called()


def test_empty_session_list_still_renders(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(sessions, "console", Console(file=output, color_system=None))
    manager = SimpleNamespace(sessions={}, target=None)
    command = sessions.Command(manager)
    command.run(manager, command.parser.parse_args([]))
    assert "Active Sessions" in output.getvalue()
