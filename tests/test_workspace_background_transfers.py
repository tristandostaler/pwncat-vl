"""Background transfers keep the console usable without sharing a shell channel."""

import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.commands.sessions import Command as SessionsCommand
from pwncat.workspace import WorkspaceError
from pwncat.workspace.background_transfers import BackgroundTransfers, progress_text
from pwncat.workspace.console import WorkspaceConsole
from pwncat.workspace.platform import WorkspaceChannel


def test_workspace_transfer_uses_separate_sftp_and_limits_concurrency(monkeypatch):
    from pwncat.workspace import background_transfers

    started, release = threading.Event(), threading.Event()
    sftp = Mock()
    connection = Mock(new_filesystem=Mock(return_value=sftp))
    session = SimpleNamespace(
        id=0, platform=SimpleNamespace(channel=WorkspaceChannel.__new__(WorkspaceChannel))
    )

    class SlowFiles:
        def __init__(self, opened):
            assert opened is sftp

        def upload(self, source, destination, *, overwrite, progress, status):
            status("copying", 12)
            progress(4)
            started.set()
            assert release.wait(2)
            return SimpleNamespace(size=12, sha256="abc")

    monkeypatch.setattr(background_transfers, "FileService", SlowFiles)
    redraw = Mock()
    transfers = BackgroundTransfers(on_update=redraw)
    transfers.start(session, connection, "upload", "/local", "/remote")
    assert started.wait(2)
    assert transfers.active()
    assert transfers.status().session_id == 0
    assert transfers.status().total == 12
    assert transfers.status().transferred == 4
    assert "33.3%" in progress_text(transfers.status())
    assert redraw.called
    with pytest.raises(WorkspaceError, match="already running"):
        transfers.start(session, connection, "download", "/remote", "/local")
    release.set()
    transfers._thread.join(timeout=2)
    assert transfers.status().state == "completed"
    assert transfers.status().size == 12
    assert transfers.status().sha256 == "abc"
    assert redraw.call_count >= 2  # Initial progress and completion.
    sftp.close.assert_called_once()
    connection.new_filesystem.assert_called_once()


def test_other_session_transfer_switches_to_workspace_shell_and_blocks_busy_selection(
    monkeypatch,
):
    from pwncat.workspace import session_files

    started, release = threading.Event(), threading.Event()

    def slow_upload(platform, source, destination, *, overwrite, progress, status):
        status("copying", 7)
        progress(3)
        started.set()
        assert release.wait(2)
        return SimpleNamespace(size=7, sha256="def")

    monkeypatch.setattr(session_files, "upload", slow_upload)
    workspace = SimpleNamespace(
        id=0, platform=SimpleNamespace(channel=WorkspaceChannel.__new__(WorkspaceChannel))
    )
    other = SimpleNamespace(id=1, platform=SimpleNamespace(channel=object()))
    manager = Mock(target=other, sessions={0: workspace, 1: other})
    backend = Mock()
    console = WorkspaceConsole(backend)
    console._manager = manager
    manager.workspace_console = console
    console.message = Mock()
    console.start_transfer("upload", "/local", "/remote")
    assert started.wait(2)
    assert manager.target is workspace
    assert console.transfers.busy_session(other)
    SessionsCommand(manager).run(
        manager, SimpleNamespace(list=False, kill=False, session_id=1)
    )
    assert manager.target is workspace
    release.set()
    console.transfers._thread.join(timeout=2)
    assert console.transfers.status().state == "completed"
    assert not console.transfers.busy_session(other)


def test_failed_transfer_is_reported_and_next_transfer_can_start(monkeypatch):
    from pwncat.workspace import session_files

    def fail(*args, **kwargs):
        raise OSError("remote file was removed")

    monkeypatch.setattr(session_files, "download", fail)
    session = SimpleNamespace(id=1, platform=SimpleNamespace(channel=object()))
    transfers = BackgroundTransfers()
    transfers.start(session, Mock(), "download", "/remote", "/local")
    transfers._thread.join(timeout=2)
    assert transfers.status().state == "failed"
    assert "remote file was removed" in transfers.status().error
    transfers.start(session, Mock(), "download", "/remote", "/local")
    transfers._thread.join(timeout=2)
    assert transfers.status().number == 2
