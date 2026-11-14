"""Workspace transfers follow the active pwncat session."""

import os
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.commands.sessions import Command as SessionsCommand
from pwncat.workspace import WorkspaceError
from pwncat.workspace.console import transfer_selected
from pwncat.workspace.console_commands import DownloadCommand, UploadCommand
from pwncat.workspace.platform import WorkspaceChannel
from pwncat.workspace.session_files import _publish, _regular, download, upload


class LocalPlatform:
    """Exercise the pwncat platform contract against a disposable directory."""

    name = "linux"
    Path = Path

    def __init__(self):
        self.channel = object()

    @staticmethod
    def lstat(path):
        return os.lstat(path)

    @staticmethod
    def open(path, mode):
        return open(path, mode)

    @staticmethod
    def mkdir(path, mode):
        os.mkdir(path, mode)

    @staticmethod
    def chmod(path, mode):
        os.chmod(path, mode)

    @staticmethod
    def link_to(source, target):
        os.link(source, target)

    @staticmethod
    def rename(source, target):
        os.replace(source, target)

    @staticmethod
    def unlink(path):
        os.unlink(path)

    @staticmethod
    def rmdir(path):
        os.rmdir(path)


def test_upload_and_download_follow_session_selection(tmp_path):
    source = tmp_path / "local.bin"
    remote = tmp_path / "other-host.bin"
    copy = tmp_path / "copy.bin"
    source.write_bytes(bytes(range(256)) * 20)
    workspace = SimpleNamespace(id=0, platform=SimpleNamespace(channel=object()))
    selected = SimpleNamespace(id=1, platform=LocalPlatform())
    manager = Mock(
        sessions={0: workspace, 1: selected},
        target=workspace,
        workspace_console=SimpleNamespace(
            local_path=lambda value: value, transfers=None, modules=None
        ),
        workspace_backend=Mock(),
        workspace_state=Mock(),
    )
    SessionsCommand(manager).run(
        manager, SimpleNamespace(list=False, kill=False, session_id=1)
    )
    assert manager.target is selected
    UploadCommand(manager).run(
        manager,
        SimpleNamespace(source=str(source), destination=str(remote), overwrite=False),
    )
    assert remote.read_bytes() == source.read_bytes()
    manager.workspace_backend.connection.filesystem.assert_not_called()
    DownloadCommand(manager).run(
        manager,
        SimpleNamespace(source=str(remote), destination=str(copy), overwrite=False),
    )
    assert copy.read_bytes() == source.read_bytes()


def test_workspace_session_keeps_sftp_route(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "pwncat.workspace.console.transfer",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    backend = Mock()
    manager = Mock(target=SimpleNamespace(platform=SimpleNamespace(
        channel=WorkspaceChannel.__new__(WorkspaceChannel)
    )))
    transfer_selected(manager, backend, "upload", "/local", "/remote")
    assert calls[0][0][:4] == (backend, "upload", "/local", "/remote")


def test_missing_active_session_never_falls_back_to_workspace_host():
    with pytest.raises(WorkspaceError, match="Select an active session"):
        transfer_selected(Mock(target=None), Mock(), "upload", "/local", "/remote")


def test_selected_upload_preserves_existing_file_and_cleans_failed_stage(tmp_path):
    platform = LocalPlatform()
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"new bytes")
    destination.write_bytes(b"old bytes")
    with pytest.raises(WorkspaceError, match="Destination exists"):
        upload(platform, str(source), str(destination))
    assert destination.read_bytes() == b"old bytes"
    assert not list(tmp_path.glob(".pwncat-upload-*"))
    upload(platform, str(source), str(destination), overwrite=True)
    assert destination.read_bytes() == b"new bytes"
    assert not list(tmp_path.glob(".pwncat-upload-*"))


def test_selected_upload_hash_failure_does_not_publish(tmp_path):
    class CorruptPlatform(LocalPlatform):
        @staticmethod
        def open(path, mode):
            if mode == "rb" and ".pwncat-upload-" in path:
                from io import BytesIO

                return BytesIO(b"corrupt")
            return open(path, mode)

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"correct")
    with pytest.raises(WorkspaceError, match="verification failed"):
        upload(CorruptPlatform(), str(source), str(destination))
    assert not destination.exists()
    assert not list(tmp_path.glob(".pwncat-upload-*"))


def test_selected_upload_waits_for_remote_writer_before_chmod(tmp_path):
    class SingleCommandPlatform(LocalPlatform):
        writing = False

        @contextmanager
        def open(self, path, mode):
            if mode == "wb":
                self.writing = True
            try:
                with open(path, mode) as stream:
                    yield stream
            finally:
                if mode == "wb":
                    self.writing = False

        def chmod(self, path, mode):
            assert not self.writing, "another command ran while the writer was active"
            os.chmod(path, mode)

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"selected session bytes")
    upload(SingleCommandPlatform(), str(source), str(destination))
    assert destination.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("direction", ["upload", "download"])
def test_selected_session_transfer_reports_bytes_and_verification_phase(tmp_path, direction):
    source, destination = tmp_path / "source", tmp_path / "destination"
    source.write_bytes(bytes(range(256)) * 300)
    counts, phases = [], []
    result = (upload if direction == "upload" else download)(
        LocalPlatform(), str(source), str(destination),
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


def test_selected_upload_repairs_unsearchable_stage_before_writing(tmp_path):
    class RestrictivePlatform(LocalPlatform):
        @staticmethod
        def mkdir(path, mode):
            os.mkdir(path, 0o600)

        @staticmethod
        def open(path, mode):
            if mode == "wb":
                assert os.stat(os.path.dirname(path)).st_mode & 0o100
            return open(path, mode)

    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.write_bytes(b"private upload")
    upload(RestrictivePlatform(), str(source), str(destination))
    assert destination.read_bytes() == source.read_bytes()
    assert not list(tmp_path.glob(".pwncat-upload-*"))


def test_selected_download_preserves_local_file_without_overwrite(tmp_path):
    platform = LocalPlatform()
    source = tmp_path / "remote"
    destination = tmp_path / "local"
    source.write_bytes(b"remote bytes")
    destination.write_bytes(b"local bytes")
    with pytest.raises(WorkspaceError, match="Local destination exists"):
        download(platform, str(source), str(destination))
    assert destination.read_bytes() == b"local bytes"
    download(platform, str(source), str(destination), overwrite=True)
    assert destination.read_bytes() == b"remote bytes"


def test_windows_replacement_keeps_backup_until_new_file_is_published():
    temporary = PureWindowsPath("C:/temp/.stage/data")
    remote = PureWindowsPath("C:/temp/file.bin")
    platform = Mock(name="windows")
    platform.name = "windows"
    platform.stat.return_value = SimpleNamespace(st_mode=0)
    _publish(platform, temporary, remote, True)
    assert platform.rename.call_count == 2
    first = platform.rename.call_args_list[0].args
    second = platform.rename.call_args_list[1].args
    assert first[0] == str(remote) and first[1].startswith(".pwncat-backup-")
    assert second == (str(temporary), remote.name)
    assert platform.unlink.call_args.args[0].endswith(first[1])


def test_windows_replacement_rolls_back_on_publish_failure():
    temporary = PureWindowsPath("C:/temp/.stage/data")
    remote = PureWindowsPath("C:/temp/file.bin")
    platform = Mock(name="windows")
    platform.name = "windows"
    platform.stat.return_value = SimpleNamespace(st_mode=0)
    platform.rename.side_effect = [None, OSError("publish failed"), None]
    with pytest.raises(OSError, match="publish failed"):
        _publish(platform, temporary, remote, True)
    calls = platform.rename.call_args_list
    assert calls[2].args[0].endswith(calls[0].args[1])
    assert calls[2].args[1] == remote.name
    platform.unlink.assert_not_called()


def test_windows_archive_attribute_is_treated_as_regular_file():
    platform = SimpleNamespace(name="windows")
    assert _regular(platform, SimpleNamespace(st_file_attributes=0x20))
    assert not _regular(platform, SimpleNamespace(st_file_attributes=0x400))
