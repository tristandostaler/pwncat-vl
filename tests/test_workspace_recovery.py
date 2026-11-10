"""Saved shortcuts can reconnect after missing or stopped remote state."""

import errno
import os
from dataclasses import replace
from unittest.mock import Mock

import pytest
from test_workspace import LocalSFTP

from pwncat.workspace import (
    ConnectionLost,
    IdentityMismatch,
    OutcomeUnknown,
    WorkspaceError,
    WorkspaceMissing,
    WorkspaceStopped,
)
from pwncat.workspace.cli import main
from pwncat.workspace.model import WorkspaceRef
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.ssh import SSHProfile
from pwncat.workspace.state import StateStore
from pwncat.workspace.tmux import TmuxWorkspace


@pytest.mark.skipif(os.name == "nt", reason="POSIX filesystem fixture")
def test_missing_remote_directory_has_actionable_message(tmp_path):
    store = StateStore(LocalSFTP(), str(tmp_path), os.getuid())
    with pytest.raises(
        WorkspaceMissing, match="Remote workspace directory is missing"
    ) as error:
        store.load("lab")
    assert store.directory("lab") in str(error.value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX filesystem fixture")
def test_missing_manifest_preserves_existing_directory(tmp_path):
    store = StateStore(LocalSFTP(), str(tmp_path), os.getuid())
    directory = store.directory("lab")
    store.private_directory(store.root, create=True)
    store.private_directory(directory, create=True)
    with pytest.raises(WorkspaceError, match="metadata is missing") as error:
        store.load("lab")
    assert not isinstance(error.value, WorkspaceMissing)
    assert os.path.isdir(directory)


@pytest.fixture
def backend():
    instance = object.__new__(TmuxWorkspace)
    instance.load = Mock()
    instance.archive = Mock()
    instance.create = Mock()
    instance.store = Mock()
    instance.store.load.return_value = {"history": "private", "history_limit": 1234}
    return instance


def test_running_workspace_is_only_reattached(backend):
    expected = object()
    assert backend.attach_or_recover("lab", expected) is False
    backend.load.assert_called_once_with("lab", expected=expected)
    backend.create.assert_not_called()
    backend.archive.assert_not_called()


def test_missing_workspace_is_created_without_archiving(backend):
    backend.load.side_effect = WorkspaceMissing("missing directory")
    assert backend.attach_or_recover("lab", object()) is True
    backend.create.assert_called_once_with("lab")
    backend.archive.assert_not_called()


def test_stopped_workspace_is_archived_before_recreation(backend):
    expected = object()
    backend.load.side_effect = WorkspaceStopped("stopped")
    calls = Mock()
    calls.attach_mock(backend.archive, "archive")
    calls.attach_mock(backend.create, "create")
    assert backend.attach_or_recover("lab", expected) is True
    assert [call[0] for call in calls.mock_calls] == ["archive", "create"]
    backend.archive.assert_called_once_with("lab", expected=expected)
    backend.create.assert_called_once_with("lab", history="private", history_limit=1234)


@pytest.mark.parametrize(
    "failure",
    [
        IdentityMismatch("changed"),
        ConnectionLost("disconnected"),
        OutcomeUnknown("unknown"),
        WorkspaceError("invalid manifest"),
        PermissionError(errno.EACCES, "permission denied"),
    ],
)
def test_other_errors_never_recreate_a_workspace(backend, failure):
    backend.load.side_effect = failure
    with pytest.raises(type(failure)):
        backend.attach_or_recover("lab", object())
    backend.create.assert_not_called()
    backend.archive.assert_not_called()


def test_failed_archive_does_not_start_a_new_workspace(backend):
    backend.load.side_effect = WorkspaceStopped("stopped")
    backend.archive.side_effect = WorkspaceError("cannot verify stopped process")
    with pytest.raises(WorkspaceError, match="cannot verify"):
        backend.attach_or_recover("lab", object())
    backend.create.assert_not_called()


def test_invalid_recovery_settings_are_rejected_before_archive(backend):
    backend.load.side_effect = WorkspaceStopped("stopped")
    backend.store.load.return_value["history_limit"] = "invalid"
    with pytest.raises(WorkspaceError, match="Invalid saved history limit"):
        backend.attach_or_recover("lab", object())
    backend.archive.assert_not_called()
    backend.create.assert_not_called()


@pytest.mark.parametrize("action", ["attach", "console"])
def test_cli_recovery_updates_saved_identity_and_retains_credentials(
    tmp_path, monkeypatch, action
):
    from test_workspace_credentials import MemoryVault

    from pwncat.workspace.credentials import CredentialStore, Secrets

    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    vault_backend = MemoryVault()
    monkeypatch.setattr(
        "pwncat.workspace.credentials.native_backend", lambda: vault_backend
    )
    store = ProfileStore()
    profile = SSHProfile("example.invalid", "user")
    vault = CredentialStore(store.root, "lab", profile)
    vault.write(Secrets("fixture-password"))
    old = WorkspaceRef("remote", "a" * 32, "1:100", "/home/user/socket")
    new = replace(old, uuid="b" * 32, server_epoch="2:200")
    store.save(SavedWorkspace("lab", profile, True, False, old, vault.reference))
    connection = Mock()
    monkeypatch.setattr("pwncat.workspace.cli.SSHConnection", connection)
    backend = Mock(ref=new)
    backend.attach_or_recover.return_value = True
    monkeypatch.setattr(
        "pwncat.workspace.cli.TmuxWorkspace", Mock(return_value=backend)
    )
    interact = Mock()
    monkeypatch.setattr("pwncat.workspace.cli.interact", interact)
    monkeypatch.setattr(
        "pwncat.workspace.cli.getpass.getpass",
        Mock(side_effect=AssertionError("must reuse saved password")),
    )
    assert main([action, "lab"]) == 0
    backend.attach_or_recover.assert_called_once_with("remote", old)
    assert store.get("lab").ref == new
    assert store.get("lab").credential_ref == vault.reference
    assert vault.read(vault.reference).password == "fixture-password"
    assert connection.call_args.args[0].password == "fixture-password"
    interact.assert_called_once()
