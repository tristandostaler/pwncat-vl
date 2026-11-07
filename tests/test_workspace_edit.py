"""Offline hostname edits preserve identity/history without reusing credentials."""

import json
import os
from dataclasses import replace
from unittest.mock import Mock

import pytest

from pwncat.workspace import WorkspaceError
from pwncat.workspace.cli import main, parser, resolve_connection
from pwncat.workspace.console_history import ConsoleHistory
from pwncat.workspace.credentials import CredentialStore, Secrets
from pwncat.workspace.model import WorkspaceRef
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.ssh import SSHProfile


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    for target in (
        "pwncat.workspace.cli.SSHConnection",
        "pwncat.workspace.cli.getpass.getpass",
        "pwncat.workspace.credentials.native_backend",
    ):
        monkeypatch.setattr(target, Mock(side_effect=AssertionError("not offline")))
    store = ProfileStore()
    saved = SavedWorkspace(
        "shortcut",
        SSHProfile(
            "old.example",
            "user",
            2222,
            str(tmp_path / "key"),
            str(tmp_path / "known_hosts"),
        ),
        True,
        True,
        WorkspaceRef("remote-name", "a" * 32, "1:100", "/home/user/socket"),
    )
    store.save(saved)
    return store, saved


@pytest.fixture
def credentials(workspace, monkeypatch):
    store, saved = workspace
    values = {}
    backend = Mock()
    backend.get_password.side_effect = lambda service, account: values.get(
        (service, account)
    )
    backend.set_password.side_effect = lambda service, account, value: values.update(
        {(service, account): value}
    )
    backend.delete_password.side_effect = lambda service, account: values.pop(
        (service, account), None
    )
    monkeypatch.setattr("pwncat.workspace.credentials.native_backend", lambda: backend)
    vault = CredentialStore(store.root, saved.alias, saved.connection)
    vault.write(Secrets("fixture-password", "fixture-passphrase"))
    saved = replace(saved, credential_ref=vault.reference)
    store.save(saved)
    return saved, backend, values


def test_edit_is_offline_and_retains_workspace_identity_and_settings(workspace, capsys):
    store, saved = workspace
    assert main(["edit", saved.alias, "--host", "NEW.example"]) == 0
    edited = store.get(saved.alias)
    assert edited.connection == replace(saved.connection, host="new.example")
    assert edited.ref == saved.ref
    assert edited.alias == saved.alias
    assert edited.password_prompt and edited.passphrase_prompt
    args = parser(saved_name=True).parse_args(["attach", saved.alias])
    alias, remote, connection, _password, _passphrase, expected = resolve_connection(
        args, store
    )
    assert (alias, remote, connection.host, expected) == (
        saved.alias,
        saved.ref.name,
        "new.example",
        saved.ref,
    )
    assert "Saved hostname" in capsys.readouterr().out
    assert main(["list"]) == 0
    assert "new.example" in capsys.readouterr().out
    if os.name != "nt":
        assert (store.root / "shortcut.json").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "hostname,expected",
    [
        ("localhost", "localhost"),
        ("NEW.example.", "new.example."),
        ("192.0.2.2", "192.0.2.2"),
        ("[2001:db8::2]", "2001:db8::2"),
        ("2001:0DB8::2", "2001:db8::2"),
        ("hôte.example", "xn--hte-kna.example"),
    ],
)
def test_hostname_forms(workspace, hostname, expected):
    store, saved = workspace
    assert main(["edit", saved.alias, "--host", hostname]) == 0
    assert store.get(saved.alias).connection.host == expected


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "user@host",
        "ssh://host",
        "host:2222",
        "host/path",
        "host?query",
        " host",
        "host\n",
        "host..example",
        "[host]",
        "[::1]:22",
        "host..",
        "-host",
        "a" * 64 + ".example",
    ],
)
def test_invalid_hostname_preserves_profile_and_credentials(
    workspace, credentials, hostname
):
    store, saved = workspace
    _saved, backend, _values = credentials
    original = (store.root / "shortcut.json").read_bytes()
    backend.reset_mock()
    assert main(["edit", saved.alias, "--host=" + hostname]) == 1
    assert (store.root / "shortcut.json").read_bytes() == original
    assert not backend.mock_calls


def test_unchanged_hostname_never_touches_credentials(workspace, credentials, capsys):
    store, saved = workspace
    _saved, backend, _values = credentials
    original = (store.root / "shortcut.json").read_bytes()
    backend.reset_mock()
    assert main(["edit", saved.alias, "--host", "OLD.example"]) == 0
    assert "unchanged" in capsys.readouterr().out
    assert (store.root / "shortcut.json").read_bytes() == original
    assert not backend.mock_calls


def test_edit_clears_old_vault_entry_and_preserves_prompt_preferences(
    workspace, credentials, capsys
):
    store, saved = workspace
    _saved, _backend, values = credentials
    assert main(["edit", saved.alias, "--host", "new.example"]) == 0
    assert not values
    edited = store.get(saved.alias)
    assert edited.credential_ref is None
    assert edited.password_prompt and edited.passphrase_prompt
    output = capsys.readouterr().out
    assert "--save-credentials" in output
    assert "fixture-password" not in output + (store.root / "shortcut.json").read_text()


def test_vault_failure_leaves_hostname_and_history_unchanged(
    workspace, credentials, capsys
):
    store, saved = workspace
    _saved, backend, values = credentials
    history = ConsoleHistory(store, saved.alias, saved.connection, saved.ref)
    history.record("help")
    original = (store.root / "shortcut.json").read_bytes()
    backend.delete_password.side_effect = RuntimeError("fixture-sensitive-error")
    assert main(["edit", saved.alias, "--host", "new.example"]) == 1
    assert (store.root / "shortcut.json").read_bytes() == original
    assert history.load() == ["help"]
    assert values
    assert "fixture-sensitive-error" not in capsys.readouterr().err


def test_failed_profile_publish_is_retryable_after_credential_removal(
    workspace, credentials, monkeypatch, capsys
):
    store, saved = workspace
    _saved, _backend, values = credentials
    original = (store.root / "shortcut.json").read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(
            "pwncat.workspace.profiles.os.replace",
            Mock(side_effect=OSError("disk full")),
        )
        assert main(["edit", saved.alias, "--host", "new.example"]) == 1
    assert (
        "Hostname was not updated, but saved credentials were removed"
        in capsys.readouterr().err
    )
    assert (store.root / "shortcut.json").read_bytes() == original
    assert not values
    assert not list(store.root.glob(".write-*"))
    assert main(["edit", saved.alias, "--host", "new.example"]) == 0
    assert store.get(saved.alias).credential_ref is None


def test_history_survives_repeated_edits_and_authentication_updates(workspace):
    store, saved = workspace
    # Profiles and histories written before this feature remain readable.
    path = store.root / "shortcut.json"
    document = json.loads(path.read_text())
    del document["history_binding"]
    path.write_text(json.dumps(document))
    history = ConsoleHistory(store, saved.alias, saved.connection, saved.ref)
    history.record("help")
    original = history.path.read_bytes()
    for hostname in ("new.example", "another.example"):
        assert main(["edit", saved.alias, "--host", hostname]) == 0
        edited = store.get(saved.alias)
        # Authentication saves reconstruct SavedWorkspace without the binding.
        store.save(
            SavedWorkspace(edited.alias, edited.connection, True, True, edited.ref)
        )
        restored = ConsoleHistory(store, saved.alias, edited.connection, edited.ref)
        assert restored.load() == ["help"]
        assert restored.path.read_bytes() == original
    restored.record("status")
    assert restored.load() == ["help", "status"]
    with pytest.raises(WorkspaceError, match="another destination"):
        history.record("panes")
    with pytest.raises(WorkspaceError, match="another destination"):
        store.save(saved)


def test_replacement_workspace_does_not_inherit_edited_workspace_history(workspace):
    store, saved = workspace
    ConsoleHistory(store, saved.alias, saved.connection, saved.ref).record("help")
    main(["edit", saved.alias, "--host", "new.example"])
    edited = store.get(saved.alias)
    replacement = replace(edited, ref=replace(edited.ref, uuid="b" * 32))
    store.save(replacement, replace_identity=True)
    assert store.get(saved.alias).history_binding is None
    assert (
        ConsoleHistory(
            store, saved.alias, replacement.connection, replacement.ref
        ).load()
        == []
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["edit", "missing", "--host", "new.example"],
        ["user@old.example", "edit", "shortcut", "--host", "new.example"],
        ["--save-credentials", "edit", "shortcut", "--host", "new.example"],
        ["--port", "2222", "edit", "shortcut", "--host", "new.example"],
    ],
)
def test_missing_alias_or_connection_options_do_not_change_profile(workspace, argv):
    store, _saved = workspace
    original = (store.root / "shortcut.json").read_bytes()
    assert main(argv) == 1
    assert (store.root / "shortcut.json").read_bytes() == original


def test_invalid_history_binding_is_rejected(workspace):
    _store, saved = workspace
    document = saved.document()
    document["history_binding"] = "not-a-binding"
    with pytest.raises(WorkspaceError, match="Invalid saved workspace"):
        SavedWorkspace.parse(document, saved.alias)
