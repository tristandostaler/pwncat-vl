"""Portable credential/entrypoint tests; no real vault access unless opted in."""

import json
import os
import subprocess
import sys
import uuid
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.workspace import WorkspaceError
from pwncat.workspace.cli import main
from pwncat.workspace.credentials import CredentialStore, Secrets, native_backend
from pwncat.workspace.model import WorkspaceRef
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.ssh import SSHProfile


class MemoryVault:
    """Test double only; production never selects this backend."""

    priority = 5

    def __init__(self):
        self.values = {}

    def get_password(self, service, account):
        return self.values.get((service, account))

    def set_password(self, service, account, value):
        self.values[service, account] = value

    def delete_password(self, service, account):
        self.values.pop((service, account), None)


@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    backend = MemoryVault()
    monkeypatch.setattr("pwncat.workspace.credentials.native_backend", lambda: backend)
    return backend


def test_secret_roundtrip_is_bound_to_profile_and_redacted(vault, tmp_path):
    profile = SSHProfile("example.invalid", "test", 2222)
    store = CredentialStore(tmp_path, "lab", profile)
    secret = Secrets("fixture-password", "fixture-passphrase")
    store.write(secret)
    assert store.read(store.reference) == secret
    assert "fixture" not in repr(secret)
    other = CredentialStore(tmp_path, "lab", replace(profile, host="other.invalid"))
    with pytest.raises(WorkspaceError, match="different connection"):
        other.read(store.reference)
    store.delete(store.reference)
    assert not vault.values


@pytest.mark.parametrize(
    "operation", ["get_password", "set_password", "delete_password"]
)
def test_vault_errors_never_expose_secret_arguments(vault, tmp_path, operation):
    store = CredentialStore(tmp_path, "lab", SSHProfile("example.invalid", "test"))
    store.write(Secrets("fixture-sensitive"))
    setattr(vault, operation, Mock(side_effect=RuntimeError("fixture-sensitive")))
    with pytest.raises(WorkspaceError) as error:
        if operation == "set_password":
            store.write(Secrets("fixture-sensitive"))
        else:
            store.delete(store.reference)
    assert "fixture-sensitive" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize(
    "platform,module,name",
    [
        ("darwin", "keyring.backends.macOS", "Keyring"),
        ("win32", "keyring.backends.Windows", "WinVaultKeyring"),
        ("linux", "keyring.backends.SecretService", "Keyring"),
    ],
)
def test_native_backend_selection_is_explicit(monkeypatch, platform, module, name):
    calls = []

    def load(value):
        calls.append(value)
        if value != module:
            raise ImportError
        return SimpleNamespace(**{name: MemoryVault})

    monkeypatch.setattr("pwncat.workspace.credentials.sys.platform", platform)
    monkeypatch.setattr("pwncat.workspace.credentials.importlib.import_module", load)
    assert type(native_backend()) is MemoryVault
    assert module in calls
    assert all(value.startswith("keyring.backends.") for value in calls)


def test_kwallet_does_not_migrate_other_applications(monkeypatch):
    migration = Mock(side_effect=AssertionError("must not touch other applications"))

    class Wallet(MemoryVault):
        _migrate = migration

    def load(module):
        if module.endswith("kwallet"):
            return SimpleNamespace(DBusKeyring=Wallet)
        raise ImportError

    monkeypatch.setattr("pwncat.workspace.credentials.sys.platform", "linux")
    monkeypatch.setattr("pwncat.workspace.credentials.importlib.import_module", load)
    native_backend()._migrate("pwncat-fixture")
    migration.assert_not_called()


def test_unavailable_native_store_has_no_plaintext_fallback(monkeypatch):
    monkeypatch.setattr(
        "pwncat.workspace.credentials.importlib.import_module",
        Mock(side_effect=ImportError),
    )
    with pytest.raises(WorkspaceError, match="No plaintext fallback"):
        native_backend()


def test_forget_credentials_removes_vault_item_and_retains_profile(vault):
    store = ProfileStore()
    connection = SSHProfile("example.invalid", "test")
    credentials = CredentialStore(store.root, "lab", connection)
    credentials.write(Secrets("fixture-password"))
    saved = SavedWorkspace(
        "lab",
        connection,
        True,
        False,
        WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket"),
        credentials.reference,
    )
    store.save(saved)
    raw = (store.root / "lab.json").read_text()
    assert "fixture-password" not in raw
    assert json.loads(raw)["credential_ref"] == credentials.reference
    assert main(["forget-credentials", "lab"]) == 0
    assert not vault.values
    assert store.get("lab").credential_ref is None
    assert store.get("lab").password_prompt


def test_forget_fails_without_deleting_profile_if_vault_deletion_fails(vault):
    store = ProfileStore()
    connection = SSHProfile("example.invalid", "test")
    credentials = CredentialStore(store.root, "lab", connection)
    credentials.write(Secrets("fixture-password"))
    store.save(
        SavedWorkspace(
            "lab",
            connection,
            True,
            False,
            WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket"),
            credentials.reference,
        )
    )
    vault.delete_password = Mock(side_effect=RuntimeError("denied"))
    assert main(["forget", "lab"]) == 1
    assert store.get("lab").credential_ref == credentials.reference


def test_saving_credentials_does_not_use_a_disabled_backend_or_prompt_first(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    monkeypatch.setattr(
        "pwncat.workspace.credentials.native_backend",
        Mock(side_effect=WorkspaceError("vault unavailable")),
    )
    prompt, connection = Mock(), Mock()
    monkeypatch.setattr("pwncat.workspace.cli.getpass.getpass", prompt)
    monkeypatch.setattr("pwncat.workspace.cli.SSHConnection", connection)
    assert (
        main(
            ["test@example.invalid", "new", "lab", "--save-credentials", "--no-attach"]
        )
        == 1
    )
    prompt.assert_not_called()
    connection.assert_not_called()


def test_profile_publish_failure_does_not_write_a_secret(vault, monkeypatch):
    from pwncat.workspace.cli import remember_connection

    store = ProfileStore()
    base = SSHProfile("example.invalid", "test")
    actual = replace(base, password="fixture-password")
    credentials = CredentialStore(store.root, "lab", base)
    monkeypatch.setattr(store, "save", Mock(side_effect=OSError("disk full")))
    with pytest.raises(OSError):
        remember_connection(
            store,
            "lab",
            base,
            WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket"),
            actual,
            True,
            False,
            credentials.reference,
            credentials,
        )
    assert not vault.values


def test_entrypoint_does_not_import_legacy_posix_modules():
    program = """
import sys
import pwncat.__main__ as entry
sys.argv = ['pwncat-vl', 'workspace', 'attach', '--help']
try:
    entry.main()
except SystemExit as exc:
    assert exc.code == 0
assert 'pwncat.manager' not in sys.modules
assert 'pwncat.util' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(
    not os.environ.get("PWNCAT_TEST_NATIVE_CREDENTIALS"),
    reason="Native vault tests require explicit opt-in",
)
def test_native_vault_with_disposable_fixture(tmp_path):
    profile = SSHProfile("example.invalid", "fixture")
    store = CredentialStore(tmp_path, "fixture-" + uuid.uuid4().hex[:16], profile)
    secret = Secrets("disposable-fixture-" + uuid.uuid4().hex)
    try:
        store.write(secret)
        assert store.read(store.reference) == secret
    finally:
        store.delete(store.reference)


def test_windows_bridge_restores_terminal_after_local_shortcut(monkeypatch):
    from contextlib import nullcontext

    from prompt_toolkit.key_binding.key_processor import KeyPress
    from prompt_toolkit.keys import Keys

    from pwncat.workspace.windows_terminal import display

    incoming, outgoing, channel = Mock(), Mock(), Mock()
    incoming.raw_mode.return_value = nullcontext()
    incoming.read_keys.return_value = [
        KeyPress(Keys.ControlG, "\x07"),
        KeyPress("p", "p"),
    ]
    outgoing.get_size.return_value = SimpleNamespace(columns=100, rows=30)
    channel.recv_ready.return_value = False
    channel.exit_status_ready.return_value = False
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(
        "pwncat.workspace.windows_terminal.terminal_devices",
        lambda: (incoming, outgoing),
    )
    assert display(channel, Mock()) == "palette"
    incoming.close.assert_called_once()
    channel.close.assert_called_once()
    channel.sendall.assert_not_called()
    channel.resize_pty.assert_called_once_with(width=100, height=30)
    assert "\x1b[?1049l" in outgoing.write_raw.call_args.args[0]
