"""First-use host confirmation and append-only trust storage."""

import io
import os
from unittest.mock import Mock

import paramiko
import pytest

from pwncat.workspace import WorkspaceError
from pwncat.workspace.hostkeys import (
    HostKeyPolicy,
    confirm_host_key,
    fingerprint,
    host_keys_path,
    save_host_key,
)


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture(scope="module")
def key():
    return paramiko.RSAKey.generate(1024)


def test_fingerprint_uses_openssh_sha256_format():
    key = Mock()
    key.asbytes.return_value = b"abc"
    assert fingerprint(key) == "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"


@pytest.mark.parametrize("answer", ["yes\n", "no\n", "y\n", "\n", ""])
def test_prompt_requires_explicit_yes(monkeypatch, capsys, tmp_path, key, answer):
    import sys

    monkeypatch.setattr(sys, "stdin", TerminalInput(answer))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    assert confirm_host_key("[host.example]:2222", key, tmp_path / "known_hosts") == (
        answer == "yes\n"
    )
    output = capsys.readouterr().err
    assert "[host.example]:2222" in output
    assert fingerprint(key) in output
    assert "ssh-rsa" in output
    assert "[yes/no]" in output


def test_piped_yes_cannot_accept_a_host_key(monkeypatch, tmp_path, key):
    import sys

    stdin = io.StringIO("yes\n")
    monkeypatch.setattr(sys, "stdin", stdin)
    with pytest.raises(WorkspaceError, match="interactive terminal"):
        confirm_host_key("host.example", key, tmp_path / "known_hosts")
    assert stdin.tell() == 0


@pytest.mark.parametrize("confirm", [None, lambda *_: False])
def test_no_approval_does_not_create_trust_file(tmp_path, key, confirm):
    path = tmp_path / "known_hosts"
    client = paramiko.SSHClient()
    with pytest.raises(WorkspaceError, match="host key"):
        HostKeyPolicy(path, confirm).missing_host_key(client, "host.example", key)
    assert not path.exists()
    assert len(client.get_host_keys()) == 0


def test_accepted_key_appends_without_rewriting_existing_entries(tmp_path, key):
    path = tmp_path / "ssh" / "known_hosts"
    save_host_key(path, "other.example", key)
    original = b"# Keep this comment\r\n" + path.read_bytes().rstrip(b"\n")
    path.write_bytes(original)
    client = paramiko.SSHClient()
    HostKeyPolicy(path, lambda *_: True).missing_host_key(
        client, "[host.example]:2222", key
    )
    assert path.read_bytes().startswith(original + b"\n")
    assert paramiko.HostKeys(str(path)).check("[host.example]:2222", key)
    assert client.get_host_keys().check("[host.example]:2222", key)
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
        assert path.parent.stat().st_mode & 0o077 == 0


def test_same_key_saved_during_confirmation_is_not_duplicated(tmp_path, key):
    path = tmp_path / "known_hosts"
    hashed = paramiko.HostKeys.hash_host("host.example")
    path.write_text(f"{hashed} {key.get_name()} {key.get_base64()}\n")
    original = path.read_bytes()
    save_host_key(path, "host.example", key)
    assert path.read_bytes() == original


def test_different_key_saved_during_confirmation_is_not_overwritten(tmp_path, key):
    path = tmp_path / "known_hosts"
    different = paramiko.RSAKey.generate(1024)
    save_host_key(path, "host.example", different)
    original = path.read_bytes()
    with pytest.raises(WorkspaceError, match="changed during confirmation"):
        save_host_key(path, "host.example", key)
    assert path.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions and symlinks")
def test_linked_or_writable_trust_file_is_preserved(tmp_path, key):
    actual, link = tmp_path / "actual", tmp_path / "link"
    actual.write_text("# preserved\n")
    link.symlink_to(actual)
    with pytest.raises(WorkspaceError, match="linked"):
        save_host_key(link, "host.example", key)
    actual.chmod(0o666)
    with pytest.raises(WorkspaceError, match="not writable by others"):
        save_host_key(actual, "host.example", key)
    assert actual.read_text() == "# preserved\n"


def test_default_known_hosts_path_uses_current_home(monkeypatch, tmp_path):
    from pathlib import Path

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert host_keys_path() == tmp_path / ".ssh" / "known_hosts"


def test_save_failure_does_not_trust_key_in_memory(monkeypatch, tmp_path, key):
    def fail(*_):
        raise OSError("read-only filesystem")

    monkeypatch.setattr("pwncat.workspace.hostkeys.os.open", fail)
    client = paramiko.SSHClient()
    with pytest.raises(WorkspaceError, match="Could not save"):
        HostKeyPolicy(tmp_path / "known_hosts", lambda *_: True).missing_host_key(
            client, "host.example", key
        )
    assert len(client.get_host_keys()) == 0
