"""Private console history across launches without recording failed input."""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from unittest.mock import Mock

import pytest

from pwncat.workspace import IdentityMismatch, WorkspaceError
from pwncat.workspace.console import ConsoleState, WorkspaceConsole
from pwncat.workspace.console_history import ConsoleHistory
from pwncat.workspace.model import WorkspaceRef
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.ssh import SSHProfile


@pytest.fixture
def history(tmp_path, monkeypatch):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    store = ProfileStore()
    saved = SavedWorkspace(
        "lab",
        SSHProfile("host.example", "user"),
        False,
        False,
        WorkspaceRef("lab", "a" * 32, "1:100", "/home/user/socket"),
    )
    store.save(saved)
    return store, saved, ConsoleHistory(store, "lab", saved.connection, saved.ref)


def make_console(saved, history):
    backend = Mock()
    backend.ref = saved.ref
    backend.current_pane.return_value = "%0"
    console = WorkspaceConsole(backend, ConsoleState(history_store=history))
    console.status = Mock()
    return console


def test_successful_commands_return_in_a_new_console(history, monkeypatch):
    store, saved, disk = history
    first = make_console(saved, disk)
    first.execute("help")
    first.execute("color off")
    assert first.execute("detach") == "detach"
    second = make_console(
        saved, ConsoleHistory(store, "lab", saved.connection, saved.ref)
    )
    monkeypatch.setattr(second, "_run_pwncat_console", Mock(return_value="detach"))
    assert second.run() == "detach"
    assert second.state.history.get_strings() == ["help", "color off", "detach"]
    assert second.run() == "detach"
    assert second.state.history.get_strings() == ["help", "color off", "detach"]
    if os.name != "nt":
        assert disk.path.stat().st_mode & 0o077 == 0
        assert store.root.stat().st_mode & 0o077 == 0
    assert store.names() == ["lab"]


def test_failed_or_private_input_is_not_written(history):
    _store, saved, disk = history
    console = make_console(saved, disk)
    with pytest.raises(WorkspaceError):
        console.execute("fixture-password-that-is-not-a-command")
    with pytest.raises(WorkspaceError):
        console.execute("help nonexistent")
    console.execute(
        " help"
    )  # Leading space deliberately keeps it out of saved history.
    assert not disk.path.exists()
    console.execute("help")
    assert disk.load() == ["help"]
    assert "fixture-password" not in disk.path.read_text()


def test_history_write_failure_does_not_turn_success_into_a_failed_command(
    history, monkeypatch, capsys
):
    _store, saved, disk = history
    disk.record("help")
    original = disk.path.read_bytes()
    console = make_console(saved, disk)
    monkeypatch.setattr(
        "pwncat.workspace.console_history.os.replace",
        Mock(side_effect=OSError("disk full")),
    )
    assert console.execute("color off") is None
    assert console.state.color_mode == "off"
    assert console.state.history_store is None
    assert (
        "Command completed, but console history could not be saved"
        in capsys.readouterr().out
    )
    assert disk.path.read_bytes() == original
    assert not list(disk.path.parent.glob(".history-write-*"))


def test_history_merge_from_multiple_clients_does_not_lose_entries(history):
    store, saved, disk = history
    commands = [
        f"help {command}"
        for command in ("panes", "split", "upload", "download", "status")
    ]
    histories = [
        ConsoleHistory(store, "lab", saved.connection, saved.ref) for _ in commands
    ]
    with ThreadPoolExecutor(max_workers=5) as workers:
        list(
            workers.map(lambda pair: pair[0].record(pair[1]), zip(histories, commands))
        )
    assert sorted(disk.load()) == sorted(commands)


def test_history_is_bounded_and_adjacent_duplicates_are_collapsed(history, monkeypatch):
    _store, _saved, disk = history
    monkeypatch.setattr("pwncat.workspace.console_history.MAX_COMMANDS", 3)
    for line in ["help", "panes", "status", "color off", "color off"]:
        disk.record(line)
    assert disk.load() == ["panes", "status", "color off"]


def test_history_byte_limit_counts_escaped_unicode(history, monkeypatch):
    _store, _saved, disk = history
    monkeypatch.setattr("pwncat.workspace.console_history.MAX_BYTES", 2048)
    commands = ["window " + "é" * 60 + str(index) for index in range(20)]
    for line in commands:
        disk.record(line)
    retained = disk.load()
    assert disk.path.stat().st_size <= 2048
    assert 0 < len(retained) < len(commands)
    assert retained[-1] == commands[-1]


def test_reused_alias_does_not_inherit_another_workspace_history(history):
    store, saved, disk = history
    disk.record("help")
    new = replace(saved, ref=replace(saved.ref, uuid="b" * 32))
    store.save(new, replace_identity=True)
    with pytest.raises(IdentityMismatch):
        disk.load()
    replacement = ConsoleHistory(store, "lab", new.connection, new.ref)
    assert replacement.load() == []
    replacement.record("panes")
    assert replacement.load() == ["panes"]


def test_forget_removes_console_history(history):
    store, _saved, disk = history
    disk.record("help")
    store.forget("lab")
    assert not disk.path.exists()
    assert store.get("lab") is None


def test_corrupt_history_is_preserved_and_console_still_opens(
    history, monkeypatch, capsys
):
    _store, saved, disk = history
    disk.record("help")
    disk.path.write_text("{invalid json")
    console = make_console(saved, disk)
    monkeypatch.setattr(console, "_run_pwncat_console", Mock(return_value="detach"))
    assert console.run() == "detach"
    assert console.state.history_store is None
    assert "Console history could not be loaded" in capsys.readouterr().out
    assert disk.path.read_text() == "{invalid json"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink creation and permissions")
def test_linked_history_is_not_read_or_overwritten(history, tmp_path):
    _store, _saved, disk = history
    external = tmp_path / "external"
    external.write_text("preserved")
    disk.path.symlink_to(external)
    with pytest.raises(WorkspaceError, match="private"):
        disk.load()
    with pytest.raises(WorkspaceError, match="private"):
        disk.record("help")
    assert external.read_text() == "preserved"
