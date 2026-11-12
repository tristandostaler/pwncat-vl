"""Workspace listener and reverse-forward definitions survive client restarts."""

import io
import socket
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.commands.listener_new import Command as ListenCommand
from pwncat.commands.listeners import Command as ListenersCommand
from pwncat.manager import ListenerState, Manager
from pwncat.workspace import WorkspaceError
from pwncat.workspace.console import ConsoleState, WorkspaceConsole
from pwncat.workspace.forwarding import ReverseForwardStatus
from pwncat.workspace.model import ListenerRule, ReverseForwardRule, WorkspaceRef
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.saved_forwards import SavedForwards, SavedListeners
from pwncat.workspace.ssh import SSHProfile


@pytest.fixture
def saved(tmp_path, monkeypatch):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    profile = SavedWorkspace(
        "lab", SSHProfile("server.example", "test"), False, False,
        WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket"),
    )
    store = ProfileStore()
    store.save(profile)
    return store, profile


def test_legacy_profile_and_new_rules_are_validated(saved):
    _store, profile = saved
    document = profile.document()
    document.pop("reverse_forwards")
    document.pop("listeners")
    parsed = SavedWorkspace.parse(document, "lab")
    assert parsed.reverse_forwards == () and parsed.listeners == ()
    document["reverse_forwards"] = [{"remote_port": 4444, "local_port": 4444, "bind_ip": "0.0.0.0"}]
    document["listeners"] = [{"host": "127.0.0.1", "port": 4444}]
    parsed = SavedWorkspace.parse(document, "lab")
    assert parsed.reverse_forwards == (ReverseForwardRule(4444, 4444, "0.0.0.0"),)
    assert parsed.listeners == (ListenerRule("127.0.0.1", 4444),)
    document["reverse_forwards"].append({"remote_port": 5555, "local_port": 6666, "bind_ip": "127.0.0.1"})
    assert len(SavedWorkspace.parse(document, "lab").reverse_forwards) == 2
    document["reverse_forwards"][1]["remote_port"] = 4444
    with pytest.raises(WorkspaceError, match="Invalid saved"):
        SavedWorkspace.parse(document, "lab")
    document["reverse_forwards"].pop()
    document["reverse_forwards"][0]["bind_ip"] = "192.0.2.1"
    with pytest.raises(WorkspaceError, match="Invalid saved"):
        SavedWorkspace.parse(document, "lab")


def test_reverse_forward_is_saved_restored_and_removed(saved):
    store, profile = saved
    settings = SavedForwards(store, "lab", profile.connection, profile.ref)
    manager = Mock()
    manager.list.return_value = []
    entry = ReverseForwardStatus(4444, 5555, "0.0.0.0", True, 0, None)
    manager.add.return_value = entry
    backend = Mock()
    backend.connection.reverse_forwards.return_value = manager
    console = WorkspaceConsole(backend, ConsoleState(forward_settings=settings))
    console.reverse_forward(["add", "4444", "5555", "0.0.0.0"])
    assert store.get("lab").reverse_forwards == (ReverseForwardRule(4444, 5555, "0.0.0.0"),)

    fresh = SavedForwards(ProfileStore(), "lab", profile.connection, profile.ref)
    assert "Restored reverse forward" in fresh.restore_reverse(manager)[0]
    manager.add.assert_called_with(4444, 5555, bind_ip="0.0.0.0")
    manager.list.return_value = [entry]
    console.reverse_forward(["stop", "4444"])
    assert store.get("lab").reverse_forwards == ()
    manager.stop.assert_called_once_with(4444)
    assert fresh.restore_reverse(manager) == []


def test_multiple_reverse_rules_are_saved_and_removed_independently(saved):
    store, profile = saved
    first = ReverseForwardRule(4444, 5555)
    second = ReverseForwardRule(6666, 7777)
    store.remember_reverse("lab", profile.connection, profile.ref, first)
    store.remember_reverse("lab", profile.connection, profile.ref, second)
    assert ProfileStore().get("lab").reverse_forwards == (first, second)
    manager = Mock()
    manager.list.return_value = []
    manager.add.side_effect = [
        ReverseForwardStatus(4444, 5555, "127.0.0.1", True, 0, None),
        ReverseForwardStatus(6666, 7777, "127.0.0.1", True, 0, None),
    ]
    messages = SavedForwards(store, "lab", profile.connection, profile.ref).restore_reverse(manager)
    assert len(messages) == 2
    assert manager.add.call_count == 2
    store.forget_reverse("lab", profile.connection, profile.ref, 4444)
    assert store.get("lab").reverse_forwards == (second,)


def test_failed_reverse_save_closes_new_forward(saved, monkeypatch):
    store, profile = saved
    settings = SavedForwards(store, "lab", profile.connection, profile.ref)
    manager = Mock()
    manager.add.return_value = ReverseForwardStatus(4444, 5555, "127.0.0.1", True, 0, None)
    backend = Mock()
    backend.connection.reverse_forwards.return_value = manager
    console = WorkspaceConsole(backend, ConsoleState(forward_settings=settings))
    monkeypatch.setattr(store, "remember_reverse", Mock(side_effect=OSError("disk full")))
    with pytest.raises(WorkspaceError, match="new listener was stopped"):
        console.reverse_forward(["add", "4444", "5555"])
    manager.stop.assert_called_once_with(4444)
    assert store.get("lab").reverse_forwards == ()


def test_listen_and_kill_update_saved_profile(saved):
    store, profile = saved
    settings = SavedListeners(store, "lab", profile.connection, profile.ref)
    listener = Mock(state=ListenerState.RUNNING, address=("127.0.0.1", 4444))
    manager = Mock()
    manager.workspace_state = SimpleNamespace(listener_settings=settings)
    manager.create_listener.return_value = listener
    manager.listeners = [listener]
    args = SimpleNamespace(
        drop_duplicate=False, platform="linux", host="127.0.0.1", port=4444,
        ssl=False, ssl_cert=None, ssl_key=None, count=None,
    )
    ListenCommand(manager).run(manager, args)
    assert store.get("lab").listeners == (ListenerRule("127.0.0.1", 4444, "linux"),)
    ListenersCommand(manager).run(manager, SimpleNamespace(kill=True, init=False, id=0, all=False))
    listener.stop.assert_called_once()
    assert store.get("lab").listeners == ()


def test_failed_listener_save_stops_new_listener(saved, monkeypatch):
    store, profile = saved
    settings = SavedListeners(store, "lab", profile.connection, profile.ref)
    listener = Mock(state=ListenerState.RUNNING, address=("127.0.0.1", 4444))
    manager = Mock()
    manager.workspace_state = SimpleNamespace(listener_settings=settings)
    manager.create_listener.return_value = listener
    monkeypatch.setattr(store, "remember_listener", Mock(side_effect=OSError("disk full")))
    args = SimpleNamespace(
        drop_duplicate=False, platform="linux", host="127.0.0.1", port=4444,
        ssl=False, ssl_cert=None, ssl_key=None, count=None,
    )
    with pytest.raises(WorkspaceError, match="it was stopped"):
        ListenCommand(manager).run(manager, args)
    listener.stop.assert_called_once()
    assert store.get("lab").listeners == ()


def test_failed_listener_restore_keeps_saved_definition(saved):
    store, profile = saved
    settings = SavedListeners(store, "lab", profile.connection, profile.ref)
    settings.remember(ListenerRule("127.0.0.1", 4444))
    listener = Mock(state=ListenerState.FAILED, failure_exception=OSError("port busy"))
    manager = Mock(listeners=[])
    manager.create_listener.return_value = listener
    messages = settings.restore(manager)
    assert "not restored" in messages[0]
    assert "port busy" in messages[0]
    listener.stop.assert_called_once()
    assert store.get("lab").listeners == (ListenerRule("127.0.0.1", 4444),)


def test_saved_listener_reopens_after_manager_restart(saved):
    store, profile = saved
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    settings = SavedListeners(store, "lab", profile.connection, profile.ref)
    settings.remember(ListenerRule("127.0.0.1", port, "linux"))
    manager = Manager(config=io.StringIO('set -g db "memory://"\n'))
    try:
        messages = settings.restore(manager)
        assert messages == [f"Restored listener 127.0.0.1:{port}."]
        assert manager.listeners[0].state is ListenerState.RUNNING
        assert settings.restore(manager) == []
    finally:
        for listener in manager.listeners:
            if listener.is_alive():
                listener.stop()
        manager.db.close()
    fresh = SavedListeners(ProfileStore(), "lab", profile.connection, profile.ref)
    assert fresh.rules() == (ListenerRule("127.0.0.1", port, "linux"),)


def test_profile_update_preserves_rules_and_replacement_clears_them(saved):
    store, profile = saved
    store.remember_reverse("lab", profile.connection, profile.ref, ReverseForwardRule(4444, 5555))
    store.remember_listener("lab", profile.connection, profile.ref, ListenerRule("127.0.0.1", 5555))
    store.save(replace(profile, password_prompt=True))
    assert len(store.get("lab").reverse_forwards) == 1
    assert len(store.get("lab").listeners) == 1
    store.save(replace(profile, ref=replace(profile.ref, uuid="b" * 32)), replace_identity=True)
    assert store.get("lab").reverse_forwards == ()
    assert store.get("lab").listeners == ()


def test_attach_restores_listeners_before_reverse_forward_and_display(saved, monkeypatch):
    from pwncat.workspace.cli import interact

    store, profile = saved
    store.remember_listener("lab", profile.connection, profile.ref, ListenerRule("127.0.0.1", 5555))
    forwards = SavedForwards(store, "lab", profile.connection, profile.ref)
    listeners = SavedListeners(store, "lab", profile.connection, profile.ref)
    events = []
    backend = Mock(ref=profile.ref)
    backend.connection.reverse_forwards.return_value = Mock()
    backend.connection.local_forwards.return_value = Mock()
    backend.display.return_value = Mock()
    monkeypatch.setattr(WorkspaceConsole, "prepare_manager", lambda self: events.append("manager") or Mock())
    monkeypatch.setattr(listeners, "restore", lambda manager: events.append("listeners") or [])
    monkeypatch.setattr(forwards, "restore_reverse", lambda manager: events.append("reverse") or [])
    monkeypatch.setattr(forwards, "restore", lambda manager: events.append("local") or [])
    monkeypatch.setattr("pwncat.workspace.cli.display", lambda *args: events.append("display") or "detach")
    interact(
        backend, profile.connection, forward_settings=forwards,
        listener_settings=listeners,
    )
    assert events == ["manager", "listeners", "reverse", "local", "display"]
