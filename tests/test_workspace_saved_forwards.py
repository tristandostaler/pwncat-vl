"""Durable forwarding intent, independent restore scope, and reconnect ordering."""

import json
from dataclasses import replace
from unittest.mock import Mock

import pytest

from pwncat.workspace import ConnectionLost, IdentityMismatch, WorkspaceError
from pwncat.workspace.forwarding import ForwardStatus
from pwncat.workspace.model import ForwardRule, WorkspaceRef
from pwncat.workspace.profiles import ProfileStore, SavedWorkspace
from pwncat.workspace.saved_forwards import SavedForwards
from pwncat.workspace.ssh import SSHProfile


@pytest.fixture
def saved(tmp_path, monkeypatch):
    monkeypatch.setenv("PWNCAT_WORKSPACE_CONFIG", str(tmp_path / "profiles"))
    profile = SavedWorkspace(
        "lab",
        SSHProfile("server.example", "test"),
        False,
        False,
        WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket"),
    )
    store = ProfileStore()
    store.save(profile)
    return store, profile, SavedForwards(store, "lab", profile.connection, profile.ref)


def manager_for(peer="192.0.2.20"):
    manager = Mock()
    manager.transport.getpeername.return_value = (peer, 22)
    manager.list.return_value = []
    manager.add.side_effect = lambda local, remote, *, destination_ip: ForwardStatus(
        local, remote, True, 0, None, destination_ip
    )
    return manager


def test_legacy_profile_defaults_to_no_saved_forwards(saved):
    _store, profile, _settings = saved
    document = profile.document()
    document.pop("forwards")
    assert SavedWorkspace.parse(document, "lab").forwards == ()


@pytest.mark.parametrize(
    "rules",
    [
        {},
        [{"local_port": True, "remote_port": 80, "destination_ip": "127.0.0.1"}],
        [{"local_port": 8080, "remote_port": 0, "destination_ip": "127.0.0.1"}],
        [{"local_port": 8080, "remote_port": 80, "destination_ip": "example.com"}],
        [{"local_port": 8080, "remote_port": 80}],
        [
            {
                "local_port": 8080,
                "remote_port": 80,
                "destination_ip": "127.0.0.1",
                "bind": "0.0.0.0",
            }
        ],
        [{"local_port": 8080, "remote_port": 80, "destination_ip": "127.0.0.1"}] * 2,
        [
            {
                "local_port": 8000 + index,
                "remote_port": 80,
                "destination_ip": "127.0.0.1",
            }
            for index in range(9)
        ],
    ],
)
def test_invalid_saved_rules_are_rejected(saved, rules):
    _store, profile, _settings = saved
    document = profile.document()
    document["forwards"] = rules
    with pytest.raises(WorkspaceError, match="Invalid saved"):
        SavedWorkspace.parse(document, "lab")


def test_connection_settings_updates_preserve_current_rules(saved):
    store, profile, settings = saved
    manager = manager_for()
    assert settings.remember(manager, ForwardStatus(8080, 80, True, 0, None))
    # The original connection snapshot predates the forward. Saving new auth
    # choices must merge under the same lock rather than erase the newer rule.
    store.save(replace(profile, password_prompt=True))
    assert settings.rules() == (ForwardRule(8080, 80, "127.0.0.1"),)
    assert store.get("lab").password_prompt
    manager.add.reset_mock()
    messages = settings.restore(manager)
    assert len(messages) == 1 and "Restored forward" in messages[0]
    manager.add.assert_called_once_with(8080, 80, destination_ip="127.0.0.1")


def test_forward_mutations_preserve_unrelated_profile_changes(saved):
    store, profile, settings = saved
    manager = manager_for()
    store.save(replace(profile, credential_ref="c" * 64))
    settings.remember(manager, ForwardStatus(8080, 80, True, 0, None))
    settings.remember(manager, ForwardStatus(8081, 81, True, 0, None))
    settings.stop(manager, 8080)
    latest = store.get("lab")
    assert latest.credential_ref == "c" * 64
    assert latest.forwards == (ForwardRule(8081, 81, "127.0.0.1"),)


def test_recreated_workspace_does_not_inherit_old_forwards(saved):
    store, profile, settings = saved
    settings.remember(manager_for(), ForwardStatus(8080, 80, True, 0, None))
    replacement = replace(profile, ref=replace(profile.ref, uuid="b" * 32))
    store.save(replacement, replace_identity=True)
    assert store.get("lab").forwards == ()
    manager = manager_for()
    with pytest.raises(IdentityMismatch):
        settings.restore(manager)
    manager.add.assert_not_called()


def test_removed_profile_is_not_recreated_by_an_old_client(saved):
    store, _profile, settings = saved
    store.forget("lab")
    with pytest.raises(WorkspaceError, match="profile was removed"):
        settings.remember(manager_for(), ForwardStatus(8080, 80, True, 0, None))
    assert store.get("lab") is None


def test_forward_can_still_stop_after_the_profile_is_forgotten(saved):
    store, _profile, settings = saved
    manager = manager_for()
    entry = ForwardStatus(8080, 80, True, 0, None)
    settings.remember(manager, entry)
    manager.list.return_value = [entry]
    store.forget("lab")
    settings.stop(manager, 8080)
    manager.stop.assert_called_once_with(8080)
    assert store.get("lab") is None


def test_restore_internal_destination_even_if_ssh_peer_changes(saved):
    store, profile, settings = saved
    rule = ForwardRule(8080, 80, "10.0.0.20")
    store.remember_forward("lab", profile.connection, profile.ref, rule)
    manager = manager_for(peer="192.0.2.21")
    messages = settings.restore(manager)
    assert "Restored forward" in messages[0]
    manager.add.assert_called_once_with(8080, 80, destination_ip="10.0.0.20")
    manager.transport.getpeername.assert_not_called()
    assert settings.rules() == (rule,)


def test_manual_internal_destination_replaces_saved_rule(saved):
    _store, _profile, settings = saved
    manager = manager_for()
    settings.remember(manager, ForwardStatus(8080, 80, True, 0, None))
    assert settings.remember(
        manager, ForwardStatus(8080, 80, True, 0, None, "10.0.0.20")
    )
    assert settings.rules() == (ForwardRule(8080, 80, "10.0.0.20"),)


def test_restore_continues_after_port_conflict_and_keeps_definition(saved):
    _store, _profile, settings = saved
    manager = manager_for()
    settings.remember(manager, ForwardStatus(8080, 80, True, 0, None))
    settings.remember(manager, ForwardStatus(8081, 81, True, 0, None))
    manager.add.side_effect = [
        WorkspaceError("Port in use"),
        ForwardStatus(8081, 81, True, 0, None),
    ]
    messages = settings.restore(manager)
    assert "not restored" in messages[0]
    assert "Restored forward" in messages[1]
    assert len(settings.rules()) == 2
    settings.stop(manager, 8080)
    assert settings.rules() == (ForwardRule(8081, 81, "127.0.0.1"),)


def test_restore_is_idempotent_for_an_already_running_matching_rule(saved):
    _store, _profile, settings = saved
    manager = manager_for()
    entry = ForwardStatus(8080, 80, True, 0, None)
    settings.remember(manager, entry)
    manager.list.return_value = [entry]
    assert settings.restore(manager) == []
    manager.add.assert_not_called()


def test_failed_remove_preserves_saved_and_running_state(saved, monkeypatch):
    store, _profile, settings = saved
    manager = manager_for()
    entry = ForwardStatus(8080, 80, True, 0, None)
    settings.remember(manager, entry)
    manager.list.return_value = [entry]
    original = (store.root / "lab.json").read_bytes()
    monkeypatch.setattr(
        "pwncat.workspace.profiles.os.replace", Mock(side_effect=OSError("disk full"))
    )
    with pytest.raises(OSError, match="disk full"):
        settings.stop(manager, 8080)
    manager.stop.assert_not_called()
    assert (store.root / "lab.json").read_bytes() == original
    assert json.loads(original)["forwards"][0]["local_port"] == 8080


@pytest.mark.parametrize("valid_reconnect", [True, False])
def test_auto_reconnect_verifies_workspace_before_restoring(
    monkeypatch, valid_reconnect
):
    from pwncat.workspace.cli import interact

    events = []
    backend, replacement, connection = Mock(), Mock(), Mock()
    backend.ref = WorkspaceRef("lab", "a" * 32, "1:100", "/home/test/socket")
    backend.display.side_effect = ConnectionLost("test disconnect")
    settings = Mock()
    settings.restore.side_effect = lambda _: events.append("restore") or []

    def load(*_args, **_kwargs):
        events.append("verify")
        if not valid_reconnect:
            raise IdentityMismatch("replaced workspace")

    replacement.load.side_effect = load
    monkeypatch.setattr(
        "pwncat.workspace.cli.SSHConnection", Mock(return_value=connection)
    )
    monkeypatch.setattr(
        "pwncat.workspace.cli.TmuxWorkspace", Mock(return_value=replacement)
    )
    monkeypatch.setattr("pwncat.workspace.cli.display", Mock(return_value="detach"))
    monkeypatch.setattr("pwncat.workspace.cli.time.sleep", Mock())
    if valid_reconnect:
        interact(
            backend, SSHProfile("server.example", "test"), forward_settings=settings
        )
        assert events == ["restore", "verify", "restore"]
    else:
        with pytest.raises(IdentityMismatch):
            interact(
                backend, SSHProfile("server.example", "test"), forward_settings=settings
            )
        assert events == ["restore", "verify"]
