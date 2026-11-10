"""Behavioral checks for reusable workspace module operations."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from pwncat.manager import ListenerState
from pwncat.modules import ModuleFailed
from pwncat.modules.workspace import (
    ListenerConfig,
    LocalForwardConfig,
    ReverseForwardConfig,
    WorkspaceModule,
)


class WorkspaceModuleTests(unittest.TestCase):
    def setUp(self):
        self.module = WorkspaceModule()

    def test_listener_reuses_matching_configuration_and_rejects_conflict(self):
        config = ListenerConfig("0.0.0.0", 4444, "linux")
        listener = SimpleNamespace(
            state=ListenerState.RUNNING,
            address=(config.host, config.port),
            platform=config.platform,
            protocol=config.protocol,
            ssl=config.ssl,
        )
        manager = SimpleNamespace(listeners=[listener], create_listener=Mock())
        settings = SimpleNamespace(remember=Mock())
        state = SimpleNamespace(listener_settings=settings)

        self.assertFalse(self.module.ensure_listener(manager, state, config))
        manager.create_listener.assert_not_called()
        settings.remember.assert_called_once()

        listener.address = ("127.0.0.1", 4444)
        with self.assertRaises(ModuleFailed):
            self.module.ensure_listener(manager, state, config)
        manager.create_listener.assert_not_called()

    def test_listener_creates_only_when_missing(self):
        config = ListenerConfig("0.0.0.0", 4444, "linux")
        listener = SimpleNamespace(
            state=ListenerState.RUNNING,
            failure_exception=None,
            stop=Mock(),
        )
        manager = SimpleNamespace(listeners=[], create_listener=Mock(return_value=listener))
        state = SimpleNamespace(listener_settings=SimpleNamespace(remember=Mock()))

        self.assertTrue(self.module.ensure_listener(manager, state, config))
        manager.create_listener.assert_called_once_with(
            protocol="socket", host="0.0.0.0", port=4444, platform="linux", ssl=False
        )
        state.listener_settings.remember.assert_called_once()

    def test_forwards_reuse_matching_entries_and_create_missing_entries(self):
        local = LocalForwardConfig(8081, "10.10.110.20", 80)
        reverse = ReverseForwardConfig(5555, 4444)
        local_entry = SimpleNamespace(
            local_port=8081, destination_ip="10.10.110.20", remote_port=80, running=True
        )
        reverse_entry = SimpleNamespace(
            remote_port=5555, local_port=4444, bind_ip="127.0.0.1", running=True
        )
        local_manager = SimpleNamespace(list=Mock(return_value=[local_entry]))
        reverse_manager = SimpleNamespace(list=Mock(return_value=[reverse_entry]))
        connection = SimpleNamespace(
            local_forwards=Mock(return_value=local_manager),
            reverse_forwards=Mock(return_value=reverse_manager),
        )
        settings = SimpleNamespace(remember=Mock(), remember_reverse=Mock())
        console = SimpleNamespace(
            backend=SimpleNamespace(connection=connection),
            state=SimpleNamespace(forward_settings=settings),
            forward=Mock(),
        )

        self.assertFalse(self.module.ensure_local_forward(console, local))
        self.assertFalse(self.module.ensure_reverse_forward(console, reverse))
        console.forward.assert_not_called()
        settings.remember.assert_called_once_with(local_manager, local_entry)
        settings.remember_reverse.assert_called_once_with(reverse_manager, reverse_entry)

        local_manager.list.return_value = []
        reverse_manager.list.return_value = []
        self.assertTrue(self.module.ensure_local_forward(console, local))
        self.assertTrue(self.module.ensure_reverse_forward(console, reverse))
        self.assertEqual(
            console.forward.call_args_list,
            [
                unittest.mock.call(["add", "8081", "10.10.110.20", "80"]),
                unittest.mock.call(["reverse", "add", "5555", "4444", "127.0.0.1"]),
            ],
        )


if __name__ == "__main__":
    unittest.main()
