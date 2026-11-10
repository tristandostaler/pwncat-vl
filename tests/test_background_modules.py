"""Background module runs keep their shell session isolated and results available."""

import threading
import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pwncat.workspace import WorkspaceError
from pwncat.workspace.background_modules import BackgroundModules
from pwncat.workspace.console import WorkspaceConsole
from pwncat.workspace.platform import WorkspaceChannel
from pwncat.commands.sessions import Command as SessionsCommand


class BackgroundModuleTests(unittest.TestCase):
    def test_status_busy_session_and_completed_result(self):
        started, release = threading.Event(), threading.Event()

        def run(actual_session, **kwargs):
            self.assertIs(actual_session, session)
            self.assertEqual(kwargs, {"progress": False, "answer": "yes"})
            self.assertIs(session._background_config.value, config)
            started.set()
            self.assertTrue(release.wait(2))
            return ["result"]

        session = SimpleNamespace(id=7, _background_config=threading.local())
        module = SimpleNamespace(name="example", run=run)
        config = object()
        tasks = BackgroundModules()
        try:
            status = tasks.start(session, module, {"answer": "yes"}, config)
            self.assertTrue(started.wait(2))
            self.assertEqual(status.number, 1)
            self.assertTrue(tasks.busy_session(session))
            with self.assertRaises(WorkspaceError):
                tasks.start(session, module, {}, object())
        finally:
            release.set()
            tasks._thread.join(timeout=2)
        self.assertEqual(tasks.status().state, "completed")
        self.assertEqual(tasks.status().result, ["result"])
        self.assertFalse(tasks.busy_session(session))
        self.assertFalse(hasattr(session._background_config, "value"))

    def test_failure_is_recorded_and_next_run_can_start(self):
        session = SimpleNamespace(id=3)
        module = SimpleNamespace(name="broken", run=Mock(side_effect=ValueError("bad module")))
        tasks = BackgroundModules()
        tasks.start(session, module, {}, object())
        tasks._thread.join(timeout=2)
        self.assertEqual(tasks.status().state, "failed")
        self.assertEqual(tasks.status().error, "bad module")
        tasks.start(session, module, {}, object())
        tasks._thread.join(timeout=2)
        self.assertEqual(tasks.status().number, 2)

    def test_other_shell_switches_console_to_workspace_session(self):
        started, release = threading.Event(), threading.Event()

        def run(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(2))
            return []

        module = SimpleNamespace(name="example", BACKGROUND_SAFE=True, run=run)
        other = SimpleNamespace(
            id=1,
            platform=SimpleNamespace(channel=object()),
            find_module=lambda name, exact: iter([module]),
        )
        workspace = SimpleNamespace(
            id=0,
            platform=SimpleNamespace(channel=WorkspaceChannel.__new__(WorkspaceChannel)),
        )
        manager = Mock(
            target=other, sessions={0: workspace, 1: other},
            modules={"example": module},
            config=Mock(copy=Mock(return_value=object())),
        )
        display = Mock()
        manager.parser.commands = [SimpleNamespace(PROG="run", display_result=display)]
        console = WorkspaceConsole(Mock())
        console._manager = manager
        manager.workspace_console = console
        console.message = Mock()
        try:
            console.start_module("example", {"answer": "yes"})
            self.assertTrue(started.wait(2))
            self.assertIs(manager.target, workspace)
            self.assertTrue(console.modules.busy_session(other))
            manager.create_session.assert_not_called()
            SessionsCommand(manager).run(
                manager, Namespace(list=False, kill=False, session_id=1)
            )
            self.assertIs(manager.target, workspace)
        finally:
            release.set()
            console.modules._thread.join(timeout=2)
        console.module_result()
        display.assert_called_once_with(
            manager, "example", [], raw=False, session=other,
        )

    def test_workspace_shell_gets_a_second_ssh_session(self):
        started, release = threading.Event(), threading.Event()

        class FakeWorkspaceChannel:
            def __init__(self, backend):
                self.backend = backend

            def close(self):
                pass

        def run(*args, **kwargs):
            started.set()
            self.assertTrue(release.wait(2))
            return None

        module = SimpleNamespace(name="example", BACKGROUND_SAFE=True, run=run)

        original = SimpleNamespace(
            id=0,
            platform=SimpleNamespace(channel=FakeWorkspaceChannel(None)),
            find_module=lambda name, exact: iter([module]),
        )
        manager = Mock(
            target=original, sessions={0: original},
            modules={"example": module},
            config=Mock(copy=Mock(return_value=object())),
        )

        def create_session(*, platform, channel):
            self.assertEqual(platform, "linux")
            new = SimpleNamespace(id=1, platform=SimpleNamespace(channel=channel))
            manager.sessions[1] = new
            manager.target = new
            return new

        manager.create_session.side_effect = create_session
        console = WorkspaceConsole(Mock())
        console._manager = manager
        console.message = Mock()
        with patch("pwncat.workspace.platform.WorkspaceChannel", FakeWorkspaceChannel):
            try:
                console.start_module("example", {})
                self.assertTrue(started.wait(2))
                self.assertIs(manager.target, manager.sessions[1])
                self.assertTrue(console.modules.busy_session(original))
            finally:
                release.set()
                console.modules._thread.join(timeout=2)

    def test_unsafe_module_does_not_start_or_switch_sessions(self):
        module = SimpleNamespace(name="interactive", BACKGROUND_SAFE=False)
        session = SimpleNamespace(
            id=0,
            find_module=lambda name, exact: iter([module]),
        )
        manager = Mock(
            target=session, modules={"interactive": module},
        )
        console = WorkspaceConsole(Mock())
        console._manager = manager
        with self.assertRaisesRegex(WorkspaceError, "cannot run in the background"):
            console.start_module("interactive", {})
        self.assertIs(manager.target, session)
        self.assertFalse(console.modules.active())


if __name__ == "__main__":
    unittest.main()
