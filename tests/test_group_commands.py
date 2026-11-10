"""Grouped console commands preserve the existing handlers and completion."""

import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document

from pwncat.commands import CommandCompleter
from pwncat.manager import Manager, Session
from pwncat.util import console
from pwncat.workspace.console_commands import WORKSPACE_COMMANDS


class GroupCommandTests(unittest.TestCase):
    def setUp(self):
        self.manager = Manager(config=io.StringIO('set -g db "memory://"\n'))
        self.manager.parser.commands[:0] = [
            cls(self.manager) for cls in WORKSPACE_COMMANDS
        ]

    def tearDown(self):
        self.manager.__exit__(None, None, None)
        self.manager.db.close()

    def command(self, name):
        return next(
            command for command in self.manager.parser.commands
            if command.PROG == name
        )

    def complete(self, line):
        completer = CommandCompleter(
            self.manager, self.manager.parser.commands
        )
        return {
            item.text for item in completer.get_completions(
                Document(line), CompleteEvent(completion_requested=True)
            )
        }

    def test_module_routes_to_existing_run_and_edit(self):
        module = self.manager.modules["bootstrap.pwnbox"]
        self.manager._target = SimpleNamespace(
            platform=SimpleNamespace(name="linux"),
            find_module=lambda pattern: [module],
        )
        run = self.command("run")
        edit = self.command("edit")
        with patch.object(run, "run") as run_handler, patch.object(edit, "run") as edit_handler:
            self.manager.parser.dispatch_line("module run bootstrap.pwnbox")
            self.manager.parser.dispatch_line("module edit bootstrap.pwnbox")
        self.assertEqual(run_handler.call_args.args[1].module, "bootstrap.pwnbox")
        self.assertEqual(edit_handler.call_args.args[1].module, "bootstrap.pwnbox")
        self.assertEqual(run.parser.prog, "run")
        self.assertEqual(edit.parser.prog, "edit")

    def test_module_run_accepts_full_and_platform_relative_names(self):
        full_name = "linux.enumerate.software.pkexec.cve_2021_4034"
        short_name = "enumerate.software.pkexec.cve_2021_4034"
        module = self.manager.modules[full_name]
        self.manager._target = SimpleNamespace(
            platform=SimpleNamespace(name="linux"),
            find_module=lambda pattern: [module],
        )
        run = self.command("run")
        with patch.object(run, "run") as handler:
            self.manager.parser.dispatch_line(f"module run {full_name}")
            self.manager.parser.dispatch_line(f"module run {short_name}")
        self.assertEqual(
            [call.args[1].module for call in handler.call_args_list],
            [full_name, short_name],
        )
        self.assertIn(full_name, self.complete("module run linux.enumerate.software.pkexec."))
        self.assertIn(short_name, self.complete("module run enumerate.software.pkexec."))

    def test_session_resolves_full_and_platform_relative_names_to_same_module(self):
        full_name = "linux.enumerate.software.pkexec.cve_2021_4034"
        short_name = "enumerate.software.pkexec.cve_2021_4034"
        module = SimpleNamespace(name=full_name, PLATFORM=None, run=Mock(return_value="same"))
        manager = SimpleNamespace(
            modules={full_name: module}, reload_if_edited=Mock()
        )
        session = SimpleNamespace(manager=manager, platform=SimpleNamespace(name="linux"))

        self.assertEqual(Session.run(session, full_name), "same")
        self.assertEqual(Session.run(session, short_name), "same")
        self.assertEqual(module.run.call_count, 2)

    def test_module_list_includes_loaded_modules_without_a_session(self):
        with patch.object(console, "print") as display:
            self.manager.parser.dispatch_line("module list")
        table = display.call_args.args[0]
        names = table.columns[0]._cells
        self.assertEqual(names, sorted(names))
        self.assertIn("bootstrap.pwnbox", names)
        self.assertTrue(any(name.startswith("windows.") for name in names))

    def test_search_without_matches_reports_no_results(self):
        self.manager._target = SimpleNamespace(
            platform=SimpleNamespace(name="linux"),
            find_module=lambda pattern: iter(()),
        )
        with patch.object(console, "print") as display:
            self.manager.parser.dispatch_line("module search enumerateé*")
            self.manager.parser.dispatch_line("search missing*")
            self.manager.parser.dispatch_line("module search [")
        self.assertEqual(display.call_count, 3)
        self.assertIn("enumerateé*", display.call_args_list[0].args[0].plain)
        self.assertIn("No modules match", display.call_args_list[1].args[0].plain)
        self.assertIn("'['", display.call_args_list[2].args[0].plain)

    def test_module_run_background_routes_to_workspace_owner(self):
        owner = SimpleNamespace(
            modules=SimpleNamespace(active=lambda: False),
            start_module=Mock(),
            module_status=Mock(),
            module_result=Mock(),
        )
        self.manager.workspace_console = owner
        self.manager._target = SimpleNamespace(
            platform=SimpleNamespace(name="linux"),
            find_module=lambda pattern: [SimpleNamespace(name="bootstrap.pwnbox")],
        )
        self.manager.parser.dispatch_line(
            "module run --background bootstrap.pwnbox mode=fast"
        )
        owner.start_module.assert_called_once_with(
            "bootstrap.pwnbox", {"mode": "fast"},
            raw=False, traceback_requested=False,
        )
        self.manager.parser.dispatch_line("module status")
        self.manager.parser.dispatch_line("module result")
        owner.module_status.assert_called_once_with()
        owner.module_result.assert_called_once_with()

    def test_listener_routes_and_flat_command_still_work(self):
        start = self.command("listen")
        manage = self.command("listeners")
        with patch.object(start, "run") as start_handler, patch.object(manage, "run") as manage_handler:
            self.manager.parser.dispatch_line("listener start -m linux 4444")
            self.manager.parser.dispatch_line("listener stop 0")
            self.manager.parser.dispatch_line("listeners -k 1")
        self.assertEqual(start_handler.call_args.args[1].port, 4444)
        self.assertEqual(start_handler.call_args.args[1].platform, "linux")
        self.assertEqual(manage_handler.call_args_list[0].args[1].id, 0)
        self.assertTrue(manage_handler.call_args_list[0].args[1].kill)
        self.assertEqual(manage_handler.call_args_list[1].args[1].id, 1)

    def test_transfers_group_keeps_upload_download_and_status(self):
        upload = self.command("upload")
        download = self.command("download")
        between = self.command("session-transfer")
        status = self.command("transfer-status")
        with patch.object(upload, "run") as upload_handler, patch.object(
            download, "run"
        ) as download_handler, patch.object(between, "run") as between_handler, patch.object(
            status, "run"
        ) as status_handler:
            self.manager.parser.dispatch_line("transfers upload /local /remote")
            self.manager.parser.dispatch_line("upload /local /remote")
            self.manager.parser.dispatch_line("transfers download /remote /local")
            self.manager.parser.dispatch_line("download /remote /local")
            self.manager.parser.dispatch_line("transfers between 1 /source 2 /destination")
            self.manager.parser.dispatch_line("transfers")

        self.assertEqual(upload_handler.call_count, 2)
        self.assertEqual(download_handler.call_count, 2)
        self.assertEqual(between_handler.call_args.args[1].source_session, 1)
        self.assertEqual(between_handler.call_args.args[1].destination_session, 2)
        status_handler.assert_called_once()
        self.assertGreaterEqual(
            self.complete("transfers "), {"upload", "download", "between", "status"}
        )

    def test_bare_transfers_preserves_workspace_status(self):
        owner = Mock()
        self.manager.workspace_console = owner
        self.manager.parser.dispatch_line("transfers")
        owner.transfer_status.assert_called_once_with()

    def test_listener_subcommands_require_their_own_arguments(self):
        manage = self.command("listeners")
        with patch.object(manage, "run") as handler:
            self.manager.parser.dispatch_line("listener show")
            self.manager.parser.dispatch_line("listener list 0")
        handler.assert_not_called()

    def test_workspace_routes_to_panes_and_supports_direction_only(self):
        backend = Mock()
        backend.split.return_value = [b"%1"]
        self.manager.workspace_backend = backend
        self.manager.workspace_console = Mock()
        self.manager.workspace_console.selected.return_value = SimpleNamespace(id="%0")
        self.manager.workspace_state = SimpleNamespace(selected="%0")
        self.manager.parser.dispatch_line("workspace pane split vertical")
        backend.split.assert_called_once_with("%0", "vertical")
        self.assertEqual(self.manager.workspace_state.selected, "%1")

    def test_help_shows_group_paths_and_restores_leaf_usage(self):
        run = self.command("run")
        with patch.object(run.parser, "print_help") as leaf_help:
            self.manager.parser.dispatch_line("help module run")
            leaf_help.assert_called_once()
            self.assertEqual(run.parser.prog, "run")
        with patch.object(console, "print") as display:
            self.manager.parser.dispatch_line("help")
        table = display.call_args.args[0]
        names = [getattr(cell, "plain", str(cell)) for cell in table.columns[0]._cells]
        self.assertIn("module", names)
        self.assertIn("workspace", names)
        self.assertIn("listener", names)
        for old in ("run", "edit", "panes", "select", "listen", "listeners"):
            self.assertNotIn(old, names)

    def test_completion_follows_group_paths_and_leaf_arguments(self):
        self.assertIn("module", self.complete(""))
        self.assertNotIn("run", self.complete(""))
        self.assertGreaterEqual(self.complete("module "), {"list", "run", "edit", "reload"})
        self.assertIn("all", self.complete("module reload "))
        self.assertGreaterEqual(self.complete("listener "), {"start", "list", "stop"})
        self.assertGreaterEqual(self.complete("workspace pane "), {"list", "select", "split"})
        self.assertGreaterEqual(self.complete("help workspace pane "), {"list", "select", "split"})
        self.assertGreaterEqual(
            self.complete("workspace pane split %0 "), {"horizontal", "vertical"}
        )
        self.assertIn(
            "--background", self.complete("transfers download /remote /local --b")
        )


if __name__ == "__main__":
    unittest.main()
