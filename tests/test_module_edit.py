"""Local module editing and reload checks; no remote target is needed."""

import io
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pwncat.commands.edit import Command as EditCommand
from pwncat.manager import Manager, Session
from pwncat.modules import ModuleFailed
from pwncat.util import console


def source(marker, *, arguments='{"note": Argument(str, default="original")}'):
    return (
        "from pwncat.modules import Argument, BaseModule\n"
        "class Module(BaseModule):\n"
        "    PLATFORM = None\n"
        f"    ARGUMENTS = {arguments}\n"
        f"    MARKER = {marker!r}\n"
        "    def run(self, session, note='original'):\n"
        "        return None\n"
    )


class ModuleEditingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.package = "edit_check_" + uuid.uuid4().hex
        directory = self.root / self.package
        directory.mkdir()
        (directory / "__init__.py").write_text("")
        self.file = directory / "sample.py"
        self.file.write_text(source("first"))
        self.name = f"{self.package}.sample"
        self.manager = Manager(config=io.StringIO('set -g db "memory://"\n'))
        self.manager.load_modules(str(self.root))

    def tearDown(self):
        self.manager.__exit__(None, None, None)
        self.manager.db.close()
        self.temp.cleanup()
        sys.modules.pop(f"pwncat.modules.{self.name}", None)
        sys.modules.pop(f"pwncat.modules.{self.package}", None)

    def test_saved_source_reloads_and_updates_module_context(self):
        old = self.manager.modules[self.name]
        self.manager.config.use(old)
        self.manager.config.locals["note"] = "kept"
        self.manager.watch_module(self.name)
        self.file.write_text(source("second"))

        self.manager.reload_if_edited(self.name)

        new = self.manager.modules[self.name]
        self.assertIsNot(new, old)
        self.assertEqual(new.MARKER, "second")
        self.assertIs(self.manager.config.module, new)
        self.assertEqual(self.manager.config.locals, {"note": "kept"})
        self.manager.reload_if_edited(self.name)
        self.assertIs(self.manager.modules[self.name], new)

    def test_invalid_save_keeps_prior_code_and_blocks_run(self):
        self.manager.watch_module(self.name)
        previous = self.manager.modules[self.name]
        previous_import = sys.modules[f"pwncat.modules.{self.name}"]
        self.file.write_text("class Module(:\n")

        with self.assertRaisesRegex(ModuleFailed, "reload failed"):
            self.manager.reload_if_edited(self.name)

        self.assertIs(self.manager.modules[self.name], previous)
        self.assertIs(sys.modules[f"pwncat.modules.{self.name}"], previous_import)
        self.file.write_text(source("fixed"))
        self.manager.reload_if_edited(self.name)
        self.assertEqual(self.manager.modules[self.name].MARKER, "fixed")

    def test_edit_opens_source_and_watches_it(self):
        with patch("pwncat.commands.edit.editor_command", return_value=["editor", str(self.file)]), patch(
            "pwncat.commands.edit.subprocess.Popen"
        ) as launch:
            EditCommand(self.manager).run(self.manager, SimpleNamespace(module=self.name))
        self.assertIn(self.name, self.manager._edited_module_hashes)
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0], ["editor", str(self.file)])

    def test_session_run_uses_reloaded_instance(self):
        old = SimpleNamespace(name="fake", PLATFORM=None, run=lambda session: "old")
        new = SimpleNamespace(name="fake", PLATFORM=None, run=lambda session: "new")
        self.manager.modules["fake"] = old
        session = SimpleNamespace(
            manager=self.manager, platform=SimpleNamespace(name="linux")
        )

        def replace_on_save(name):
            self.assertEqual(name, "fake")
            self.manager.modules[name] = new

        with patch.object(self.manager, "reload_if_edited", side_effect=replace_on_save):
            self.assertEqual(Session.run(session, "fake"), "new")

    def test_edit_command_is_available_at_local_prompt(self):
        with patch("subprocess.Popen") as launch:
            self.manager.parser.dispatch_line(f"edit {self.name}")
        self.assertIn(self.name, self.manager._edited_module_hashes)
        launch.assert_called_once()

    def test_reload_command_refreshes_module_at_local_prompt(self):
        self.file.write_text(source("via-command"))
        self.manager.parser.dispatch_line(f"reload {self.name}")
        self.assertEqual(self.manager.modules[self.name].MARKER, "via-command")

    def test_reload_all_continues_after_one_module_fails(self):
        names = sorted(self.manager.modules)
        reloaded = []

        def reload_one(name):
            reloaded.append(name)
            if name == self.name:
                raise ModuleFailed("bad save")

        with patch.object(self.manager, "reload_module", side_effect=reload_one), patch.object(
            console, "log"
        ) as log:
            self.manager.parser.dispatch_line("module reload all")

        self.assertEqual(reloaded, names)
        self.assertIn(f"Reloaded {len(names) - 1}/{len(names)} modules.", log.call_args_list[0].args[0])
        self.assertIn(self.name, log.call_args_list[1].args[0])
        self.assertIn("bad save", log.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main()
