"""Local module creation and deletion stay inside the user module directory."""

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pwncat.commands.moddelete import local_module_choices
from pwncat.manager import Manager
from pwncat.modules import BaseModule
from pwncat.modules.workspace import WorkspaceModule
from pwncat.util import console


class ModuleFileCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data_home = Path(self.temp.name) / "data"
        env = patch.dict(os.environ, {"XDG_DATA_HOME": str(self.data_home)})
        env.start()
        self.addCleanup(env.stop)
        self.manager = Manager(config=io.StringIO('set -g db "memory://"\n'))
        self.addCleanup(self.manager.db.close)
        self.addCleanup(self.manager.__exit__, None, None, None)
        self.root = self.data_home / "pwncat" / "modules"

    def tearDown(self):
        for name in ("bootstrap.pwnbox", "bootstrap", "sample"):
            sys.modules.pop("pwncat.modules." + name, None)

    def create(self, name="bootstrap.pwnbox"):
        with patch("pwncat.commands.edit.editor_command", return_value=["editor", "file"]):
            with patch("pwncat.commands.edit.subprocess.Popen") as launch:
                self.manager.parser.dispatch_line(f"module new {name}")
        return launch

    def test_new_creates_package_loads_module_and_opens_editor(self):
        launch = self.create()
        source = self.root / "bootstrap" / "pwnbox.py"
        self.assertTrue((self.root / "bootstrap" / "__init__.py").is_file())
        self.assertTrue(source.is_file())
        self.assertIn("class Module(WorkspaceModule)", source.read_text())
        self.assertIsInstance(self.manager.modules["bootstrap.pwnbox"], WorkspaceModule)
        self.assertIn("bootstrap.pwnbox", self.manager._edited_module_hashes)
        self.assertEqual(Path(launch.call_args.args[0][-1]).resolve(), source.resolve())

    def test_new_never_overwrites_existing_module(self):
        self.create()
        source = self.root / "bootstrap" / "pwnbox.py"
        source.write_text("# custom changes\n")
        with patch.object(console, "log") as log:
            self.create()
        self.assertEqual(source.read_text(), "# custom changes\n")
        self.assertIn("already exists", log.call_args.args[0])

    def test_new_generic_module_uses_base_module_template(self):
        self.create("sample")
        source = self.root / "sample.py"
        self.assertTrue(source.is_file())
        self.assertIn("class Module(BaseModule)", source.read_text())
        self.assertIsInstance(self.manager.modules["sample"], BaseModule)
        self.assertIn("sample", list(local_module_choices(SimpleNamespace(manager=self.manager))))

    def test_delete_confirms_clears_context_and_allows_recreation(self):
        self.create()
        module = self.manager.modules["bootstrap.pwnbox"]
        self.manager.config.use(module)
        with patch("builtins.input", return_value="n"):
            self.manager.parser.dispatch_line("module delete bootstrap.pwnbox")
        self.assertTrue((self.root / "bootstrap" / "pwnbox.py").exists())

        with patch("builtins.input", return_value="yes"):
            self.manager.parser.dispatch_line("module delete bootstrap.pwnbox")
        self.assertFalse((self.root / "bootstrap" / "pwnbox.py").exists())
        self.assertNotIn("bootstrap.pwnbox", self.manager.modules)
        self.assertNotIn("bootstrap.pwnbox", self.manager._edited_module_hashes)
        self.assertNotIn("pwncat.modules.bootstrap.pwnbox", sys.modules)
        self.assertIsNone(self.manager.config.module)
        self.create()
        self.assertIn("bootstrap.pwnbox", self.manager.modules)

    def test_delete_rejects_builtin_and_invalid_names(self):
        builtin = "linux.enumerate.software.pkexec.cve_2021_4034"
        self.assertIn(builtin, self.manager.modules)
        with patch("sys.stderr", new_callable=io.StringIO) as errors:
            self.manager.parser.dispatch_line(f"module delete {builtin} --yes")
        self.assertIn("invalid choice", errors.getvalue())
        self.assertIn(builtin, self.manager.modules)

        with patch.object(console, "log") as log:
            self.manager.parser.dispatch_line("module new ../outside")
        self.assertIn("dotted Python module name", log.call_args.args[0])
        self.assertFalse((self.data_home / "outside.py").exists())

    def test_delete_removes_broken_module_source(self):
        directory = self.root / "bootstrap"
        directory.mkdir(parents=True)
        (directory / "__init__.py").write_text("")
        source = directory / "broken.py"
        source.write_text("class Module(:\n")
        self.assertNotIn("bootstrap.broken", self.manager.modules)

        self.manager.parser.dispatch_line("module delete bootstrap.broken --yes")

        self.assertFalse(source.exists())

    def test_new_refuses_symlinked_package(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        self.root.mkdir(parents=True)
        (self.root / "bootstrap").symlink_to(outside, target_is_directory=True)
        with patch.object(console, "log") as log:
            self.create()
        self.assertIn("symlink", log.call_args.args[0])
        self.assertFalse((outside / "pwnbox.py").exists())


if __name__ == "__main__":
    unittest.main()
