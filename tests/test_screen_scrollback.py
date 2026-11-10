"""The local Screen client keeps terminal scrollback available."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from pwncat.workspace import local_screen


class ScreenScrollbackTests(unittest.TestCase):
    def test_screen_config_preserves_user_settings_and_disables_alt_buffer(self):
        with TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".screenrc").write_text("startup_message off\n")
            with patch.object(local_screen.Path, "home", return_value=home):
                with local_screen._scrollback_screenrc() as config:
                    contents = Path(config).read_text()
                    self.assertIn(f'source "{home / ".screenrc"}"', contents)
                    self.assertIn("termcapinfo * ti@:te@", contents)
                    self.assertIn("defscrollback 50000", contents)
                self.assertFalse(Path(config).exists())

    def test_new_and_reattached_clients_use_scrollback_config(self):
        connection = SimpleNamespace(host="example.test", user="user", port=22)
        configs = []

        def call(command, **kwargs):
            config = Path(command[2])
            self.assertIn("termcapinfo * ti@:te@", config.read_text())
            configs.append(command)
            return 0

        with patch.object(local_screen.shutil, "which", return_value="/usr/bin/screen"):
            with patch.object(local_screen, "_existing", side_effect=[None, ("123.demo", "Detached")]):
                with patch.object(local_screen.subprocess, "call", side_effect=call):
                    local_screen.attach_or_start(["attach", "demo"], "demo", connection, "demo")
                    local_screen.attach_or_start(["attach", "demo"], "demo", connection, "demo")

        self.assertEqual(configs[0][1], "-c")
        self.assertEqual(configs[0][3:5], ["-m", "-S"])
        self.assertEqual(configs[1][-2:], ["-r", "123.demo"])


if __name__ == "__main__":
    unittest.main()
