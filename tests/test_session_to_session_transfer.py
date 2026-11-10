"""Session copies stream bytes and publish only verified destinations."""

import io
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pwncat.commands.session_transfer import Command as SessionTransferCommand
from pwncat.workspace import WorkspaceError
from pwncat.workspace.session_files import copy_between


class LocalPlatform:
    name = "linux"
    Path = Path

    @staticmethod
    def lstat(path):
        return os.lstat(path)

    @staticmethod
    def open(path, mode):
        return open(path, mode)

    @staticmethod
    def mkdir(path, mode):
        os.mkdir(path, mode)

    @staticmethod
    def chmod(path, mode):
        os.chmod(path, mode)

    @staticmethod
    def link_to(source, destination):
        os.link(source, destination)

    @staticmethod
    def rename(source, destination):
        os.replace(source, destination)

    @staticmethod
    def unlink(path):
        os.unlink(path)

    @staticmethod
    def rmdir(path):
        os.rmdir(path)


class SessionToSessionTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source.bin"
        self.destination = self.root / "destination.bin"
        self.source.write_bytes(bytes(range(256)) * 300)
        self.source_platform = LocalPlatform()
        self.destination_platform = LocalPlatform()

    def tearDown(self):
        self.temp.cleanup()

    def test_binary_copy_streams_without_a_local_staging_file(self):
        phases = []
        counts = []
        with patch("pwncat.workspace.session_files.tempfile.mkdtemp", side_effect=AssertionError):
            result = copy_between(
                self.source_platform, str(self.source),
                self.destination_platform, str(self.destination),
                progress=counts.append,
                status=lambda phase, total: phases.append((phase, total)),
            )
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        self.assertEqual(result.size, self.source.stat().st_size)
        self.assertEqual(counts[-1], result.size)
        self.assertEqual(
            phases,
            [("copying", result.size), ("verifying", result.size), ("publishing", result.size)],
        )
        self.assertEqual(list(self.root.glob(".pwncat-upload-*")), [])

    def test_existing_destination_requires_overwrite(self):
        self.destination.write_bytes(b"original")
        with self.assertRaisesRegex(WorkspaceError, "Destination exists"):
            copy_between(
                self.source_platform, str(self.source),
                self.destination_platform, str(self.destination),
            )
        self.assertEqual(self.destination.read_bytes(), b"original")
        copy_between(
            self.source_platform, str(self.source),
            self.destination_platform, str(self.destination), overwrite=True,
        )
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())

    def test_symlink_source_is_refused(self):
        link = self.root / "source-link"
        link.symlink_to(self.source)
        with self.assertRaisesRegex(WorkspaceError, "regular remote file"):
            copy_between(
                self.source_platform, str(link),
                self.destination_platform, str(self.destination),
            )
        self.assertFalse(self.destination.exists())

    def test_corrupt_destination_stage_is_never_published(self):
        class CorruptPlatform(LocalPlatform):
            @staticmethod
            def open(path, mode):
                if mode == "rb" and ".pwncat-upload-" in path:
                    return io.BytesIO(b"corrupt")
                return open(path, mode)

        with self.assertRaisesRegex(WorkspaceError, "verification failed"):
            copy_between(
                self.source_platform, str(self.source),
                CorruptPlatform(), str(self.destination),
            )
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".pwncat-upload-*")), [])

    def test_command_copies_between_ids_without_changing_active_session(self):
        first = SimpleNamespace(id=1, platform=self.source_platform)
        second = SimpleNamespace(id=2, platform=self.destination_platform)
        manager = SimpleNamespace(sessions={1: first, 2: second}, target=first)
        args = SimpleNamespace(
            source_session=1, source=str(self.source),
            destination_session=2, destination=str(self.destination), overwrite=False,
        )
        with patch("pwncat.commands.session_transfer.console.log") as log:
            SessionTransferCommand(manager).run(manager, args)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        self.assertIs(manager.target, first)
        self.assertIn("session-1 to session-2", log.call_args.args[0])

    def test_command_rejects_missing_session_without_writing(self):
        first = SimpleNamespace(id=1, platform=self.source_platform)
        manager = SimpleNamespace(sessions={1: first}, target=first)
        args = SimpleNamespace(
            source_session=1, source=str(self.source),
            destination_session=2, destination=str(self.destination), overwrite=False,
        )
        with patch("pwncat.commands.session_transfer.console.log") as log:
            SessionTransferCommand(manager).run(manager, args)
        self.assertFalse(self.destination.exists())
        self.assertIn("session-2 does not exist", log.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
