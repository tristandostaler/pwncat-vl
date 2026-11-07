"""Private remote metadata. The live tmux server remains authoritative."""

from __future__ import annotations

import errno
import json
import posixpath
import re
import stat
import uuid

from . import WorkspaceError, WorkspaceMissing
from .model import workspace_name


def missing(exc):
    return getattr(exc, "errno", None) == errno.ENOENT


class StateStore:
    def __init__(self, sftp, home, uid):
        if not home.startswith("/") or any(ord(c) < 32 for c in home):
            raise WorkspaceError(
                "Remote home must be an absolute path without control characters."
            )
        self.sftp, self.uid = sftp, uid
        try:
            home_attrs = sftp.lstat(home)
        except OSError as exc:
            if missing(exc):
                raise WorkspaceError(
                    f"Remote SSH home directory is missing: {home}"
                ) from exc
            raise
        if (
            not stat.S_ISDIR(home_attrs.st_mode)
            or home_attrs.st_uid != uid
            or stat.S_IMODE(home_attrs.st_mode) & 0o022
        ):
            raise WorkspaceError(
                "Remote home must be owned by the SSH user and not writable by others."
            )
        self.root = posixpath.join(home, ".pwncat-workspaces")

    def private_directory(self, path, *, create=False, exclusive=False):
        try:
            attrs = self.sftp.lstat(path)
            if exclusive:
                raise WorkspaceError(
                    "Workspace state already exists. Attach if running, or archive "
                    "the stopped workspace before reusing its name."
                )
        except OSError as exc:
            if not missing(exc) or not create:
                raise
            self.sftp.mkdir(path, mode=0o700)
            attrs = self.sftp.lstat(path)
        if (
            not stat.S_ISDIR(attrs.st_mode)
            or attrs.st_uid != self.uid
            or stat.S_IMODE(attrs.st_mode) & 0o077
        ):
            raise WorkspaceError(
                f"State directory must be owned by the SSH account and private: {path}"
            )

    def directory(self, name):
        return posixpath.join(self.root, workspace_name(name))

    def create(self, name):
        self.private_directory(self.root, create=True)
        directory = self.directory(name)
        # Check the socket limit before reserving a new workspace directory.
        if len(posixpath.join(directory, "tmux.sock").encode()) >= 100:
            raise WorkspaceError(
                "Workspace socket path is too long; use a shorter workspace name."
            )
        self.private_directory(directory, create=True, exclusive=True)
        return directory

    def write(self, directory, filename, data):
        self.private_directory(directory)
        target = posixpath.join(directory, filename)
        temporary = posixpath.join(directory, ".write-" + uuid.uuid4().hex)
        try:
            with self.sftp.open(temporary, "wx") as stream:
                self.sftp.chmod(temporary, 0o600)
                stream.write(data)
                stream.flush()
            try:
                self.sftp.lstat(target)
            except OSError as exc:
                if not missing(exc):
                    raise
                self.sftp.rename(temporary, target)
            else:
                # Do not implement a remove-then-rename fallback: it loses atomicity.
                self.sftp.posix_rename(temporary, target)
        finally:
            try:
                self.sftp.remove(temporary)
            except (OSError, EOFError):
                pass

    def save(self, name, manifest):
        self.write(
            self.directory(name),
            "manifest.json",
            json.dumps(manifest, sort_keys=True).encode("utf-8"),
        )

    def archive(self, name, expected):
        if self.load(name) != expected:
            raise WorkspaceError("Workspace metadata changed; archive cancelled.")
        archive_root = posixpath.join(self.root, ".archives")
        self.private_directory(archive_root, create=True)
        destination = posixpath.join(archive_root, name + "-" + uuid.uuid4().hex)
        # One same-filesystem rename preserves all files, permissions and history.
        # Standard SFTP rename refuses a destination that already exists.
        self.sftp.rename(self.directory(name), destination)
        return destination

    def load(self, name):
        directory = self.directory(name)
        try:
            self.private_directory(self.root)
            self.private_directory(directory)
        except OSError as exc:
            if missing(exc):
                raise WorkspaceMissing(
                    f"Remote workspace directory is missing: {directory}. "
                    "Attach using the saved local name to start a fresh workspace."
                ) from exc
            raise
        path = posixpath.join(directory, "manifest.json")
        try:
            attrs = self.sftp.lstat(path)
        except OSError as exc:
            if missing(exc):
                raise WorkspaceError(
                    f"Remote workspace metadata is missing: {path}. Existing files were preserved."
                ) from exc
            raise
        if (
            not stat.S_ISREG(attrs.st_mode)
            or attrs.st_uid != self.uid
            or stat.S_IMODE(attrs.st_mode) & 0o077
            or attrs.st_size > 65536
        ):
            raise WorkspaceError("Unsafe or oversized workspace manifest.")
        with self.sftp.open(path, "rb") as stream:
            data = stream.read(65537)
        try:
            value = json.loads(data)
            if (
                not isinstance(value, dict)
                or value.get("version") != 1
                or value.get("name") != name
                or not re.fullmatch(r"[0-9a-f]{32}", value.get("uuid", ""))
                or value.get("history") not in ("memory", "private")
                or not isinstance(value.get("server_epoch"), str)
                or not re.fullmatch(r"[0-9]+:[0-9]+", value["server_epoch"])
            ):
                raise ValueError
            return value
        except (ValueError, TypeError) as exc:
            raise WorkspaceError(
                "Invalid/incomplete workspace manifest; existing files were preserved."
            ) from exc

    def names(self):
        try:
            self.private_directory(self.root)
        except OSError as exc:
            if missing(exc):
                return []
            raise
        return sorted(
            entry.filename
            for entry in self.sftp.listdir_attr(self.root)
            if stat.S_ISDIR(entry.st_mode)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", entry.filename)
        )
