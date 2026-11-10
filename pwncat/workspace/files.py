"""SFTP transfers with private staging and explicit overwrite semantics."""

from __future__ import annotations

import hashlib
import os
import posixpath
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass

from . import WorkspaceError
from .state import missing


@dataclass(frozen=True)
class TransferResult:
    size: int
    sha256: str


def remote_path(value):
    if not value.startswith("/") or "\x00" in value:
        raise WorkspaceError("Use an absolute path on the workspace SSH host.")
    return posixpath.normpath(value)


def copy_stream(source, destination, progress=None):
    digest, count = hashlib.sha256(), 0
    while True:
        data = source.read(65536)
        if not data:
            break
        destination.write(data)
        digest.update(data)
        count += len(data)
        if progress:
            progress(count)
    return TransferResult(count, digest.hexdigest())


def stream_hash(stream):
    digest = hashlib.sha256()
    while True:
        data = stream.read(65536)
        if not data:
            return digest.hexdigest()
        digest.update(data)


class FileService:
    def __init__(self, sftp):
        self.sftp = sftp

    def _destination(self, path, overwrite):
        try:
            attrs = self.sftp.lstat(path)
        except OSError as exc:
            if missing(exc):
                return
            raise
        if not stat.S_ISREG(attrs.st_mode):
            raise WorkspaceError(
                "Destination is not a regular file (symlinks are refused)."
            )
        if not overwrite:
            raise WorkspaceError("Destination exists; use --overwrite explicitly.")

    def upload(self, source, destination, *, overwrite=False, progress=None, status=None):
        destination = remote_path(destination)
        self._destination(destination, overwrite)
        source = os.path.expanduser(source)
        stage = posixpath.join(
            posixpath.dirname(destination), ".workspace-" + uuid.uuid4().hex
        )
        temporary = posixpath.join(stage, "data")
        self.sftp.mkdir(stage, mode=0o700)
        try:
            attrs = self.sftp.lstat(stage)
            if not stat.S_ISDIR(attrs.st_mode) or stat.S_IMODE(attrs.st_mode) & 0o077:
                raise WorkspaceError(
                    "Server did not create a private transfer directory."
                )
            with open(source, "rb") as local:
                before = os.fstat(local.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise WorkspaceError("Source must be a regular file.")
                if status:
                    status("copying", before.st_size)
                with self.sftp.open(temporary, "wx") as remote:
                    self.sftp.chmod(temporary, 0o600)
                    result = copy_stream(local, remote, progress)
                    remote.flush()
                after = os.fstat(local.fileno())
            if (before.st_size, before.st_mtime_ns) != (
                after.st_size,
                after.st_mtime_ns,
            ):
                raise WorkspaceError(
                    "Source changed during upload; destination was not published."
                )
            if status:
                status("verifying", before.st_size)
            with self.sftp.open(temporary, "rb") as remote:
                if stream_hash(remote) != result.sha256:
                    raise WorkspaceError(
                        "Upload verification failed; destination was not published."
                    )
            if status:
                status("publishing", before.st_size)
            self._destination(destination, overwrite)
            if overwrite:
                self.sftp.posix_rename(temporary, destination)
            else:
                # Standard SFTP rename fails if the destination already exists.
                self.sftp.rename(temporary, destination)
            return result
        finally:
            for path, remove in (
                (temporary, self.sftp.remove),
                (stage, self.sftp.rmdir),
            ):
                try:
                    remove(path)
                except (OSError, EOFError):
                    pass  # Connection loss may leave a private partial directory.

    def download(self, source, destination, *, overwrite=False, progress=None, status=None):
        source = remote_path(source)
        before = self.sftp.lstat(source)
        if not stat.S_ISREG(before.st_mode):
            raise WorkspaceError(
                "Source must be a regular remote file (symlinks are refused)."
            )
        if status:
            status("copying", before.st_size)
        destination = os.path.abspath(os.path.expanduser(destination))
        if os.path.lexists(destination):
            if not stat.S_ISREG(os.lstat(destination).st_mode):
                raise WorkspaceError("Local destination is not a regular file.")
            if not overwrite:
                raise WorkspaceError(
                    "Local destination exists; use --overwrite explicitly."
                )
        stage = tempfile.mkdtemp(prefix=".workspace-", dir=os.path.dirname(destination))
        temporary = os.path.join(stage, "data")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with (
                os.fdopen(descriptor, "wb") as local,
                self.sftp.open(source, "rb") as remote,
            ):
                result = copy_stream(remote, local, progress)
                local.flush()
                os.fsync(local.fileno())
            after = self.sftp.lstat(source)
            if (before.st_size, before.st_mtime) != (after.st_size, after.st_mtime):
                raise WorkspaceError(
                    "Remote source changed during download; destination was not published."
                )
            if status:
                status("verifying", before.st_size)
            with open(temporary, "rb") as local:
                if stream_hash(local) != result.sha256:
                    raise WorkspaceError("Download verification failed.")
            if status:
                status("publishing", before.st_size)
            if overwrite:
                os.replace(temporary, destination)
            else:
                os.link(
                    temporary, destination
                )  # Atomic no-clobber publication on the same filesystem.
            return result
        finally:
            shutil.rmtree(stage)
