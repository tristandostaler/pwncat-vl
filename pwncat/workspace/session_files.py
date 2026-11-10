"""Verified file transfers through the selected pwncat session's platform."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
import uuid

from . import WorkspaceError
from .files import copy_stream, stream_hash


def _remote_path(platform, value):
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise WorkspaceError("Use a nonempty remote path without control characters.")
    # The Windows platform interpolates paths into PowerShell strings and uses
    # -Path (which expands wildcards). Refuse syntax it cannot quote literally.
    if platform.name == "windows" and any(char in value for char in '"`$*?[]'):
        raise WorkspaceError("This Windows path contains unsupported characters.")
    path = platform.Path(value).expanduser()
    if platform.name != "windows" and not path.is_absolute() and str(path).startswith("-"):
        path = platform.Path("./" + str(path))
    return path


def _stat(platform, path):
    try:
        if platform.name == "windows":
            return platform.stat(str(path))
        return platform.lstat(str(path))
    except FileNotFoundError:
        return None


def _regular(platform, attrs):
    if platform.name == "windows":
        flags = attrs.st_file_attributes
        unsafe = (
            getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
            | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            | getattr(stat, "FILE_ATTRIBUTE_DEVICE", 0x40)
        )
        return not flags & unsafe
    return stat.S_ISREG(attrs.st_mode)


def _destination(platform, path, overwrite):
    attrs = _stat(platform, path)
    if attrs is None:
        return
    if not _regular(platform, attrs):
        raise WorkspaceError("Destination is not a regular file (symlinks are refused).")
    if not overwrite:
        raise WorkspaceError("Destination exists; use --overwrite explicitly.")


def _private_stage(platform, path):
    """The upload owner must be able to traverse its private staging directory."""
    if platform.name == "windows":
        return
    attrs = _stat(platform, path)
    if attrs is None or not stat.S_ISDIR(attrs.st_mode):
        raise WorkspaceError("Upload staging directory could not be verified.")
    if stat.S_IMODE(attrs.st_mode) != 0o700:
        platform.chmod(str(path), 0o700)
        attrs = _stat(platform, path)
        if attrs is None or stat.S_IMODE(attrs.st_mode) != 0o700:
            raise WorkspaceError("Upload staging directory is not private and searchable.")


def _publish(platform, temporary, remote, overwrite):
    if not overwrite:
        # Hard-link publication refuses an existing name atomically.
        platform.link_to(str(temporary), str(remote))
    elif platform.name != "windows":
        platform.rename(str(temporary), str(remote))
    else:
        # Rename-Item accepts a new name in the same directory but cannot
        # replace an existing name. Keep the old file until publication.
        old = _stat(platform, remote)
        backup = remote.parent / (".pwncat-backup-" + uuid.uuid4().hex)
        if old is not None:
            platform.rename(str(remote), backup.name)
        try:
            platform.rename(str(temporary), remote.name)
        except BaseException:
            if old is not None:
                try:
                    platform.rename(str(backup), remote.name)
                except Exception as rollback:
                    raise WorkspaceError(
                        f"Replacement failed; the previous file remains at {backup}."
                    ) from rollback
            raise
        if old is not None:
            platform.unlink(str(backup))


def upload(platform, source, destination, *, overwrite=False, progress=None, status=None):
    """Stage on the selected host, verify bytes, then publish the file."""
    remote = _remote_path(platform, destination)
    _destination(platform, remote, overwrite)
    stage = remote.parent / (".pwncat-upload-" + uuid.uuid4().hex)
    temporary = stage / "data"
    created = False
    with open(os.path.expanduser(source), "rb") as local:
        before = os.fstat(local.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise WorkspaceError("Source must be a regular file.")
        if status:
            status("copying", before.st_size)
        try:
            platform.mkdir(str(stage), mode=0o700)
            created = True
            _private_stage(platform, stage)
            with platform.open(str(temporary), "wb") as remote_stream:
                result = copy_stream(local, remote_stream, progress)
                remote_stream.flush()
            if platform.name != "windows":
                platform.chmod(str(temporary), 0o600)
            after = os.fstat(local.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise WorkspaceError("Source changed during upload; destination was not published.")
            if status:
                status("verifying", before.st_size)
            with platform.open(str(temporary), "rb") as remote_stream:
                if stream_hash(remote_stream) != result.sha256:
                    raise WorkspaceError("Upload verification failed; destination was not published.")
            if status:
                status("publishing", before.st_size)
            _destination(platform, remote, overwrite)
            _publish(platform, temporary, remote, overwrite)
            return result
        finally:
            if created:
                if platform.name != "windows":
                    try:
                        # Recover a directory that lost its search bit before
                        # attempting to remove the temporary file inside it.
                        platform.chmod(str(stage), 0o700)
                    except (OSError, WorkspaceError):
                        pass
                try:
                    platform.unlink(str(temporary))
                except (FileNotFoundError, OSError):
                    pass
                try:
                    platform.rmdir(str(stage))
                except (FileNotFoundError, OSError):
                    pass


def download(platform, source, destination, *, overwrite=False, progress=None, status=None):
    """Read from the selected host and publish locally after verification."""
    remote = _remote_path(platform, source)
    before = _stat(platform, remote)
    if before is None or not _regular(platform, before):
        raise WorkspaceError("Source must be a regular remote file (symlinks are refused).")
    if status:
        status("copying", before.st_size)
    destination = os.path.abspath(os.path.expanduser(destination))
    if os.path.lexists(destination):
        if not stat.S_ISREG(os.lstat(destination).st_mode):
            raise WorkspaceError("Local destination is not a regular file.")
        if not overwrite:
            raise WorkspaceError("Local destination exists; use --overwrite explicitly.")
    stage = tempfile.mkdtemp(prefix=".workspace-", dir=os.path.dirname(destination))
    temporary = os.path.join(stage, "data")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as local, platform.open(str(remote), "rb") as remote_stream:
            result = copy_stream(remote_stream, local, progress)
            local.flush()
            os.fsync(local.fileno())
        after = _stat(platform, remote)
        if after is None or (before.st_size, before.st_mtime) != (after.st_size, after.st_mtime):
            raise WorkspaceError("Remote source changed during download; destination was not published.")
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
            os.link(temporary, destination)
        return result
    finally:
        shutil.rmtree(stage)
