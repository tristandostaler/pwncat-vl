"""Explicit first-use SSH host trust; known keys are never replaced."""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

import paramiko

from . import WorkspaceError
from .model import safe_text


def host_keys_path(configured=None):
    return (
        Path(configured).expanduser().absolute()
        if configured
        else Path.home() / ".ssh" / "known_hosts"
    )


def fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def confirm_host_key(hostname, key, path):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise WorkspaceError(
            f"Unknown SSH host key for {safe_text(hostname)}. "
            "Connect from an interactive terminal to review and accept its fingerprint, "
            "or provide a verified --known-hosts file."
        )
    print(
        f"\nFirst SSH connection to {safe_text(hostname)}.\n"
        f"Host key: {safe_text(key.get_name())} {fingerprint(key)}\n"
        "Compare this fingerprint with the server's trusted SSH fingerprint.\n"
        f"Accepted keys will be saved to {safe_text(path)}.",
        file=sys.stderr,
    )
    print(
        "Trust this host and save its key? [yes/no] ",
        end="",
        file=sys.stderr,
        flush=True,
    )
    return sys.stdin.readline().strip() == "yes"


@contextmanager
def locked_host_file(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or (
        path.exists()
        and getattr(path.lstat(), "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise WorkspaceError("Refusing to write a linked known_hosts file.")
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "a+b") as stream:
        attrs = os.fstat(stream.fileno())
        if not stat.S_ISREG(attrs.st_mode) or (
            os.name != "nt"
            and (attrs.st_uid != os.getuid() or stat.S_IMODE(attrs.st_mode) & 0o022)
        ):
            raise WorkspaceError(
                "The known_hosts file must be a regular file owned by you and not writable by others."
            )
        if os.name == "nt":
            import msvcrt

            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield stream
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream, fcntl.LOCK_EX)
            yield stream


def save_host_key(path, hostname, key):
    try:
        with locked_host_file(path) as stream:
            # Re-read under the lock: another connection may have saved a key
            # while this connection was waiting for the user's answer.
            # Read through the locked handle (Windows locks exclude other
            # handles, even within this process). Preserve all original bytes.
            stream.seek(0)
            found = False
            for number, raw in enumerate(stream, 1):
                line = raw.decode("utf-8").strip()
                if not line or line.startswith("#"):
                    continue
                entry = paramiko.hostkeys.HostKeyEntry.from_line(line, number)
                if entry is None:
                    continue
                keys = paramiko.HostKeys()
                for name in entry.hostnames:
                    keys.add(name, entry.key.get_name(), entry.key)
                if keys.lookup(hostname) is not None:
                    if not keys.check(hostname, key):
                        raise WorkspaceError(
                            "The saved SSH host key changed during confirmation. Connection stopped; no key was replaced."
                        )
                    found = True
            if found:
                return
            stream.seek(0, os.SEEK_END)
            prefix = b""
            if stream.tell():
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b"\n":
                    prefix = b"\n"
            record = f"{hostname} {key.get_name()} {key.get_base64()}\n".encode()
            stream.write(prefix + record)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, UnicodeError, paramiko.SSHException) as exc:
        raise WorkspaceError(
            f"Could not save the SSH host key to {safe_text(path)}; connection stopped: {safe_text(exc)}"
        ) from exc


class HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, path, confirm=None):
        self.path, self.confirm = path, confirm

    def missing_host_key(self, client, hostname, key):
        if self.confirm is None:
            raise WorkspaceError(
                f"Unknown SSH host key for {safe_text(hostname)}. "
                "Connect interactively to review and accept it first."
            )
        if not self.confirm(hostname, key, self.path):
            raise WorkspaceError("SSH host key was not accepted. Connection stopped.")
        save_host_key(self.path, hostname, key)
        client.get_host_keys().add(hostname, key.get_name(), key)
