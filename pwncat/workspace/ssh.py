"""Connection ownership and strict host verification for workspace channels."""

from __future__ import annotations

import getpass
import os
import shlex
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

import paramiko

from . import ConnectionLost, OutcomeUnknown, WorkspaceError
from .hostkeys import HostKeyPolicy, host_keys_path


def close_channel(channel):
    """A dead transport must not interrupt terminal restoration or cleanup."""
    try:
        channel.close()
    except (OSError, EOFError, paramiko.SSHException):
        pass


@dataclass(frozen=True)
class SSHProfile:
    host: str
    user: str
    port: int = 22
    identity: str | None = None
    known_hosts: str | None = None
    password: str | None = field(default=None, repr=False)
    passphrase: str | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, address, **options):
        try:
            if any(ord(c) < 32 for c in address):
                raise ValueError
            parsed = urlsplit(address if "://" in address else "ssh://" + address)
            if (
                parsed.scheme != "ssh"
                or not parsed.hostname
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError
            host = parsed.hostname
            user = unquote(parsed.username) if parsed.username else getpass.getuser()
            port = options.pop("port", None)
            if port is None:
                port = parsed.port if parsed.port is not None else 22
            if (
                not 1 <= port <= 65535
                or any(c.isspace() for c in host)
                or not user
                or any(ord(c) < 32 for c in user)
            ):
                raise ValueError
            return cls(host, user, port, **options)
        except (ValueError, TypeError) as exc:
            raise WorkspaceError(
                "Use [ssh://]user@hostname[:port], without a password in the URL."
            ) from exc


class SSHConnection:
    """Own the SSHClient, not just one of its channels. No shell bootstrap."""

    def __init__(self, profile: SSHProfile, *, confirm_host_key=None):
        self.profile = profile
        self.confirm_host_key = confirm_host_key
        self.client = None
        self.sftp = None
        self._forwards = None

    def connect(self):
        self.close()
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
            if self.profile.known_hosts:
                try:
                    client.load_host_keys(os.path.expanduser(self.profile.known_hosts))
                except FileNotFoundError:
                    pass  # A first-use confirmation can create this file.
            client.set_missing_host_key_policy(
                HostKeyPolicy(
                    host_keys_path(self.profile.known_hosts), self.confirm_host_key
                )
            )
            client.connect(
                hostname=self.profile.host,
                port=self.profile.port,
                username=self.profile.user,
                key_filename=os.path.expanduser(self.profile.identity)
                if self.profile.identity
                else None,
                password=self.profile.password,
                passphrase=self.profile.passphrase,
                allow_agent=True,
                look_for_keys=self.profile.identity is None,
                timeout=10,
                banner_timeout=10,
                auth_timeout=15,
            )
            client.get_transport().set_keepalive(15)
            self.client = client
        except (paramiko.AuthenticationException, paramiko.BadHostKeyException) as exc:
            client.close()
            raise WorkspaceError(
                f"SSH identity/authentication check failed: {exc}"
            ) from exc
        except WorkspaceError:
            client.close()
            raise
        except (OSError, EOFError, paramiko.SSHException) as exc:
            client.close()
            raise ConnectionLost(f"SSH connection failed: {exc}") from exc
        except BaseException:
            client.close()
            raise
        return self

    def active(self):
        return bool(
            self.client
            and self.client.get_transport()
            and self.client.get_transport().is_active()
        )

    def open_channel(self, command: str, *, terminal=False, size=(80, 24)):
        if not self.active():
            raise ConnectionLost("SSH is disconnected.")
        channel = None
        try:
            channel = self.client.get_transport().open_session(timeout=10)
            channel.settimeout(10)
            if terminal:
                channel.get_pty(
                    term=os.environ.get("TERM", "xterm-256color"),
                    width=size[0],
                    height=size[1],
                )
            channel.exec_command(command)
            return channel
        except (OSError, EOFError, paramiko.SSHException) as exc:
            if channel:
                close_channel(channel)
            # An exec request may have reached the server even if acknowledgement failed.
            raise OutcomeUnknown(
                "SSH command acknowledgement was lost; inspect before retrying."
            ) from exc

    def execute(self, argv, *, timeout=10, limit=1024 * 1024):
        channel = self.open_channel(shlex.join(str(a) for a in argv))
        stdout, stderr = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        try:
            while True:
                while channel.recv_ready():
                    stdout.extend(channel.recv(32768))
                    if len(stdout) > limit:
                        raise WorkspaceError("Remote response exceeds the size limit.")
                while channel.recv_stderr_ready():
                    stderr.extend(channel.recv_stderr(32768))
                    if len(stderr) > limit:
                        raise WorkspaceError(
                            "Remote error response exceeds the size limit."
                        )
                if (
                    channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                ):
                    status = channel.recv_exit_status()
                    if status == -1:
                        raise OutcomeUnknown(
                            "Remote command ended without a status; inspect before retrying."
                        )
                    return status, bytes(stdout), bytes(stderr)
                if not self.active() or time.monotonic() >= deadline:
                    raise OutcomeUnknown(
                        "Remote command outcome is unknown; it was not retried."
                    )
                time.sleep(0.01)
        finally:
            close_channel(channel)

    def filesystem(self):
        if self.sftp is None:
            try:
                self.sftp = self.client.open_sftp()
                self.sftp.get_channel().settimeout(15)
            except (OSError, EOFError, paramiko.SSHException) as exc:
                raise WorkspaceError(
                    "SFTP is required for workspace metadata and file transfers."
                ) from exc
        return self.sftp

    def local_forwards(self):
        if not self.active():
            raise ConnectionLost("SSH is disconnected.")
        if self._forwards is None:
            from .forwarding import LocalForwards

            self._forwards = LocalForwards(self.client.get_transport())
        return self._forwards

    def close(self):
        try:
            if self._forwards is not None:
                self._forwards.close()
                self._forwards = None
            if self.sftp is not None:
                try:
                    self.sftp.close()
                except (OSError, EOFError, paramiko.SSHException):
                    pass
                self.sftp = None
        finally:
            if self.client is not None:
                self.client.close()
                self.client = None
