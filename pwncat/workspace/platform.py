"""Expose the workspace's authenticated SSHClient as a pwncat channel.

The workspace owns one ``paramiko.SSHClient`` per remote host (``SSHConnection``
in ``ssh.py``).  Opening one more shell channel through it is cheap, reuses the
host-key policy and authentication state, and leaves the tmux display channel,
the tmux control channel and the SFTP channel alone.

The resulting channel plugs into the *normal* pwncat console:
``manager.create_session(platform="linux", channel=WorkspaceChannel(backend))``.
No custom ``Platform`` subclass is needed; ``Linux`` already implements the
``Platform`` contract and ``Session`` calls ``get_pty()``, ``get_host_hash()``
and ``exit()`` on it exactly as it does for a standalone ``pwncat-vl`` session.
"""
from __future__ import annotations

import os
import select
import socket
import time

import pwncat.channel

class WorkspaceChannel(pwncat.channel.Channel):
    """One SSH shell channel on the workspace's existing SSHClient."""

    def __init__(self, backend, **kwargs):
        profile = backend.connection.profile

        super().__init__(host=profile.host, port=profile.port, user=profile.user)

        self.backend = backend
        # ``Channel.__str__`` and ``Session`` both read ``self.address``.
        self.address = (profile.host, profile.port)
        self._connected = False

        client = backend.connection.client
        if client is None:
            raise pwncat.channel.ChannelError(
                self, "workspace SSH client is not connected"
            )

        try:
            columns, rows = os.get_terminal_size(0)
        except OSError:
            columns, rows = 80, 24

        self.channel = client.invoke_shell(width=columns, height=rows)
        self.channel.setblocking(False)
        self._connected = True

    @property
    def connected(self) -> bool:
        return self._connected

    def send(self, data: bytes) -> int:
        if not self._connected:
            raise pwncat.channel.ChannelClosed(self)

        view = memoryview(data)
        while view:
            try:
                sent = self.channel.send(view)
            except BlockingIOError:
                select.select([], [self.channel], [], 0.5)
                continue
            except Exception as exc:
                self._connected = False
                raise pwncat.channel.ChannelClosed(self) from exc

            if sent == 0:
                time.sleep(0.001)
                continue
            view = view[sent:]

        return len(data)

    def recv(self, count: int | None = None) -> bytes:
        if not self._connected:
            raise pwncat.channel.ChannelClosed(self)

        # ``paramiko.Channel.recv`` needs an integer; ``Channel.peek`` and
        # ``ChannelFile.readall`` may call ``recv(None)``.
        if count is None:
            count = 65536

        if self.peek_buffer:
            data = self.peek_buffer[:count]
            self.peek_buffer = self.peek_buffer[len(data) :]
            count -= len(data)
        else:
            data = b""

        if count == 0:
            return data

        try:
            new = self.channel.recv(count)
            if new == b"":
                self._connected = False
                raise pwncat.channel.ChannelClosed(self)
            return data + new
        except (BlockingIOError, socket.timeout):
            # Paramiko reports an idle nonblocking read as socket.timeout.
            # Keep the channel usable and return any already-buffered data.
            return data
        except Exception as exc:
            self._connected = False
            raise pwncat.channel.ChannelClosed(self) from exc

    def close(self):
        if not self._connected:
            return
        self._connected = False
        try:
            self.channel.close()
        except Exception:
            pass
