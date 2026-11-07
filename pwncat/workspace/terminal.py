"""Exclusive local terminal ownership for a native tmux display."""

from __future__ import annotations

import os
import select
import signal
import sys

if os.name != "nt":
    import termios
    import tty

from . import ConnectionLost, WorkspaceError
from .ssh import close_channel


class InputFilter:
    """Ctrl-G or Ctrl-] opens local actions; doubling sends the literal prefix."""

    def __init__(self):
        self.prefix = None

    def feed(self, data):
        output = bytearray()
        for byte in data:
            if self.prefix is not None:
                prefix, self.prefix = self.prefix, None
                if byte in (ord("p"), ord("P"), 16, ord("d"), ord("D"), 4):
                    # Discard trailing input: it must never run after reconnect/palette.
                    return bytes(output), "palette" if byte in (
                        ord("p"),
                        ord("P"),
                        16,
                    ) else "detach"
                if byte == prefix:
                    output.append(prefix)
                else:
                    output.extend((prefix, byte))
            elif byte in (7, 29):
                self.prefix = byte
            else:
                output.append(byte)
        return bytes(output), None


def terminal_size():
    try:
        size = os.get_terminal_size(sys.stdin.fileno())
        return size.columns, size.lines
    except OSError:
        return 80, 24


def display(channel, connection):
    if os.name == "nt":
        from .windows_terminal import display as windows_display

        return windows_display(channel, connection)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        close_channel(channel)
        raise WorkspaceError("Attach requires an interactive terminal.")
    descriptor = sys.stdin.fileno()
    original = termios.tcgetattr(descriptor)
    previous_handlers = {
        sig: signal.getsignal(sig)
        for sig in (signal.SIGWINCH, signal.SIGTERM, signal.SIGHUP)
    }
    resized = [False]
    keys = InputFilter()

    def interrupted(*_):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGWINCH, lambda *_: resized.__setitem__(0, True))
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
        tty.setraw(descriptor)
        channel.settimeout(2)
        while True:
            if resized[0]:
                resized[0] = False
                columns, rows = terminal_size()
                channel.resize_pty(width=columns, height=rows)
            readable, _, _ = select.select([descriptor, channel], [], [], 0.2)
            # Drain output before accepting more input, including a pending remote exit.
            if channel in readable:
                data = channel.recv(65536)
                if not data:
                    status = channel.recv_exit_status()
                    if not connection.active() or status == -1:
                        raise ConnectionLost("SSH display connection was lost.")
                    if status:
                        raise WorkspaceError(
                            f"Tmux display exited with status {status}."
                        )
                    return "detach"
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            if descriptor in readable:
                data = os.read(descriptor, 4096)
                if not data:
                    return "detach"
                output, action = keys.feed(data)
                if output:
                    channel.sendall(output)
                if action:
                    return action
            if not connection.active():
                raise ConnectionLost("SSH disconnected; input was not queued.")
    except (OSError, EOFError) as exc:
        raise ConnectionLost(
            "Terminal transport interrupted; input was not replayed."
        ) from exc
    finally:
        close_channel(channel)
        try:
            termios.tcsetattr(descriptor, termios.TCSADRAIN, original)
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
        # A dropped connection cannot deliver tmux's terminal cleanup sequence.
        sys.stdout.write(
            "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l"
            "\x1b[?2004l\x1b[?1049l\x1b[?25h\x1b[0m"
        )
        sys.stdout.flush()
