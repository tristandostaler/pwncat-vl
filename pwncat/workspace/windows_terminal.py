"""Native Windows 10+ terminal bridge; WSL uses the POSIX bridge."""

from __future__ import annotations

import codecs
import signal
import sys
import time

from prompt_toolkit.keys import Keys

from . import ConnectionLost, WorkspaceError
from .ssh import close_channel
from .terminal import InputFilter


def terminal_devices():
    from prompt_toolkit.input import create_input
    from prompt_toolkit.output.windows10 import Windows10_Output, is_win_vt100_enabled

    if not is_win_vt100_enabled():
        raise WorkspaceError(
            "Native attachment requires Windows 10+ with virtual terminal support, such as Windows Terminal."
        )
    return create_input(), Windows10_Output(sys.stdout)


def key_bytes(events):
    chunks = []
    for event in events:
        if event.key in (Keys.WindowsMouseEvent, Keys.Ignore):
            continue
        if event.key == Keys.BracketedPaste:
            chunks.append("\x1b[200~" + event.data + "\x1b[201~")
        else:
            chunks.append(event.data)
    return "".join(chunks).encode("utf-8")


def display(channel, connection):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        close_channel(channel)
        raise WorkspaceError("Attach requires an interactive terminal.")
    incoming = outgoing = None
    handlers = {}
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    keys = InputFilter()

    def interrupted(*_):
        raise KeyboardInterrupt

    try:
        incoming, outgoing = terminal_devices()
        for sig in (signal.SIGTERM, getattr(signal, "SIGBREAK", signal.SIGINT)):
            handlers[sig] = signal.signal(sig, interrupted)
        channel.settimeout(2)
        last_size, last_input = None, time.monotonic()
        with incoming.raw_mode():
            while True:
                size = outgoing.get_size()
                dimensions = max(1, size.columns), max(1, size.rows)
                if dimensions != last_size:
                    channel.resize_pty(width=dimensions[0], height=dimensions[1])
                    last_size = dimensions
                if channel.recv_ready():
                    outgoing.write_raw(decoder.decode(channel.recv(65536)))
                    outgoing.flush()
                elif channel.exit_status_ready():
                    status = channel.recv_exit_status()
                    if not connection.active() or status == -1:
                        raise ConnectionLost("SSH display connection was lost.")
                    if status:
                        raise WorkspaceError(
                            f"Tmux display exited with status {status}."
                        )
                    return "detach"
                events = incoming.read_keys()
                if events:
                    last_input = time.monotonic()
                elif time.monotonic() - last_input > 0.05:
                    events = incoming.flush_keys()
                output, action = keys.feed(key_bytes(events))
                if output:
                    channel.sendall(output)
                if action:
                    return action
                if not connection.active():
                    raise ConnectionLost("SSH disconnected; input was not queued.")
                time.sleep(0.02)
    except (OSError, EOFError) as exc:
        raise ConnectionLost(
            "Terminal transport interrupted; input was not replayed."
        ) from exc
    finally:
        close_channel(channel)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
        if incoming:
            incoming.close()
        if outgoing:
            outgoing.write_raw(
                "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1049l\x1b[?25h\x1b[0m"
            )
            outgoing.flush()
