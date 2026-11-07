"""Bounded tmux control protocol; no terminal data is executed or rendered here."""

from __future__ import annotations

import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass

import paramiko

from . import ConnectionLost, OutcomeUnknown, WorkspaceError
from .ssh import close_channel


def command_line(arguments):
    # tmux has its own parser. Shell quoting alone is not sufficient here.
    def quote(value):
        value = str(value)
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise WorkspaceError("Control arguments cannot contain control characters.")
        return (
            '"'
            + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
            + '"'
        )

    return (" ".join(quote(arg) for arg in arguments) + "\n").encode("utf-8")


@dataclass(frozen=True)
class Response:
    ok: bool
    lines: tuple[bytes, ...]


class ControlParser:
    MAX_BYTES = 1024 * 1024

    def __init__(self):
        self.buffer = bytearray()
        self.block = None
        self.lines = []
        self.size = 0

    def feed(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > self.MAX_BYTES:
            raise WorkspaceError("Oversized tmux control record.")
        events = []
        while b"\n" in self.buffer:
            raw, _, self.buffer = self.buffer.partition(b"\n")
            line = bytes(raw)
            match = re.fullmatch(rb"%(begin|end|error) (\d+) (\d+) (\d+)", line)
            if match:
                kind, *key = match.groups()
                if kind == b"begin":
                    if self.block is not None:
                        raise WorkspaceError("Nested tmux response.")
                    self.block, self.lines, self.size = key, [], 0
                else:
                    if self.block != key:
                        raise WorkspaceError("Mismatched tmux response boundary.")
                    events.append(Response(kind == b"end", tuple(self.lines)))
                    self.block, self.lines, self.size = None, [], 0
            elif self.block is not None:
                self.size += len(line) + 1
                if self.size > self.MAX_BYTES:
                    raise WorkspaceError("Oversized tmux response.")
                self.lines.append(line)
            elif line.startswith(b"%"):
                events.append(line)
            else:
                raise WorkspaceError("Unexpected output on the tmux control channel.")
        return events


class ControlClient:
    """One command at a time; continuously drain bounded notifications."""

    def __init__(self, channel, timeout=10):
        self.channel = channel
        channel.settimeout(1)
        self.timeout = timeout
        self.responses = deque()
        self.notifications = deque(maxlen=128)
        self.condition = threading.Condition()
        self.writer = threading.Lock()
        self.failure = None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        try:
            self._response()  # attach-session's initial response
        except BaseException:
            self.close()
            raise

    def _read(self):
        parser = ControlParser()
        try:
            while not self.stopped.is_set():
                try:
                    data = self.channel.recv(32768)
                except socket.timeout:  # noqa: UP041 - distinct from TimeoutError on Python 3.9
                    continue
                if not data:
                    raise ConnectionLost("Tmux control connection closed.")
                with self.condition:
                    for event in parser.feed(data):
                        if isinstance(event, Response):
                            if len(self.responses) >= 4:
                                raise WorkspaceError("Unexpected tmux responses.")
                            self.responses.append(event)
                        elif event.startswith(b"%exit"):
                            self.failure = ConnectionLost("Tmux control client exited.")
                        else:
                            self.notifications.append(event)
                    self.condition.notify_all()
        except Exception as exc:  # noqa: BLE001 - propagate worker failures to its owner
            with self.condition:
                self.failure = exc
                self.condition.notify_all()

    def _response(self):
        deadline = time.monotonic() + self.timeout
        with self.condition:
            while not self.responses:
                if self.failure:
                    raise ConnectionLost(
                        f"Control channel failed: {self.failure}"
                    ) from self.failure
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Tmux response timed out.")
                self.condition.wait(remaining)
            result = self.responses.popleft()
        if not result.ok:
            raise WorkspaceError(b"\n".join(result.lines).decode("utf-8", "replace"))
        return result.lines

    def request(self, *arguments):
        payload = command_line(arguments)
        with self.writer:
            if self.failure or self.stopped.is_set():
                raise ConnectionLost("Control channel is disconnected.")
            try:
                self.channel.sendall(payload)
                return self._response()
            except (
                OSError,
                EOFError,
                ConnectionLost,
                KeyboardInterrupt,
                paramiko.SSHException,
            ) as exc:
                self.close()
                raise OutcomeUnknown(
                    "Tmux operation outcome is unknown; it was not retried."
                ) from exc

    def close(self):
        self.stopped.set()
        close_channel(self.channel)
        if threading.current_thread() is not self.thread:
            self.thread.join(timeout=1)
