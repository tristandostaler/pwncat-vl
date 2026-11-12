"""Bounded private console history, scoped to one saved workspace identity."""

from __future__ import annotations

import json
import os
import tempfile

from . import WorkspaceError

MAX_COMMANDS = 500
MAX_COMMAND_LENGTH = 4096
MAX_BYTES = 256 * 1024


class ConsoleHistory:
    def __init__(self, store, alias, connection, ref):
        self.store, self.alias = store, alias
        self.connection, self.ref = connection, ref
        self.path = store.history_path(alias)

    def _read(self, binding):
        try:
            attrs = self.store._check(self.path)
        except FileNotFoundError:
            return []
        if attrs.st_size > MAX_BYTES:
            raise WorkspaceError(
                "Console history is oversized; existing file was preserved."
            )
        try:
            with self.path.open("rb") as stream:
                value = json.loads(stream.read(MAX_BYTES + 1))
            if (
                not isinstance(value, dict)
                or set(value) != {"version", "binding", "commands"}
                or value["version"] != 1
                or not isinstance(value["binding"], str)
                or not isinstance(value["commands"], list)
                or len(value["commands"]) > MAX_COMMANDS
                or any(
                    not isinstance(line, str) or len(line) > MAX_COMMAND_LENGTH
                    for line in value["commands"]
                )
            ):
                raise ValueError
        except (TypeError, ValueError, UnicodeError) as exc:
            raise WorkspaceError(
                "Invalid console history; existing file was preserved."
            ) from exc
        return value["commands"] if value["binding"] == binding else []

    def load(self):
        with self.store._lock():
            saved = self.store.check_workspace(self.alias, self.connection, self.ref)
            return self._read(saved.console_history_binding)

    def database_uri(self):
        """Give this workspace its own persistent pwncat database."""
        with self.store._lock():
            saved = self.store.check_workspace(self.alias, self.connection, self.ref)
            return "file://" + str(self.store.root / (".db-" + saved.console_history_binding))

    def record(self, line):
        # Leading space is an explicit opt-out. Authentication prompts never
        # pass through this recorder, nor do failed/unsupported commands.
        if not line or line[0].isspace() or len(line) > MAX_COMMAND_LENGTH:
            return
        line = line.rstrip()
        with self.store._lock():
            saved = self.store.check_workspace(self.alias, self.connection, self.ref)
            binding = saved.console_history_binding
            commands = self._read(binding)
            if commands and commands[-1] == line:
                return
            commands.append(line)
            retained, size = [], 512  # Reserve space for the JSON envelope.
            for command in reversed(commands[-MAX_COMMANDS:]):
                cost = len(json.dumps(command).encode()) + 2
                if size + cost > MAX_BYTES:
                    break
                retained.append(command)
                size += cost
            document = {
                "version": 1,
                "binding": binding,
                "commands": list(reversed(retained)),
            }
            descriptor, temporary = tempfile.mkstemp(
                prefix=".history-write-", dir=self.store.root
            )
            try:
                with os.fdopen(descriptor, "w") as stream:
                    json.dump(document, stream)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
