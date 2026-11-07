"""An isolated tmux server per authenticated SSH workspace."""

from __future__ import annotations

import posixpath
import re
import shlex
import uuid

from . import (
    ConnectionLost,
    IdentityMismatch,
    OutcomeUnknown,
    WorkspaceError,
    WorkspaceMissing,
    WorkspaceStopped,
)
from .model import Pane, WorkspaceRef, pane_id
from .protocol import ControlClient, command_line
from .state import StateStore


class TmuxWorkspace:
    def __init__(self, connection):
        self.connection = connection
        self.control = None
        self.ref = None
        status, output, error = connection.execute(
            [
                "sh",
                "-c",
                'id -u; printf "%s\\n" "$HOME"; command -v tmux; command -v bash; tmux -V',
            ]
        )
        lines = output.decode("utf-8", "strict").splitlines()
        if status or len(lines) != 5 or not lines[0].isdigit():
            raise WorkspaceError(
                "Workspace requires a quiet SSH exec shell, SFTP, Bash, and tmux 3.3+. "
                + error.decode("utf-8", "replace")
            )
        version = re.fullmatch(r"tmux (\d+)\.(\d+)[a-z]?", lines[4])
        if not version or tuple(map(int, version.groups())) < (3, 3):
            raise WorkspaceError(
                "Workspace requires a supported tmux release (3.3 or newer)."
            )
        self.home, self.binary, self.shell = lines[1:4]
        if not self.binary.startswith("/") or not self.shell.startswith("/"):
            raise WorkspaceError(
                "Remote tmux and Bash must resolve to absolute executable paths."
            )
        self.store = StateStore(connection.filesystem(), self.home, int(lines[0]))

    def _argv(self, socket_path, *args):
        return [self.binary, "-N", "-S", socket_path, *args]

    def _identity(self, socket_path):
        try:
            status, output, _ = self.connection.execute(
                self._argv(
                    socket_path,
                    "display-message",
                    "-p",
                    "-t",
                    "workspace",
                    "#{@workspace_uuid} #{pid}:#{start_time}",
                )
            )
        except OutcomeUnknown as exc:
            # This query is read-only. No workspace mutation was submitted.
            raise ConnectionLost("Workspace identity check was interrupted.") from exc
        if status:
            raise WorkspaceStopped(
                "Workspace is not running. It was not recreated; saved history is unchanged."
            )
        values = output.decode("ascii", "strict").strip().split()
        if len(values) != 2 or not re.fullmatch(r"\d+:\d+", values[1]):
            raise IdentityMismatch("Workspace server identity is missing or invalid.")
        return values

    def load(self, name, expected=None):
        manifest = self.store.load(name)
        socket_path = posixpath.join(self.store.directory(name), "tmux.sock")
        identity, epoch = self._identity(socket_path)
        ref = WorkspaceRef(
            name, manifest["uuid"], manifest["server_epoch"], socket_path
        )
        if (
            identity != ref.uuid
            or epoch != ref.server_epoch
            or (expected and ref != expected)
        ):
            raise IdentityMismatch(
                "Workspace server changed. Reconnection stopped without replacing any panes."
            )
        self.ref = ref
        return ref

    def attach_or_recover(self, name, expected):
        """Reattach, or start fresh after a reset; preserve any stopped state."""
        try:
            self.load(name, expected=expected)
            return False
        except WorkspaceMissing:
            self.create(name)
        except WorkspaceStopped:
            manifest = self.store.load(name)
            history_limit = manifest.get("history_limit", 50000)
            if type(history_limit) is not int or not 100 <= history_limit <= 200000:
                raise WorkspaceError(
                    "Invalid saved history limit; existing files were preserved."
                )
            # Archive verifies the saved identity, stopped socket and process
            # before moving any existing files. Other errors never recreate.
            self.archive(name, expected=expected)
            self.create(
                name,
                history=manifest["history"],
                history_limit=history_limit,
            )
        return True

    def create(self, name, *, history="memory", history_limit=50000):
        if history not in ("memory", "private") or not 100 <= history_limit <= 200000:
            raise WorkspaceError("Invalid history policy or limit (100–200000 lines).")
        directory = self.store.create(name)
        identity = uuid.uuid4().hex
        socket_path = posixpath.join(directory, "tmux.sock")
        rc_path = posixpath.join(directory, "shell.bash")
        history_path = posixpath.join(directory, "history")
        self.store.private_directory(history_path, create=True)
        # Source the user's shell configuration first, then apply workspace policy.
        rc = "[[ -f ~/.bashrc ]] && source ~/.bashrc\numask 077\n"
        rc += f"HISTSIZE={history_limit}\nHISTFILESIZE={history_limit}\n"
        if history == "private":
            rc += (
                f"HISTFILE={shlex.quote(history_path)}/pane-${{TMUX_PANE#%}}-${{BASHPID:-$$}}.history\n"
                ': >> "$HISTFILE"\n'
                "shopt -s histappend\n"
                # Bash 3.2's append guard skips a fresh, empty history forever.
                # Each pane has one writer, so an atomic snapshot is safe there.
                "if (( BASH_VERSINFO[0] < 4 )); then\n"
                '_workspace_history_append() { builtin history -w "$HISTFILE.tmp" && command mv -f -- "$HISTFILE.tmp" "$HISTFILE"; }\n'
                "else\n"
                '_workspace_history_append() { builtin history -a "$HISTFILE"; }\n'
                "fi\n"
                "if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a '* ]]; then\n"
                "    PROMPT_COMMAND+=('_workspace_history_append')\n"
                "else\n"
                "    PROMPT_COMMAND=\"${PROMPT_COMMAND:+$PROMPT_COMMAND$'\\n'}_workspace_history_append\"\n"
                "fi\n"
            )
        else:
            rc += "unset HISTFILE\n"
        self.store.write(directory, "shell.bash", rc.encode())
        launch = shlex.join([self.shell, "--rcfile", rc_path, "-i"])
        config = b"".join(
            command_line(args)
            for args in [
                ["set-option", "-g", "@workspace_uuid", identity],
                ["set-option", "-g", "default-shell", self.shell],
                ["set-option", "-g", "default-command", launch],
                ["set-option", "-g", "history-limit", str(history_limit)],
                ["set-option", "-g", "remain-on-exit", "on"],
                ["set-option", "-s", "exit-unattached", "off"],
                ["set-option", "-s", "set-clipboard", "off"],
                ["set-option", "-g", "allow-passthrough", "off"],
                ["set-option", "-g", "update-environment", ""],
            ]
        )
        self.store.write(directory, "tmux.conf", config)
        # Write a provisional manifest so interrupted initialization stays visible.
        manifest = {
            "version": 1,
            "name": name,
            "uuid": identity,
            "history": history,
            "history_limit": history_limit,
            "server_epoch": "pending",
        }
        self.store.save(name, manifest)
        status, _, error = self.connection.execute(
            [
                self.binary,
                "-S",
                socket_path,
                "-f",
                posixpath.join(directory, "tmux.conf"),
                "new-session",
                "-d",
                "-s",
                "workspace",
                "-c",
                self.home,
            ]
        )
        if status:
            raise WorkspaceError(
                "Workspace creation failed; its files were preserved: "
                + error.decode("utf-8", "replace")
            )
        actual, epoch = self._identity(socket_path)
        if actual != identity:
            raise IdentityMismatch("Unexpected server while creating workspace.")
        manifest["server_epoch"] = epoch
        self.store.save(name, manifest)
        return self.load(name)

    def connect_control(self):
        self.close()
        self._verify()
        channel = self.connection.open_channel(
            shlex.join(
                self._argv(
                    self.ref.socket_path,
                    "-C",
                    "attach-session",
                    "-f",
                    "no-output,ignore-size",
                    "-t",
                    "workspace",
                )
            )
        )
        self.control = ControlClient(channel)

    def _verify(self):
        if self.ref is None:
            raise WorkspaceError("Select a workspace first.")
        actual, epoch = self._identity(self.ref.socket_path)
        if (actual, epoch) != (self.ref.uuid, self.ref.server_epoch):
            raise IdentityMismatch("Workspace server changed; operation cancelled.")

    def request(self, *args):
        self._verify()
        if self.control is None:
            self.connect_control()
        return self.control.request(*args)

    def panes(self):
        # Path is a quoted display field, never a source of shell commands.
        rows = self.request(
            "list-panes",
            "-s",
            "-t",
            "workspace",
            "-F",
            "#{window_id} #{pane_id} #{pane_pid} #{pane_width} #{pane_height} "
            "#{pane_active} #{pane_dead} #{q:pane_current_path}",
        )
        result = []
        for row in rows:
            fields = shlex.split(row.decode("utf-8", "replace"))
            if len(fields) != 8 or not re.fullmatch(r"@[0-9]+", fields[0]):
                raise WorkspaceError(
                    "Unexpected pane metadata; no pane action was performed."
                )
            result.append(
                Pane(
                    pane_id(fields[1]),
                    *map(int, fields[2:5]),
                    fields[5] == "1",
                    fields[6] == "1",
                    fields[7],
                    fields[0],
                )
            )
        return result

    def current_pane(self):
        rows = self.request("display-message", "-p", "-t", "workspace", "#{pane_id}")
        if len(rows) != 1:
            raise WorkspaceError("Cannot identify the selected pane.")
        return pane_id(rows[0].decode("ascii", "strict"))

    def pane(self, target):
        pane_id(target)
        for pane in self.panes():
            if pane.id == target:
                return pane
        raise WorkspaceError("Pane no longer exists. Use 'panes' and select another.")

    def select(self, target):
        pane = self.pane(target)
        # Both targets are stable IDs from this workspace, never window indexes.
        self.request("select-window", "-t", pane.window_id)
        self.request("select-pane", "-t", pane.id)

    def new_window(self, title=None):
        args = [
            "new-window",
            "-t",
            "workspace",
            "-c",
            self.home,
            "-P",
            "-F",
            "#{pane_id}",
        ]
        if title is not None:
            if not title or len(title) > 80 or not title.isprintable():
                raise WorkspaceError("Window title must be 1–80 printable characters.")
            args.extend(["-n", title])
        rows = self.request(*args)
        if len(rows) != 1:
            raise WorkspaceError(
                "Window was requested; inspect 'panes' before repeating."
            )
        return pane_id(rows[0].decode("ascii", "strict"))

    def split(self, target, direction="horizontal"):
        if direction not in ("horizontal", "vertical"):
            raise WorkspaceError("Split direction must be horizontal or vertical.")
        self.pane(target)
        # Start in the workspace home: do not infer a nested shell's namespace.
        return self.request(
            "split-window",
            "-h" if direction == "horizontal" else "-v",
            "-t",
            target,
            "-c",
            self.home,
            "-P",
            "-F",
            "#{pane_id}",
        )

    def display(self, size, *, takeover=False):
        self._verify()
        clients = self.request(
            "list-clients", "-t", "workspace", "-F", "#{client_control_mode}"
        )
        if b"0" in clients and not takeover:
            raise WorkspaceError(
                "Another display is attached. Use --takeover to detach it explicitly."
            )
        # A new display owns size; observer control clients never affect it.
        args = ["attach-session", "-t", "workspace"]
        if takeover:
            args.append("-d")
            # -d also detaches our control observer. Reopen it on the next action.
            self.close()
        return self.connection.open_channel(
            shlex.join(self._argv(self.ref.socket_path, *args)),
            terminal=True,
            size=size,
        )

    def destroy(self):
        self._verify()
        status, _, error = self.connection.execute(
            self._argv(self.ref.socket_path, "kill-server")
        )
        if status:
            raise WorkspaceError(error.decode("utf-8", "replace"))
        self.close()

    def archive(self, name, expected=None):
        manifest = self.store.load(name)
        socket_path = posixpath.join(self.store.directory(name), "tmux.sock")
        if expected and (manifest["uuid"], manifest["server_epoch"], socket_path) != (
            expected.uuid,
            expected.server_epoch,
            expected.socket_path,
        ):
            raise IdentityMismatch(
                "Saved workspace identity changed; archive cancelled."
            )
        status, _, error = self.connection.execute(
            [
                "sh",
                "-c",
                'LC_ALL=C; export LC_ALL; exec "$@"',
                "workspace-archive",
                *self._argv(socket_path, "list-sessions"),
            ]
        )
        if status == 0:
            raise WorkspaceError(
                "Workspace server is still running. Stop it before archiving."
            )
        expected_errors = (
            f"no server running on {socket_path}",
            f"error connecting to {socket_path} (No such file or directory)",
        )
        if (
            status != 1
            or error.decode("utf-8", "replace").strip() not in expected_errors
        ):
            raise WorkspaceError(
                "Cannot verify the workspace server is stopped; archive cancelled."
            )
        # A live tmux server may have lost its socket. Refuse to rename its state
        # even then. A reused PID or unsupported ps also requires manual review.
        pid = manifest["server_epoch"].split(":", 1)[0]
        status, output, error = self.connection.execute(
            ["sh", "-c", 'exec ps -p "$1" -o pid=', "workspace-archive", pid]
        )
        if status != 1 or output.strip() or error.strip():
            raise WorkspaceError(
                "Cannot confirm the recorded tmux process has stopped. "
                "Archive cancelled; saved files were retained."
            )
        destination = self.store.archive(name, manifest)
        if self.ref and self.ref.name == name:
            self.close()
            self.ref = None
        return destination

    def close(self):
        if self.control:
            control = self.control
            self.control = None
            control.close()
