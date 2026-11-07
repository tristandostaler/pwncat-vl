"""Interactive workspace commands with explicit pane and SSH filesystem contexts."""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass, field

from prompt_toolkit.history import InMemoryHistory
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import ConnectionLost, OutcomeUnknown, WorkspaceError
from .console_history import ConsoleHistory
from .console_ui import (
    colors_enabled,
    create_prompt,
    output_console,
    prompt_color_depth,
    prompt_text,
)
from .files import FileService
from .forwarding import LOOPBACK, destination_address, port_number
from .model import pane_id, safe_text
from .saved_forwards import SavedForwards

COMMANDS = {
    "help": ("help [COMMAND]", "Show workspace commands and usage."),
    "color": (
        "color [auto|on|off]",
        "Inspect or change console colors for this client.",
    ),
    "status": ("status", "Show connection, history policy, and selected pane context."),
    "panes": ("panes", "List panes across all windows; * marks the selected pane."),
    "select": ("select %ID", "Select a pane and its window for resume and split."),
    "split": (
        "split [%ID] [horizontal|vertical]",
        "Split the selected or specified pane.",
    ),
    "window": ("window [TITLE]", "Create a window and select its first pane."),
    "upload": (
        "upload LOCAL /REMOTE [--overwrite]",
        "Upload through the workspace SSH account.",
    ),
    "download": (
        "download /REMOTE LOCAL [--overwrite]",
        "Download through the workspace SSH account.",
    ),
    "forward": (
        "forward add LOCAL_PORT [SERVER_IP] REMOTE_PORT | list | stop LOCAL_PORT",
        "Manage local forwards to services on the connected SSH host.",
    ),
    "lpwd": ("lpwd", "Show the local directory used for transfer paths."),
    "lcd": ("lcd DIRECTORY", "Change the local transfer directory."),
    "resume": ("resume", "Return to the selected remote pane."),
    "detach": ("detach", "Leave the workspace; remote processes keep running."),
}


def message(text, style="", *, console=None):
    output = console if console is not None else Console(emoji=False, highlight=False)
    output.print(Text(text, style=style))


def detail(label, value, *, console=None):
    text = Text(label + ": ", style="bold cyan")
    text.append(safe_text(value), style="default")
    output = console if console is not None else Console(emoji=False, highlight=False)
    output.print(text)


@dataclass
class ConsoleState:
    selected: str | None = None
    local_directory: str = field(default_factory=os.getcwd)
    history: InMemoryHistory = field(default_factory=InMemoryHistory, repr=False)
    color_mode: str = "auto"
    forward_settings: SavedForwards | None = field(default=None, repr=False)
    history_store: ConsoleHistory | None = field(default=None, repr=False)
    history_loaded: bool = False


def print_panes(backend, selected=None, *, console=None):
    panes = backend.panes()
    console = console if console is not None else Console(emoji=False, highlight=False)
    if console.is_terminal:
        table = Table(
            header_style="bold cyan", border_style="bright_black", expand=True
        )
        for name in ("", "Pane", "Window", "PID", "Size", "State", "Directory"):
            table.add_column(name)
        for pane in panes:
            table.add_row(
                Text("●" if pane.id == selected else "", style="green"),
                Text(pane.id, style="bold cyan"),
                Text(pane.window_id),
                str(pane.pid),
                f"{pane.width}×{pane.height}",
                Text(
                    "exited" if pane.dead else "running",
                    style="yellow" if pane.dead else "green",
                ),
                Text(safe_text(pane.directory)),
            )
        console.print(table)
        return
    for pane in panes:
        print(
            f"{'*' if pane.id == selected else ' '} {pane.id:>5}  window={pane.window_id}  "
            f"pid={pane.pid:<7} {pane.width}x{pane.height}  "
            f"{'exited' if pane.dead else 'running'}  {safe_text(pane.directory)}"
        )


def transfer(backend, action, source, destination, overwrite=False, *, console=None):
    service = FileService(backend.connection.filesystem())
    result = getattr(service, action)(source, destination, overwrite=overwrite)
    message(
        f"Transferred {result.size} bytes; SHA-256 {result.sha256}",
        "green",
        console=console,
    )


class WorkspaceConsole:
    def __init__(self, backend, state=None):
        self.backend = backend
        self.state = state if state is not None else ConsoleState()

    def message(self, text, style=""):
        message(text, style, console=output_console(self.state))

    def detail(self, label, value):
        detail(label, value, console=output_console(self.state))

    def help(self, args):
        if len(args) > 1 or (args and args[0] not in COMMANDS):
            self.usage("help")
        if args:
            usage, description = COMMANDS[args[0]]
            self.message("Usage: " + usage, "bold cyan")
            self.message(description)
            if args[0] == "forward":
                self.message(
                    "SERVER_IP defaults to 127.0.0.1. Use a loopback IP or the IP of the current SSH connection.",
                    "dim",
                )
                self.message(
                    "Eligible forwards are saved and restored on attach. 'forward stop PORT' also removes the saved setting.",
                    "dim",
                )
            return
        table = Table(box=box.SIMPLE, header_style="bold")
        table.add_column("Command", style="bold green", no_wrap=True)
        table.add_column("Description")
        for name, (_, description) in COMMANDS.items():
            table.add_row(Text(name), Text(description))
        output_console(self.state).print(table)
        self.message(
            "Use 'help COMMAND' for usage. Tab completes commands and options.", "dim"
        )

    def selected(self):
        if self.state.selected is None:
            self.state.selected = self.backend.current_pane()
        # A missing pane is an error, never a reason to silently choose another.
        return self.backend.pane(self.state.selected)

    def local_path(self, value):
        return os.path.abspath(
            os.path.join(self.state.local_directory, os.path.expanduser(value))
        )

    def usage(self, command):
        raise WorkspaceError("Usage: " + COMMANDS[command][0])

    def execute(self, line):
        result = self._execute(line)
        if self.state.history_store:
            try:
                self.state.history_store.record(line)
            except (WorkspaceError, OSError) as exc:
                self.message(
                    "Command completed, but console history could not be saved: "
                    + safe_text(exc),
                    "yellow",
                )
                self.state.history_store = (
                    None  # Continue in memory for this invocation.
                )
        return result

    def _execute(self, line):
        words = shlex.split(line)
        if not words:
            return None
        command, *args = words
        if command not in COMMANDS:
            raise WorkspaceError(
                f"Unsupported workspace command: {safe_text(command)}. "
                "Use 'help' for available commands or 'resume' for the remote shell. "
                "Pwncat modules are not connected to workspace panes."
            )
        if command == "help":
            self.help(args)
        elif command == "color":
            if len(args) > 1 or (args and args[0] not in ("auto", "on", "off")):
                self.usage(command)
            if args:
                self.state.color_mode = args[0]
            self.message(
                f"Colors: {self.state.color_mode} ({'enabled' if colors_enabled(self.state) else 'disabled'}).",
                "bold magenta",
            )
            self.message(
                "'color on' overrides NO_COLOR; 'color auto' follows your terminal settings.",
                "dim",
            )
        elif command in ("status", "panes", "lpwd", "resume", "detach"):
            if args:
                self.usage(command)
            if command == "detach":
                return "detach"
            if command == "resume":
                self.backend.select(self.selected().id)
                return "resume"
            if command == "lpwd":
                print(safe_text(self.state.local_directory))
            elif command == "panes":
                print_panes(
                    self.backend,
                    self.state.selected,
                    console=output_console(self.state),
                )
            else:
                self.status()
        elif command == "select":
            if len(args) != 1:
                self.usage(command)
            self.backend.select(pane_id(args[0]))
            self.state.selected = args[0]
            self.message("Selected " + args[0], "green")
        elif command == "split":
            target, direction = None, "horizontal"
            if args and args[0].startswith("%"):
                target = pane_id(args.pop(0))
            if args:
                direction = args.pop(0)
            if args or direction not in ("horizontal", "vertical"):
                self.usage(command)
            result = self.backend.split(target or self.selected().id, direction)
            if len(result) != 1:
                raise WorkspaceError(
                    "Split was requested; inspect 'panes' before repeating."
                )
            self.state.selected = pane_id(result[0].decode("ascii", "strict"))
            self.message("Created " + self.state.selected, "green")
        elif command == "window":
            if len(args) > 1:
                self.usage(command)
            self.state.selected = self.backend.new_window(args[0] if args else None)
            self.message("Created " + self.state.selected, "green")
        elif command == "lcd":
            if len(args) != 1:
                self.usage(command)
            directory = self.local_path(args[0])
            if not os.path.isdir(directory):
                raise WorkspaceError("Local directory does not exist.")
            self.state.local_directory = directory
            print(safe_text(directory))
        elif command in ("upload", "download"):
            if len(args) not in (2, 3) or (len(args) == 3 and args[2] != "--overwrite"):
                self.usage(command)
            source, destination = args[:2]
            if command == "upload":
                source = self.local_path(source)
            else:
                destination = self.local_path(destination)
            transfer(
                self.backend,
                command,
                source,
                destination,
                len(args) == 3,
                console=output_console(self.state),
            )
        elif command == "forward":
            self.forward(args)
        return None

    def forward(self, args):
        if not args or args == ["list"]:
            manager = self.backend.connection.local_forwards()
            entries, saved_ports = manager.list(), set()
            if self.state.forward_settings:
                try:
                    entries, saved_ports = self.state.forward_settings.view(manager)
                except (WorkspaceError, OSError) as exc:
                    self.message(
                        "Saved forward settings unavailable: " + safe_text(exc),
                        "yellow",
                    )
            if not entries:
                self.message("No local forwards in this connection.", "dim")
            for entry in entries:
                self.message(
                    f"127.0.0.1:{entry.local_port} -> SSH host {entry.remote_endpoint}  "
                    f"{'listening' if entry.running else 'stopped'}  connections={entry.connections}"
                    + ("  saved" if entry.local_port in saved_ports else ""),
                    "cyan" if entry.running else "yellow",
                )
                if entry.error:
                    self.message("  Last error: " + safe_text(entry.error), "yellow")
        elif len(args) in (3, 4) and args[0] == "add":
            local, remote = port_number(args[1]), port_number(args[-1])
            destination = str(
                destination_address(args[2] if len(args) == 4 else LOOPBACK)
            )
            manager = self.backend.connection.local_forwards()
            entry = manager.add(local, remote, destination_ip=destination)
            if self.state.forward_settings:
                try:
                    saved = self.state.forward_settings.remember(manager, entry)
                except (WorkspaceError, OSError) as exc:
                    manager.stop(local)
                    raise WorkspaceError(
                        "Could not save the forward; its new listener was stopped: "
                        + safe_text(exc)
                    ) from exc
                self.message(
                    "Saved for automatic restoration on attach/reconnect."
                    if saved
                    else "Running for this connection only; automatic restoration is limited to the SSH host and loopback.",
                    "dim",
                )
            self.message(
                f"Listening on 127.0.0.1:{entry.local_port} -> SSH host {entry.remote_endpoint}.",
                "green",
            )
            self.message(
                "The service is contacted when a local client connects. 'resume' returns to your pane.",
                "dim",
            )
        elif len(args) == 2 and args[0] == "stop":
            local = port_number(args[1])
            manager = self.backend.connection.local_forwards()
            if self.state.forward_settings:
                self.state.forward_settings.stop(manager, local)
                self.message(
                    f"Stopped local forward on port {local}; saved setting removed.",
                    "green",
                )
            else:
                manager.stop(local)
                self.message(f"Stopped local forward on port {local}.", "green")
        else:
            self.usage("forward")

    def status(self):
        self.backend._verify()
        profile = self.backend.connection.profile
        manifest = self.backend.store.load(self.backend.ref.name)
        self.detail("Workspace", self.backend.ref.name)
        self.detail(
            "SSH / file account", f"{profile.user}@{profile.host}:{profile.port}"
        )
        self.detail(
            "History",
            manifest["history"] + "; scrollback remains in the live tmux server",
        )
        self.detail("Local directory", self.state.local_directory)
        try:
            pane = self.selected()
        except (ConnectionLost, OutcomeUnknown):
            raise
        except WorkspaceError as exc:
            self.message("Selected pane unavailable: " + safe_text(exc), "yellow")
            return
        self.detail(
            "Selected pane", f"{pane.id}  window={pane.window_id}  pid={pane.pid}"
        )
        self.detail("Observed directory", pane.directory)
        self.message(
            "Transfers use absolute paths on the SSH host, including when a pane enters another host or account.",
            "dim",
        )

    def run(self):
        # On entry, native tmux owns the current selection. During the console,
        # explicit stable IDs remain authoritative even if a pane disappears.
        self.state.selected = self.backend.current_pane()
        if not self.state.history_loaded:
            self.state.history_loaded = True
            if self.state.history_store:
                try:
                    for line in self.state.history_store.load():
                        self.state.history.append_string(line)
                except (WorkspaceError, OSError) as exc:
                    self.message(
                        "Console history could not be loaded: " + safe_text(exc),
                        "yellow",
                    )
                    self.state.history_store = None
        self.message(
            "\nWorkspace console. 'help' lists commands; Ctrl+Q or 'resume' returns to the remote pane.",
            "bold magenta",
        )
        self.status()
        prompt = None
        if sys.stdin.isatty() and sys.stdout.isatty():
            prompt = create_prompt(self.state, COMMANDS, self.backend.ref.name)
        while True:
            try:
                label = "".join(
                    text for _, text in prompt_text(self.state, self.backend.ref.name)
                )
                if prompt:
                    prompt.color_depth = prompt_color_depth(self.state)
                line = prompt.prompt() if prompt else input(label)
            except EOFError:
                return "detach"
            except KeyboardInterrupt:
                print("\nCancelled. No operation will be replayed.")
                continue
            try:
                action = self.execute(line)
                if action:
                    return action
            except KeyboardInterrupt:
                print("\nCancelled. No operation will be replayed.")
            except ConnectionLost:
                raise
            except (WorkspaceError, OSError, ValueError, EOFError) as exc:
                self.message("Error: " + safe_text(exc), "bold red")
                if isinstance(exc, OutcomeUnknown):
                    self.backend.close()
                if not self.backend.connection.active():
                    raise ConnectionLost(
                        "SSH disconnected; the command was not replayed."
                    ) from exc
