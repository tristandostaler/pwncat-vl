"""Interactive workspace commands with explicit pane and SSH filesystem
contexts.

The *outer* loop lives in ``cli.interact``: it alternates ``display()`` (native
tmux) and ``WorkspaceConsole.run()``, handles Ctrl+G p / Ctrl+G d / Ctrl+],
reconnection, saved forwards and the ``.history-NAME.json`` file.

``WorkspaceConsole.run()`` now delegates its *inner* REPL to the normal pwncat
``Manager`` / ``CommandParser`` over one extra SSH shell channel on the
workspace's authenticated ``SSHClient``.  Every pwncat command and module is
therefore available (``run``, ``search``, ``use``, ``set``, ``sessions``,
``enumerate``, ``escalate``, ``persist``, ``implant``, ...) with the normal
``(local) pwncat$`` prompt, completion, syntax highlighting, aliases, key
bindings and database history.  Workspace actions are registered as normal
``CommandDefinition`` objects by ``console_commands.WORKSPACE_COMMANDS``.

``run()`` returns ``"resume"``, ``"park"`` or ``"detach"`` to the outer loop.
"""
from __future__ import annotations

import os
import shlex
from contextlib import contextmanager
from dataclasses import dataclass, field

from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.formatted_text import merge_formatted_text
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn

from pwncat.channel import ChannelError
from pwncat.manager import InteractiveExit, Manager

from . import ConnectionLost, OutcomeUnknown, WorkspaceError
from .console_history import ConsoleHistory
from .console_ui import colors_enabled, output_console
from .files import FileService
from .background_transfers import BackgroundTransfers, progress_text
from .background_modules import BackgroundModules
from .forwarding import LOOPBACK, destination_address, port_number
from .model import pane_id, safe_text
from .saved_forwards import SavedForwards, SavedListeners

COMMANDS = {
    "help": ("help [COMMAND]", "Show workspace commands and usage."),
    "color": (
        "color [auto|on|off]",
        "Inspect or change console colors for this client.",
    ),
    "status": (
        "status",
        "Show connection, history policy, and selected pane context.",
    ),
    "panes": (
        "panes",
        "List panes across all windows; * marks the selected pane.",
    ),
    "select": (
        "select %ID",
        "Select a pane and its window for resume and split.",
    ),
    "split": (
        "split [%ID] [horizontal|vertical]",
        "Split the selected or specified pane.",
    ),
    "window": ("window [TITLE]", "Create a window and select its first pane."),
    "upload": (
        "upload LOCAL /REMOTE [--overwrite] [--background|-b]",
        "Upload through the workspace SSH account.",
    ),
    "download": (
        "download /REMOTE LOCAL [--overwrite] [--background|-b]",
        "Download through the workspace SSH account.",
    ),
    "forward": (
        "forward [list] | add LOCAL_PORT [SERVER_IP] REMOTE_PORT | stop LOCAL_PORT | reverse add REMOTE_PORT LOCAL_PORT [BIND_IP] | reverse list | reverse stop REMOTE_PORT",
        "Manage local and reverse SSH forwards.",
    ),
    "lpwd": ("lpwd", "Show the local directory used for transfer paths."),
    "lcd": ("lcd DIRECTORY", "Change the local transfer directory."),
    "resume": ("resume", "Return to the selected remote pane."),
    "detach": ("detach", "Leave the workspace; remote processes keep running."),
    "transfers": (
        "transfers [upload|download|between|status]",
        "Upload, download, copy between sessions, or show transfer status.",
    ),
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
    listener_settings: SavedListeners | None = field(default=None, repr=False)
    history_store: ConsoleHistory | None = field(default=None, repr=False)
    history_loaded: bool = False
    # Set by ``resume`` / ``detach`` / connection loss and read by ``run``.
    exit_reason: str | None = None

def print_panes(backend, selected=None, *, console=None):
    panes = backend.panes()
    console = console if console is not None else Console(emoji=False, highlight=False)
    if console.is_terminal:
        table = Table(
            header_style="bold cyan",
            border_style="bright_black",
            expand=True,
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
            f"{'*' if pane.id == selected else ' '} {pane.id:>5} "
            f"window={pane.window_id} "
            f"pid={pane.pid:<7} {pane.width}x{pane.height} "
            f"{'exited' if pane.dead else 'running'} {safe_text(pane.directory)}"
        )

@contextmanager
def _transfer_progress(console, action):
    if console is None or not console.is_terminal:
        yield None, None
        return
    with Progress(
        TextColumn("{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
        refresh_per_second=4,
    ) as display:
        task = display.add_task(action, total=None)

        def phase_changed(phase, total):
            display.update(task, description=phase, total=total)
            display.refresh()

        yield (
            lambda count: display.update(task, completed=count),
            phase_changed,
        )


def transfer(backend, action, source, destination, overwrite=False, *, console=None, progress=None, status=None):
    service = FileService(backend.connection.filesystem())
    result = getattr(service, action)(
        source, destination, overwrite=overwrite, progress=progress, status=status
    )
    message(
        f"Transferred {result.size} bytes; SHA-256 {result.sha256}",
        "green",
        console=console,
    )


def transfer_selected(manager, backend, action, source, destination, overwrite=False, *, console=None):
    """Use the active pwncat session, retaining SFTP for the workspace session."""
    session = manager.target
    if session is None:
        raise WorkspaceError("Select an active session before transferring a file.")
    from .platform import WorkspaceChannel

    if isinstance(session.platform.channel, WorkspaceChannel):
        with _transfer_progress(console, action) as (progress, status):
            transfer(
                backend, action, source, destination, overwrite, console=console,
                progress=progress, status=status,
            )
        return
    from . import session_files

    with _transfer_progress(console, action) as (progress, status):
        result = getattr(session_files, action)(
            session.platform, source, destination, overwrite=overwrite,
            progress=progress, status=status,
        )
    message(
        f"Transferred {result.size} bytes in session {session.id}; SHA-256 {result.sha256}",
        "green",
        console=console,
    )

class WorkspaceConsole:
    def __init__(self, backend, state=None):
        self.backend = backend
        self.state = state if state is not None else ConsoleState()
        self._manager = None
        self._workspace_session_ready = False
        self.transfers = BackgroundTransfers(on_update=self._refresh_progress)
        self.modules = BackgroundModules(on_update=self._refresh_progress)

    def close(self):
        """Release the console on detach or connection loss, never on resume."""
        manager, self._manager = self._manager, None
        self._workspace_session_ready = False
        if manager is None:
            return
        manager.interactive_running = False
        try:
            for listener in manager.listeners:
                listener.stop()
            for session in list(manager.sessions.values()):
                try:
                    # Do not issue shell commands during transport teardown.
                    session.platform.channel.close()
                except (ChannelError, OSError):
                    pass
                finally:
                    session.died()
        finally:
            manager.db.close()

    def message(self, text, style=""):
        message(text, style, console=output_console(self.state))

    def _refresh_progress(self):
        manager = self._manager
        prompt = manager.parser.prompt if manager is not None else None
        app = getattr(prompt, "app", None)
        if app is not None and app.is_running:
            app.invalidate()

    def start_transfer(self, action, source, destination, overwrite=False):
        session = self._manager.target
        if session is None:
            raise WorkspaceError("Select an active session before transferring a file.")
        if self.modules.busy_session(session):
            raise WorkspaceError("That session is running a background module.")
        from .platform import WorkspaceChannel

        fallback = None
        if not isinstance(session.platform.channel, WorkspaceChannel):
            fallback = next(
                (
                    other for other in self._manager.sessions.values()
                    if isinstance(other.platform.channel, WorkspaceChannel)
                ),
                None,
            )
            if fallback is None:
                raise WorkspaceError(
                    "A workspace SSH session is required to keep the console usable during this transfer."
                )
        status = self.transfers.start(
            session, self.backend.connection, action, source, destination,
            overwrite=overwrite,
        )
        if fallback is not None:
            self._manager.target = fallback
        self.message(
            f"Started transfer {status.number} in session {status.session_id}. "
            + (
                f"Switched to workspace session {fallback.id} while it runs. "
                if fallback is not None else ""
            )
            + "Use 'transfers' to check its result.",
            "green",
        )

    def transfer_status(self):
        status = self.transfers.status()
        if status is None:
            self.message("No background transfer has been started.", "dim")
        elif status.state == "running":
            self.message(
                f"Transfer {status.number}: {status.action} in session {status.session_id}: "
                + progress_text(status),
                "cyan",
            )
        elif status.state == "completed":
            self.message(
                f"Transfer {status.number}: completed {status.size} bytes; SHA-256 {status.sha256}",
                "green",
            )
        else:
            self.message(
                f"Transfer {status.number}: failed: {status.error}", "red",
            )

    def start_module(self, name, values, *, raw=False, traceback_requested=False):
        """Run an opted-in module while the console uses another shell session."""
        from .platform import WorkspaceChannel

        manager = self._manager
        session = manager.target
        if session is None:
            raise WorkspaceError("Select an active session before running a module.")
        if self.modules.active():
            raise WorkspaceError("A module is already running. Use 'module status' to check it.")
        if self.transfers.busy_session(session):
            raise WorkspaceError("That session is busy with a background transfer.")

        module = next(session.find_module(name, exact=True), None)
        if module is None:
            raise WorkspaceError(f"Module {safe_text(name)} was not found in this session.")
        manager.reload_if_edited(module.name)
        module = manager.modules[module.name]
        if not getattr(module, "BACKGROUND_SAFE", False):
            raise WorkspaceError(
                f"{safe_text(module.name)} cannot run in the background. "
                "It must declare BACKGROUND_SAFE = True after checking that it "
                "never reads terminal input or changes the active session."
            )

        fallback = next(
            (
                other for other in manager.sessions.values()
                if other is not session
                and isinstance(other.platform.channel, WorkspaceChannel)
                and not self.modules.busy_session(other)
            ),
            None,
        )
        if fallback is None:
            channel = WorkspaceChannel(self.backend)
            try:
                fallback = manager.create_session(platform="linux", channel=channel)
            except Exception:
                channel.close()
                manager.target = session
                raise

        config = manager.config.copy()
        manager.target = fallback
        try:
            status = self.modules.start(
                session, module, values, config, raw=raw,
                traceback_requested=traceback_requested,
            )
        except Exception:
            manager.target = session
            raise
        self.message(
            f"Started module {status.number} ({status.name}) in session {status.session_id}. "
            f"Switched to workspace session {fallback.id} while it runs. "
            "Use 'module status' or 'module result' to check it.",
            "green",
        )

    def module_status(self):
        status = self.modules.status()
        if status is None:
            self.message("No background module has been started.", "dim")
        else:
            self.message(
                f"Module {status.number} ({status.name}) in session {status.session_id}: "
                f"{status.state}" + (f": {status.error}" if status.error else ""),
                "red" if status.state == "failed" else "cyan",
            )

    def module_result(self):
        status = self.modules.status()
        if status is None or status.state == "running":
            self.module_status()
            return
        if status.state == "failed":
            self.module_status()
            if status.traceback_requested and status.traceback:
                output_console(self.state).print(Text(status.traceback))
            return
        run_command = next(
            command for command in self._manager.parser.commands
            if command.PROG == "run"
        )
        run_command.display_result(
            self._manager, status.name, status.result,
            raw=status.raw, session=status.session,
        )

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
                    "SERVER_IP defaults to 127.0.0.1. Use a loopback IP or the IP of the current SSH "
                    "connection.",
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
            "Use 'help COMMAND' for usage. Tab completes commands and options.",
            "dim",
        )

    def selected(self):
        if self.state.selected is None:
            self.state.selected = self.backend.current_pane()
        # A missing pane is an error, never a reason to silently choose another.
        return self.backend.pane(self.state.selected)

    def local_path(self, value):
        # pwncat's ``lcd`` changes the process working directory; resolve
        # relative transfer paths against it so both consoles agree.
        return os.path.abspath(
            os.path.join(os.getcwd(), os.path.expanduser(value))
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
                self.state.history_store = None  # Continue in memory for this invocation.
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
                f"Colors: {self.state.color_mode} "
                f"({'enabled' if colors_enabled(self.state) else 'disabled'}).",
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
            options = args[2:]
            background = "--background" in options or "-b" in options
            overwrite = "--overwrite" in options
            if (
                len(args) < 2
                or len(options) != len(set(options))
                or ("--background" in options and "-b" in options)
                or any(option not in ("--overwrite", "--background", "-b") for option in options)
            ):
                self.usage(command)
            source, destination = args[:2]
            if command == "upload":
                source = self.local_path(source)
            else:
                destination = self.local_path(destination)
            if background:
                self.start_transfer(command, source, destination, overwrite)
            else:
                transfer(
                    self.backend,
                    command,
                    source,
                    destination,
                    overwrite,
                    console=output_console(self.state),
                )
        elif command == "forward":
            self.forward(args)
        return None

    def forward(self, args):
        if args and args[0] == "reverse":
            self.reverse_forward(args[1:])
        elif not args or args == ["list"]:
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
            for entry in entries:
                self.message(
                    f"Local 127.0.0.1:{entry.local_port} -> SSH host {entry.remote_endpoint} "
                    f"{'listening' if entry.running else 'stopped'} connections={entry.connections}"
                    + (" saved" if entry.local_port in saved_ports else ""),
                    "cyan" if entry.running else "yellow",
                )
                if entry.error:
                    self.message(" Last error: " + safe_text(entry.error), "yellow")
            reverse_entries = self._list_reverse()
            if not entries and not reverse_entries:
                self.message("No local or reverse forwards in this connection.", "dim")
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

    def reverse_forward(self, args):
        manager = self.backend.connection.reverse_forwards()
        if args == ["list"]:
            if not self._list_reverse():
                self.message("No reverse forwards in this connection.", "dim")
        elif len(args) in (3, 4) and args[0] == "add":
            remote, local = port_number(args[1]), port_number(args[2])
            bind_ip = args[3] if len(args) == 4 else LOOPBACK
            entry = manager.add(remote, local, bind_ip=bind_ip)
            if self.state.forward_settings:
                try:
                    self.state.forward_settings.remember_reverse(manager, entry)
                except (WorkspaceError, OSError) as exc:
                    manager.stop(remote)
                    raise WorkspaceError(
                        "Could not save the reverse forward; its new listener was stopped: "
                        + safe_text(exc)
                    ) from exc
            self.message(
                f"Requested SSH host {entry.remote_endpoint} -> 127.0.0.1:{entry.local_port}.",
                "green",
            )
            if entry.bind_ip == "0.0.0.0":
                self.message(
                    "Other hosts can connect only if the SSH server permits external remote binds (GatewayPorts).",
                    "dim",
                )
            if self.state.forward_settings:
                self.message("Saved for automatic restoration on attach/reconnect.", "dim")
        elif len(args) == 2 and args[0] == "stop":
            remote = port_number(args[1])
            if self.state.forward_settings:
                self.state.forward_settings.stop_reverse(manager, remote)
                self.message(f"Stopped reverse forward on SSH host port {remote}; saved setting removed.", "green")
            else:
                manager.stop(remote)
                self.message(f"Stopped reverse forward on SSH host port {remote}.", "green")
        else:
            self.usage("forward")

    def _list_reverse(self):
        manager = self.backend.connection.reverse_forwards()
        entries, saved_ports = manager.list(), set()
        if self.state.forward_settings:
            try:
                entries, saved_ports = self.state.forward_settings.view_reverse(manager)
            except (WorkspaceError, OSError) as exc:
                self.message("Saved reverse settings unavailable: " + safe_text(exc), "yellow")
        for entry in entries:
            self.message(
                f"Reverse SSH host {entry.remote_endpoint} -> 127.0.0.1:{entry.local_port} "
                f"{'listening' if entry.running else 'stopped'} connections={entry.connections}"
                + (" saved" if entry.remote_port in saved_ports else ""),
                "cyan" if entry.running else "yellow",
            )
            if entry.error:
                self.message(" Last error: " + safe_text(entry.error), "yellow")
        return entries

    def status(self):
        self.backend._verify()
        profile = self.backend.connection.profile
        manifest = self.backend.store.load(self.backend.ref.name)
        self.detail("Workspace", self.backend.ref.name)
        self.detail(
            "SSH / file account",
            f"{profile.user}@{profile.host}:{profile.port}",
        )
        self.detail(
            "History",
            manifest["history"] + "; scrollback remains in the live tmux server",
        )
        self.detail("Local directory", os.getcwd())
        try:
            pane = self.selected()
        except (ConnectionLost, OutcomeUnknown):
            raise
        except WorkspaceError as exc:
            self.message("Selected pane unavailable: " + safe_text(exc), "yellow")
            return
        self.detail(
            "Selected pane", f"{pane.id} window={pane.window_id} pid={pane.pid}"
        )
        self.detail("Observed directory", pane.directory)
        self.message(
            "The workspace SSH session uses absolute remote paths; 'sessions ID' can select another transfer target.",
            "dim",
        )

    def run(self):
        from . import local_screen

        self.state.exit_reason = None
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
            "\nWorkspace console. Normal pwncat commands and workspace commands are available. "
            + (
                "Ctrl+Q parks this live console for 'workspace attach'; 'resume' returns to the pane; 'detach' closes this client."
                if local_screen.managed()
                else "Ctrl+Q or 'detach' leaves the workspace; 'resume' returns to the pane."
            ),
            "bold magenta",
        )
        return self._run_pwncat_console()

    def _run_pwncat_console(self):
        """Re-enter the same console and active session after a tmux visit."""
        from .platform import WorkspaceChannel

        manager = self.prepare_manager()
        from . import local_screen

        # Mouse reporting captures drag events before the terminal can select
        # console text. Keep prompt_toolkit's default (disabled) mouse mode.
        if not self._workspace_session_ready:
            channel = None
            try:
                channel = WorkspaceChannel(self.backend)
                manager.create_session(
                    platform="linux", channel=channel, active=True
                )
                self._workspace_session_ready = True
            except Exception as exc:
                if channel is not None:
                    channel.close()
                self.close()
                raise WorkspaceError(
                    "Could not open the pwncat console over the workspace SSH account: "
                    + safe_text(exc)
                ) from exc

        try:
            self._manager.interactive(confirm_exit=False)
        except InteractiveExit:
            pass

        from . import local_screen

        reason = self.state.exit_reason or ("park" if local_screen.managed() else "detach")
        if reason == "connection-lost" or not self.backend.connection.active():
            self.close()
            raise ConnectionLost("SSH disconnected; the console was not replayed.")
        if reason == "detach":
            if self.transfers.active() or self.modules.active():
                self.message(
                    "A background transfer or module is still running. "
                    + (
                        "Use Ctrl+Q to park this client, or wait for it to finish."
                        if local_screen.managed()
                        else "Wait for it to finish before leaving this client."
                    ),
                    "yellow",
                )
                return "busy"
            self.close()
        return reason

    def prepare_manager(self):
        """Create the listener owner before display, without opening a shell pane."""
        if self._manager is None:
            from .console_commands import WORKSPACE_COMMANDS

            database_uri = (
                self.state.history_store.database_uri()
                if self.state.history_store is not None
                else "memory://"
            )
            manager = self._manager = Manager(database_uri=database_uri)
            manager.workspace_console = self
            manager.workspace_state = self.state
            manager.workspace_backend = self.backend

            # Insert at the front so workspace ``upload``/``download`` keep
            # their SFTP staging and SHA-256 guarantees over pwncat's own.
            manager.parser.commands[:0] = [
                cls(manager) for cls in WORKSPACE_COMMANDS
            ]

            original_toolbar = manager.parser._render_toolbar

            def workspace_toolbar():
                rendered = original_toolbar()
                current = self.transfers.status()
                if current is not None:
                    if current.state == "running":
                        extra = f" | Transfer {current.number}: {progress_text(current)}"
                    else:
                        extra = f" | Transfer {current.number}: {current.state} (details: transfers)"
                    rendered = merge_formatted_text([rendered, extra])
                module = self.modules.status()
                if module is not None:
                    extra = f" | Module {module.number}: {module.state} (details: module status)"
                    rendered = merge_formatted_text([rendered, extra])
                return rendered

            manager.parser._render_toolbar = workspace_toolbar

            original_dispatch = manager.parser.dispatch_line

            def dispatch(line, *a, **k):
                result = original_dispatch(line, *a, **k)
                if self.state.history_store:
                    try:
                        self.state.history_store.record(line)
                    except (WorkspaceError, OSError) as exc:
                        self.message(
                            "Command completed, but console history could not be saved: "
                            + safe_text(exc),
                            "yellow",
                        )
                        self.state.history_store = None
                if not self.backend.connection.active():
                    self.state.exit_reason = "connection-lost"
                    raise InteractiveExit
                return result

            manager.parser.dispatch_line = dispatch
        return self._manager
