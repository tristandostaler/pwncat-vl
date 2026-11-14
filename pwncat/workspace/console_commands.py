"""Workspace actions as normal pwncat ``CommandDefinition`` objects.

They are registered into ``manager.parser.commands`` by
``WorkspaceConsole._run_pwncat_console`` and therefore appear in ``help``,
tab-complete, and share the same history, aliases and key bindings as ``run``,
``search``, ``use``, ``set``, ``sessions``, ``enumerate``, ``escalate``,
``persist`` and ``implant``.

Implementation is delegated to the existing ``WorkspaceConsole`` methods
(``forward``, ``status``, ``selected``, ``local_path``) and to the module-level
``print_panes`` / ``transfer`` helpers, imported lazily to avoid an import
cycle with ``console.py``.

``upload`` and ``download`` are inserted before pwncat's own versions so they
follow the selected pwncat session. The workspace session uses SFTP; other
sessions use their platform's file API. ``lcd`` / ``lpwd`` / ``help`` are not registered:
pwncat's versions govern the local transfer directory and the full command
index.
"""
from __future__ import annotations

from pwncat.commands import CommandDefinition, CommandRoute, GroupCommand, Complete, Parameter
from pwncat.manager import InteractiveExit
from pwncat.workspace import WorkspaceError
from pwncat.workspace.console_ui import colors_enabled, output_console
from pwncat.workspace.model import pane_id

class _Base(CommandDefinition):
    LOCAL = True

    @property
    def console(self):
        return self.manager.workspace_console

    @property
    def state(self):
        return self.manager.workspace_state

    @property
    def backend(self):
        return self.manager.workspace_backend

class ForwardCommand(_Base):
    """Manage local and reverse forwards over the workspace SSH connection.

    ``forward add LOCAL_PORT [DEST_IP] REMOTE_PORT`` forwards
    ``127.0.0.1:LOCAL_PORT`` to ``DEST_IP:REMOTE_PORT`` through the existing
    authenticated SSH connection. ``DEST_IP`` defaults to ``127.0.0.1`` and
    may be any literal IPv4 or IPv6 address reachable from the SSH host.
    ``forward`` or ``forward list`` shows local and reverse forwards together.
    ``forward stop LOCAL_PORT`` also removes the saved setting.
    ``forward reverse add REMOTE_PORT LOCAL_PORT [BIND_IP]`` listens on the
    SSH host and connects to local 127.0.0.1:LOCAL_PORT. BIND_IP defaults to
    127.0.0.1; 0.0.0.0 requests access from other hosts if SSH permits it.
    Reverse forwards are saved with the workspace and restored on attach.
    """

    PROG = "forward"
    ARGS = {
        "action": Parameter(
            Complete.CHOICES,
            nargs="?",
            metavar="ACTION",
            choices=["add", "list", "stop", "reverse"],
            help="add / list / stop / reverse",
        ),
        "args": Parameter(Complete.NONE, nargs="*", metavar="ARG"),
    }

    def run(self, manager, args):
        self.console.forward(([] if args.action is None else [args.action]) + args.args)

class PanesCommand(_Base):
    """List panes across all windows; * marks the selected pane."""

    PROG = "panes"
    ARGS = {}

    def run(self, manager, args):
        from pwncat.workspace.console import print_panes

        print_panes(
            self.backend,
            self.state.selected,
            console=output_console(self.state),
        )

class SelectCommand(_Base):
    """Select a pane across windows for resume, split and status."""

    PROG = "select"
    ARGS = {"pane": Parameter(Complete.NONE, metavar="%ID")}

    def run(self, manager, args):
        pane = pane_id(args.pane)
        self.backend.select(pane)
        self.state.selected = pane
        self.console.message("Selected " + pane, "green")

class SplitCommand(_Base):
    """Split the selected (or specified) pane; the new pane is selected."""

    PROG = "split"
    ARGS = {
        "pane": Parameter(Complete.NONE, nargs="?", metavar="%ID"),
        "direction": Parameter(
            Complete.CHOICES,
            nargs="?",
            choices=["horizontal", "vertical"],
            default="horizontal",
        ),
    }

    def run(self, manager, args):
        if args.pane in ("horizontal", "vertical") and args.direction == "horizontal":
            args.direction, args.pane = args.pane, None
        target = pane_id(args.pane) if args.pane else self.console.selected().id
        result = self.backend.split(target, args.direction)
        if len(result) != 1:
            raise WorkspaceError(
                "Split was requested; inspect 'workspace pane list' before repeating."
            )
        self.state.selected = pane_id(result[0].decode("ascii", "strict"))
        self.console.message("Created " + self.state.selected, "green")

class WindowCommand(_Base):
    """Create a window and select its first pane."""

    PROG = "window"
    ARGS = {"title": Parameter(Complete.NONE, nargs="?")}

    def run(self, manager, args):
        self.state.selected = self.backend.new_window(args.title)
        self.console.message("Created " + self.state.selected, "green")

class StatusCommand(_Base):
    """Show connection, history policy, and selected pane context."""

    PROG = "status"
    ARGS = {}

    def run(self, manager, args):
        self.console.status()


class WorkspaceCommand(GroupCommand):
    """Inspect the workspace and organize its remote tmux panes and windows."""

    PROG = "workspace"
    GROUP_SUMMARIES = {
        ("pane",): "List, select and split remote panes",
        ("window",): "Create remote windows",
    }
    ROUTES = {
        ("status",): CommandRoute("status", summary="Show workspace status"),
        ("pane", "list"): CommandRoute("panes", summary="List panes"),
        ("pane", "select"): CommandRoute("select", summary="Select a pane for resume"),
        ("pane", "split"): CommandRoute("split", summary="Split a pane"),
        ("window", "new"): CommandRoute("window", summary="Create a window"),
    }

class UploadCommand(_Base):
    """Upload to the selected pwncat session; verify the remote bytes."""

    PROG = "upload"
    ARGS = {
        "source": Parameter(Complete.LOCAL_FILE),
        "destination": Parameter(Complete.REMOTE_FILE),
        "--overwrite": Parameter(Complete.NONE, action="store_true"),
        "--background,-b": Parameter(Complete.NONE, action="store_true"),
    }

    def run(self, manager, args):
        from pwncat.workspace.console import transfer_selected

        if getattr(args, "background", False):
            self.console.start_transfer(
                "upload", self.console.local_path(args.source), args.destination,
                args.overwrite,
            )
            return
        transfer_selected(
            manager,
            self.backend,
            "upload",
            self.console.local_path(args.source),
            args.destination,
            args.overwrite,
            console=output_console(self.state),
        )

class DownloadCommand(_Base):
    """Download from the selected pwncat session; verify the local bytes."""

    PROG = "download"
    ARGS = {
        "source": Parameter(Complete.REMOTE_FILE),
        "destination": Parameter(Complete.LOCAL_FILE),
        "--overwrite": Parameter(Complete.NONE, action="store_true"),
        "--background,-b": Parameter(Complete.NONE, action="store_true"),
    }

    def run(self, manager, args):
        from pwncat.workspace.console import transfer_selected

        if getattr(args, "background", False):
            self.console.start_transfer(
                "download", args.source, self.console.local_path(args.destination),
                args.overwrite,
            )
            return
        transfer_selected(
            manager,
            self.backend,
            "download",
            args.source,
            self.console.local_path(args.destination),
            args.overwrite,
            console=output_console(self.state),
        )

class ColorCommand(_Base):
    """Control console colours (auto / on / off); 'on' overrides NO_COLOR."""

    PROG = "color"
    ARGS = {
        "mode": Parameter(
            Complete.CHOICES, nargs="?", choices=["auto", "on", "off"]
        )
    }

    def run(self, manager, args):
        if args.mode:
            self.state.color_mode = args.mode
        self.console.message(
            f"Colors: {self.state.color_mode} "
            f"({'enabled' if colors_enabled(self.state) else 'disabled'}).",
            "bold magenta",
        )

class ResumeCommand(_Base):
    """Return to tmux, keeping the console and its active session open."""

    PROG = "resume"
    ARGS = {}

    def run(self, manager, args):
        self.backend.select(self.console.selected().id)
        self.state.exit_reason = "resume"
        raise InteractiveExit

class DetachCommand(_Base):
    """Leave the workspace; remote processes and tmux keep running."""

    PROG = "detach"
    ARGS = {}

    def run(self, manager, args):
        self.state.exit_reason = "detach"
        raise InteractiveExit

WORKSPACE_COMMANDS = [
    WorkspaceCommand,
    ForwardCommand,
    PanesCommand,
    SelectCommand,
    SplitCommand,
    WindowCommand,
    StatusCommand,
    UploadCommand,
    DownloadCommand,
    ColorCommand,
    ResumeCommand,
    DetachCommand,
]
