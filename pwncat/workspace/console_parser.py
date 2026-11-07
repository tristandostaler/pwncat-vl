"""Run the normal pwncat console over a workspace SSH connection.

This is what the *inner* body of ``WorkspaceConsole`` calls on Ctrl+G p.  The
outer loop (display <-> console, Ctrl+G p/d, Ctrl+], reconnection, forward
lifetime, ``.history-NAME.json``, vault) stays where it is; only the REPL body
is replaced.

Every command and module available in a standalone ``pwncat-vl`` invocation is
available here.  Workspace actions live in ``console_commands.WORKSPACE_COMMANDS``
and appear alongside them in ``help`` and tab-completion.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from prompt_toolkit.history import InMemoryHistory

from pwncat.manager import Manager, InteractiveExit
from pwncat.util import console
from pwncat.workspace.console_commands import WORKSPACE_COMMANDS
from pwncat.workspace.console_history import ConsoleHistory
from pwncat.workspace.saved_forwards import SavedForwards
from pwncat.workspace.platform import WorkspaceChannel  # noqa: F401 registers "workspace"

@dataclass
class ConsoleState:
    selected: str | None = None
    local_directory: str | None = None
    color_mode: str = "auto"
    exit_reason: str | None = None
    forward_settings: SavedForwards | None = field(default=None, repr=False)
    history_store: ConsoleHistory | None = field(default=None, repr=False)
    history: InMemoryHistory = field(default_factory=InMemoryHistory, repr=False)

def _register_workspace_commands(manager: Manager) -> None:
    for cls in WORKSPACE_COMMANDS:
        manager.parser.commands.append(cls(manager))

def run_console(
    backend,
    state: ConsoleState | None = None,
    reconnect_seconds: int = 60,
    history_policy: str = "memory",
    history_limit: int = 50000,
) -> str:
    """Open the normal pwncat console over the workspace SSH connection.

    Returns ``"resume"`` to return to the tmux display, or ``"detach"`` to
    close the local client.  The outer ``WorkspaceConsole.run`` loop routes
    accordingly.  The Manager, Session, CommandParser, history database,
    aliases, bindings, syntax highlighting, completion and module runner
    behave exactly as in a standalone ``pwncat-vl`` invocation.
    """
    state = state or ConsoleState()
    state.exit_reason = None
    state.local_directory = state.local_directory or os.getcwd()
    if state.forward_settings is None:
        state.forward_settings = SavedForwards(backend.connection)
    if state.history_store is None:
        state.history_store = ConsoleHistory(
            backend, private=(history_policy == "private"),
        )

    with Manager() as manager:
        manager.workspace_state = state
        manager.workspace_backend = backend
        _register_workspace_commands(manager)

        try:
            session = manager.create_session(
                platform="linux", protocol="workspace", backend=backend,
            )
        except Exception as exc:
            console.log(f"[red]error[/red]: {exc}")
            return "detach"

        manager.target = session
        try:
            manager.interactive()
        except InteractiveExit:
            # Ctrl+Q or the ``exit``/``resume``/``detach`` commands.
            pass
        finally:
            try:
                state.forward_settings.stop_all()
            except Exception:
                pass
            try:
                state.history_store.flush()
            except Exception:
                pass

    return state.exit_reason or "resume"
