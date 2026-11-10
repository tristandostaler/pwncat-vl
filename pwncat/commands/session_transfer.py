"""Copy a file directly between two active pwncat sessions."""

from rich.markup import escape
from rich.progress import BarColumn, Progress, TextColumn, TransferSpeedColumn

from pwncat.commands import CommandDefinition, Complete, Parameter
from pwncat.commands.sessions import _transfer_busy
from pwncat.util import console
from pwncat.workspace.model import safe_text
from pwncat.workspace.session_files import copy_between


class Command(CommandDefinition):
    """Stream a file between sessions without saving it on the local computer."""

    PROG = "session-transfer"
    LOCAL = True
    ARGS = {
        "source_session": Parameter(Complete.NONE, type=int, metavar="SOURCE_ID"),
        "source": Parameter(Complete.NONE, metavar="SOURCE_PATH"),
        "destination_session": Parameter(Complete.NONE, type=int, metavar="DEST_ID"),
        "destination": Parameter(Complete.NONE, metavar="DEST_PATH"),
        "--overwrite": Parameter(
            Complete.NONE, action="store_true", help="Replace an existing destination file"
        ),
    }

    def run(self, manager, args):
        source_session = manager.sessions.get(args.source_session)
        destination_session = manager.sessions.get(args.destination_session)
        if source_session is None or destination_session is None:
            missing = (
                args.source_session if source_session is None else args.destination_session
            )
            console.log(f"[red]error[/red]: session-{missing} does not exist")
            return
        if source_session is destination_session:
            console.log("[red]error[/red]: select two different sessions")
            return
        for session in (source_session, destination_session):
            if _transfer_busy(manager, session):
                console.log(
                    f"[red]error[/red]: session-{session.id} is busy with background work"
                )
                return

        with Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            TransferSpeedColumn(),
            console=console,
            transient=True,
        ) as display:
            task = display.add_task("copying", total=None)

            def progress(count):
                display.update(task, completed=count)

            def status(phase, total):
                display.update(task, description=phase, total=total)

            try:
                result = copy_between(
                    source_session.platform,
                    args.source,
                    destination_session.platform,
                    args.destination,
                    overwrite=args.overwrite,
                    progress=progress,
                    status=status,
                )
            except Exception as exc:
                console.log(f"[red]error[/red]: {escape(safe_text(exc))}")
                return

        console.log(
            f"Transferred {result.size} bytes from session-{source_session.id} "
            f"to session-{destination_session.id}; SHA-256 {result.sha256}"
        )
