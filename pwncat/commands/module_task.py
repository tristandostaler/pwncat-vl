"""Inspect the current or most recent background module run."""

from pwncat.commands import CommandDefinition, Complete, Parameter
from pwncat.util import console


class Command(CommandDefinition):
    """Show background module status or its completed result."""

    PROG = "module-task"
    LOCAL = True
    ARGS = {
        "action": Parameter(Complete.CHOICES, choices=["status", "result"]),
    }

    def run(self, manager, args):
        owner = getattr(manager, "workspace_console", None)
        if owner is None:
            console.log("[red]error[/red]: background modules require a workspace console")
        elif args.action == "result":
            owner.module_result()
        else:
            owner.module_status()
