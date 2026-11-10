"""Show transfer status when a workspace console is available."""

from pwncat.commands import CommandDefinition
from pwncat.util import console


class Command(CommandDefinition):
    """Show the current or most recent background file transfer."""

    PROG = "transfer-status"
    ARGS = {}
    LOCAL = True

    def run(self, manager, args):
        owner = getattr(manager, "workspace_console", None)
        if owner is None:
            console.log("Background transfer status is available in a workspace console.")
            return
        owner.transfer_status()
