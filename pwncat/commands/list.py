"""List every module currently loaded by pwncat."""

import textwrap

from rich import box
from rich.table import Table

from pwncat.commands import CommandDefinition
from pwncat.util import console


class Command(CommandDefinition):
    """List loaded modules, including custom modules and other platforms."""

    PROG = "list"
    ARGS = {}
    LOCAL = True

    def run(self, manager, args):
        table = Table(title=f"Loaded Modules ({len(manager.modules)})", box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("Description")

        for name, module in sorted(manager.modules.items()):
            description = " ".join((module.__doc__ or "").split())
            table.add_row(name, textwrap.shorten(description, width=80))

        console.print(table)
