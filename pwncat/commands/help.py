#!/usr/bin/env python3
import textwrap

import rich.box
from rich.table import Table, Column

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition, GroupCommand


class Command(CommandDefinition):
    """
    List known commands and print their associated help documentation.
    """

    PROG = "help"
    ARGS = {"topic": Parameter(Complete.NONE, nargs="*", metavar="COMMAND")}
    LOCAL = True

    def run(self, manager: "pwncat.manager.Manager", args):
        if args.topic:
            for command in manager.parser.commands:
                if args.topic[0] == command.PROG:
                    if isinstance(command, GroupCommand):
                        command.show_help(args.topic[1:])
                        return
                    if len(args.topic) > 1:
                        console.log(
                            f"[red]error[/red]: {command.PROG}: no subcommand "
                            f"{' '.join(args.topic[1:])}"
                        )
                        return
                    if command.parser is not None:
                        command.parser.print_help()
                    else:
                        console.print(textwrap.dedent(command.__doc__).strip())
                    return
            console.log(f"[red]error[/red]: {args.topic[0]}: unknown command")
        else:
            table = Table(
                Column("Command", style="green"),
                Column("Description", no_wrap=True),
                box=rich.box.SIMPLE,
            )

            grouped_names = {
                route.command for group in manager.parser.commands
                if isinstance(group, GroupCommand)
                for route in group.ROUTES.values()
            }
            for command in manager.parser.commands:
                if command.PROG in grouped_names:
                    continue
                doc = command.__doc__
                if doc is None:
                    doc = ""
                else:
                    doc = textwrap.shorten(
                        textwrap.dedent(doc).strip().replace("\n", ""), 60,
                    )

                table.add_row(command.PROG, doc)

            console.print(table)
