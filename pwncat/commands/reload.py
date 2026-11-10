"""Refresh a loaded module from its local Python source."""

from rich.markup import escape

import pwncat.modules
from pwncat.commands import CommandDefinition, Complete, Parameter
from pwncat.commands.edit import module_choices, module_name
from pwncat.util import console


def reload_choices(command):
    yield "all"
    yield from module_choices(command)


class Command(CommandDefinition):
    """Reload a local module now, for example before using info or run."""

    PROG = "reload"
    ARGS = {
        "module": Parameter(
            Complete.CHOICES, choices=reload_choices, nargs="?", metavar="MODULE",
            help="Module to reload, or all (defaults to the current module context)",
        ),
    }
    LOCAL = True

    def run(self, manager, args):
        if args.module == "all":
            names = sorted(manager.modules)
            if not names:
                console.log("No modules are loaded.")
                return
            failures = []
            for name in names:
                try:
                    manager.reload_module(name)
                except pwncat.modules.ModuleFailed as exc:
                    failures.append((name, str(exc)))
            console.log(f"Reloaded {len(names) - len(failures)}/{len(names)} modules.")
            for name, error in failures:
                detail = error if error.startswith(f"{name}:") else f"{name}: {error}"
                console.log(f"[red]error[/red]: {escape(detail)}")
            return
        try:
            name = module_name(manager, args.module)
            manager.reload_module(name)
        except pwncat.modules.ModuleFailed as exc:
            console.log(f"[red]error[/red]: {escape(str(exc))}")
            return
        console.log(f"Reloaded [cyan]{escape(name)}[/cyan] from local source.")
