"""Create a local pwncat module and open it for editing."""

import importlib
from types import SimpleNamespace

from rich.markup import escape

from pwncat.commands import CommandDefinition, Complete, Parameter
from pwncat.module_files import create_module_file, module_root
from pwncat.modules import ModuleFailed
from pwncat.util import console


class Command(CommandDefinition):
    """Create a local module package and starter source, then edit it."""

    PROG = "module-new"
    ARGS = {
        "module": Parameter(Complete.NONE, metavar="MODULE", help="Dotted module name"),
    }
    LOCAL = True

    def run(self, manager, args):
        name = args.module
        try:
            if name in manager.modules:
                raise ModuleFailed(f"{name}: a module with this name already exists")
            source = create_module_file(name)
            importlib.invalidate_caches()
            manager.load_modules(str(module_root()))
            if name not in manager.modules:
                raise ModuleFailed(f"{name}: source was created but could not be loaded")
        except (ModuleFailed, OSError, ImportError, SyntaxError) as exc:
            console.log(f"[red]error[/red]: {escape(str(exc))}")
            return
        console.log(f"Created [cyan]{escape(name)}[/cyan]: {escape(str(source))}")
        edit = next(command for command in manager.parser.commands if command.PROG == "edit")
        edit.run(manager, SimpleNamespace(module=name))
