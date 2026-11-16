#!/usr/bin/env python3

from pathlib import Path

from rich.markup import escape

from pwncat.commands import Complete, Parameter, CommandDefinition
from pwncat.util import console


class Command(CommandDefinition):
    """
    Load modules from the specified directory. This does not remove
    currently loaded modules, but may replace modules which were already
    loaded. Also, prior to loading any specified modules, the standard
    modules are loaded. This normally happens only when modules are first
    utilized. This ensures that a standard module does not shadow a custom
    module. In fact, the opposite may happen in a custom module is defined
    with the same name as a standard module.
    """

    PROG = "load"
    ARGS = {
        "path": Parameter(
            Complete.LOCAL_FILE,
            help="Path to a python package directory to load modules from",
            nargs="+",
        ),
    }
    DEFAULTS = {}
    LOCAL = True

    def run(self, manager, args):
        paths = [Path(path).expanduser() for path in args.path]
        for path in paths:
            if not path.is_dir():
                reason = "does not exist" if not path.exists() else "is not a directory"
                console.log(f"[red]error[/red]: {escape(str(path))} {reason}")
                return

        before = set(manager.modules)
        manager.load_modules(*(str(path) for path in paths))
        new_modules = sorted(set(manager.modules) - before)
        if new_modules:
            console.log(f"Loaded {len(new_modules)} new module(s): {escape(', '.join(new_modules))}")
        else:
            console.log("No new modules found in the supplied directory.")
