"""Delete a local user module without touching built-in source."""

import importlib
import sys
from pathlib import Path

from rich.markup import escape

from pwncat.commands import CommandDefinition, Complete, Parameter
from pwncat.module_files import check_local_path, module_path, module_root
from pwncat.modules import ModuleFailed
from pwncat.util import console


def local_module_choices(command):
    root = module_root()
    if not root.is_dir() or root.is_symlink():
        return
    for source in root.rglob("*.py"):
        if source.name == "__init__.py":
            continue
        name = ".".join((*source.relative_to(root).parts[:-1], source.stem))
        try:
            if module_path(name) != source:
                continue
            check_local_path(source)
        except ModuleFailed:
            continue
        if source.is_file():
            yield name


class Command(CommandDefinition):
    """Delete a local module file; built-in modules cannot be deleted."""

    PROG = "module-delete"
    ARGS = {
        "module": Parameter(
            Complete.CHOICES, choices=local_module_choices, metavar="MODULE",
            help="Local module to delete",
        ),
        "--yes,-y": Parameter(
            Complete.NONE, action="store_true", help="Skip the confirmation prompt"
        ),
    }
    LOCAL = True

    def run(self, manager, args):
        name = args.module
        try:
            source = module_path(name)
            check_local_path(source)
            if not source.is_file():
                raise ModuleFailed(f"{name}: no local user module file exists")
            if not args.yes:
                answer = input(f"Delete local module {name}? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    console.log("Deletion cancelled.")
                    return
            loaded = manager.modules.get(name)
            loaded_is_local = (
                loaded is not None and manager.module_source(name) == source.resolve()
            )
            source.unlink()
            if loaded_is_local:
                manager.modules.pop(name, None)
                if manager.config.module is loaded:
                    manager.config.back()
                manager._edited_module_hashes.pop(name, None)
            imported_name = "pwncat.modules." + name
            imported = sys.modules.get(imported_name)
            if imported is not None and getattr(imported, "__file__", None):
                if Path(imported.__file__).resolve() == source.resolve():
                    sys.modules.pop(imported_name, None)
            importlib.invalidate_caches()
        except (ModuleFailed, OSError, EOFError, KeyboardInterrupt) as exc:
            console.log(f"[red]error[/red]: {escape(str(exc))}")
            return
        console.log(f"Deleted local module [cyan]{escape(name)}[/cyan]: {escape(str(source))}")
