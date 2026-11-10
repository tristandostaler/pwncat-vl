"""Open a local module in an editor and refresh it after the next save."""

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from rich.markup import escape

import pwncat.modules
from pwncat.commands import CommandDefinition, Complete, Parameter
from pwncat.util import console


def module_choices(command):
    yield from command.manager.modules
    if command.manager.target is not None:
        platform = command.manager.target.platform.name + "."
        for name in command.manager.modules:
            if name.startswith(platform) or name.startswith("agnostic."):
                yield name.split(".", 1)[1]


def module_name(manager, requested):
    if requested is None:
        if manager.config.module is None:
            raise pwncat.modules.ModuleNotFound("specify a module or use one first")
        return manager.config.module.name
    candidates = [requested]
    if manager.target is not None:
        candidates.append(manager.target.platform.name + "." + requested)
    candidates.append("agnostic." + requested)
    for name in candidates:
        if name in manager.modules:
            return name
    raise pwncat.modules.ModuleNotFound(requested)


def editor_command(source: Path):
    selected = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if selected:
        argv = shlex.split(selected)
        if not argv:
            raise ValueError("VISUAL/EDITOR is empty")
        return [*argv, str(source)]

    vscode_app = Path(
        "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
    )
    if sys.platform == "darwin" and vscode_app.is_file():
        return [str(vscode_app), "--reuse-window", str(source)]
    vscode = shutil.which("code")
    if vscode:
        return [vscode, "--reuse-window", str(source)]
    raise FileNotFoundError(
        "No editor found. Set VISUAL or EDITOR to an editor command."
    )


class Command(CommandDefinition):
    """Edit a local module in your IDE; the next run loads saved changes."""

    PROG = "edit"
    ARGS = {
        "module": Parameter(
            Complete.CHOICES, choices=module_choices, nargs="?", metavar="MODULE",
            help="Module to edit (defaults to the current module context)",
        ),
    }
    LOCAL = True

    def run(self, manager, args):
        try:
            name = module_name(manager, args.module)
            source = manager.module_source(name)
            if not os.access(source, os.W_OK):
                raise PermissionError(f"{source} is not writable")
            argv = editor_command(source)
            manager.watch_module(name)
            if Path(argv[0]).name in {"vi", "vim", "nvim", "nano", "emacs", "hx"}:
                subprocess.run(argv, check=True)
            else:
                subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
        except (pwncat.modules.ModuleFailed, OSError, ValueError, subprocess.SubprocessError) as exc:
            console.log(f"[red]error[/red]: {escape(str(exc))}")
            return
        console.log(
            f"Editing [cyan]{escape(name)}[/cyan]: {escape(str(source))}. "
            "Save in the editor; the next run reloads it automatically."
        )
