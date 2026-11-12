"""Paths and starter source for modules owned by the local user."""

from __future__ import annotations

import keyword
import os
from pathlib import Path

from pwncat.modules import ModuleFailed


def module_root() -> Path:
    data_home = os.environ.get("XDG_DATA_HOME") or "~/.local/share"
    return Path(os.path.expanduser(data_home)) / "pwncat" / "modules"


def module_parts(name: str) -> tuple[str, ...]:
    parts = tuple(name.split(".")) if isinstance(name, str) else ()
    if not parts or any(
        not part.isidentifier() or keyword.iskeyword(part) or part == "__init__"
        for part in parts
    ):
        raise ModuleFailed("Use a dotted Python module name, such as bootstrap.pwnbox.")
    return parts


def module_path(name: str) -> Path:
    parts = module_parts(name)
    return module_root().joinpath(*parts[:-1], parts[-1] + ".py")


def check_local_path(path: Path) -> None:
    root = module_root()
    if not path.is_relative_to(root):
        raise ModuleFailed("Module must be inside the local user module directory.")
    for candidate in (root, *path.relative_to(root).parents):
        if candidate == Path("."):
            continue
        current = candidate if candidate == root else root / candidate
        if current.is_symlink():
            raise ModuleFailed(f"Refusing a symlink in the module path: {current}")
    if path.is_symlink():
        raise ModuleFailed(f"Refusing a symlinked module file: {path}")


def starter_source(name: str) -> str:
    if name.startswith("bootstrap."):
        return '''"""Describe what this workspace bootstrap configures."""

from pwncat.modules import ModuleFailed
from pwncat.modules.workspace import WorkspaceModule
from pwncat.platform.linux import Linux


class Module(WorkspaceModule):
    """Configure the active workspace."""

    PLATFORM = [Linux]
    ARGUMENTS = {}

    def run(self, session):
        manager, backend, console, state = self.workspace_context(session)
        raise ModuleFailed("Edit this module to implement your bootstrap steps.")
'''
    return '''"""Describe what this module does."""

from pwncat.modules import BaseModule, ModuleFailed


class Module(BaseModule):
    """A local pwncat module."""

    PLATFORM = None
    ARGUMENTS = {}

    def run(self, session):
        raise ModuleFailed("Edit this module to implement its behavior.")
'''


def create_module_file(name: str) -> Path:
    parts = module_parts(name)
    path = module_path(name)
    root = module_root()
    check_local_path(path)
    root.mkdir(parents=True, exist_ok=True)
    directory = root
    for part in parts[:-1]:
        directory /= part
        if directory.is_symlink():
            raise ModuleFailed(f"Refusing a symlink in the module path: {directory}")
        directory.mkdir(exist_ok=True)
        initializer = directory / "__init__.py"
        if initializer.is_symlink():
            raise ModuleFailed(f"Refusing a symlinked package file: {initializer}")
        if not initializer.exists():
            with initializer.open("x", encoding="utf-8") as output:
                output.write('"""Local pwncat modules."""\n')
    with path.open("x", encoding="utf-8") as output:
        output.write(starter_source(name))
    return path
