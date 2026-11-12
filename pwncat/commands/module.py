"""Group module discovery, editing and execution commands."""

from pwncat.commands import CommandRoute, GroupCommand


class Command(GroupCommand):
    """Find, inspect, edit and run pwncat modules."""

    PROG = "module"
    ROUTES = {
        ("list",): CommandRoute("list", summary="List all loaded modules"),
        ("run",): CommandRoute("run", summary="Run a module on the active session"),
        ("status",): CommandRoute("module-task", ("status",), "Show the latest background module's status", "module status"),
        ("result",): CommandRoute("module-task", ("result",), "Show the latest background module's result", "module result"),
        ("edit",): CommandRoute("edit", summary="Open local module source in an editor"),
        ("new",): CommandRoute("module-new", summary="Create and edit a local module"),
        ("delete",): CommandRoute("module-delete", summary="Delete a local module file"),
        ("reload",): CommandRoute("reload", summary="Refresh a module from disk"),
        ("info",): CommandRoute("info", summary="Show module details and arguments"),
        ("search",): CommandRoute("search", summary="Find modules by pattern"),
        ("load",): CommandRoute("load", summary="Load modules from a local directory"),
        ("use",): CommandRoute("use", summary="Enter a module context"),
    }
