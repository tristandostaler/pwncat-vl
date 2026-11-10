"""Group creation and management of pwncat background listeners."""

from pwncat.commands import CommandRoute, GroupCommand


class Command(GroupCommand):
    """Start, inspect and stop local pwncat listeners."""

    PROG = "listener"
    ROUTES = {
        ("start",): CommandRoute("listen", summary="Start a background listener"),
        ("list",): CommandRoute("listeners", summary="List listeners", usage="listener list [--all]"),
        ("show",): CommandRoute("listeners", summary="Show one listener", usage="listener show ID"),
        ("stop",): CommandRoute("listeners", ("--kill",), "Stop one listener", "listener stop ID"),
        ("init",): CommandRoute("listeners", ("--init",), "Initialize pending channels", "listener init ID"),
    }

    def routed_arguments(self, path, arguments):
        if path == ("list",):
            if arguments not in ([], ["--all"], ["-a"]):
                raise ValueError("usage: listener list [--all]")
        elif path in (("show",), ("stop",), ("init",)):
            if len(arguments) != 1:
                raise ValueError(f"usage: listener {path[0]} ID")
        return arguments
