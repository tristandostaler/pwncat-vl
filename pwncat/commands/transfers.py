"""Group file transfers between the local computer and pwncat sessions."""

from pwncat.commands import CommandRoute, GroupCommand


class Command(GroupCommand):
    """Upload, download, copy between sessions, and view transfer status."""

    PROG = "transfers"
    ROUTES = {
        ("upload",): CommandRoute("upload", summary="Upload to the active session"),
        ("download",): CommandRoute("download", summary="Download from the active session"),
        ("between",): CommandRoute(
            "session-transfer", summary="Copy a file between two sessions"
        ),
        ("status",): CommandRoute(
            "transfer-status", summary="Show the latest background transfer"
        ),
    }

    def run(self, manager, args):
        # Preserve the existing bare `transfers` status command.
        super().run(manager, args if args.strip() else "status")
