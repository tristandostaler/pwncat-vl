"""Authenticated SSH workspaces, independent of pwncat target sessions."""


class WorkspaceError(Exception):
    """An actionable workspace failure, safe to show after terminal restoration."""


class ConnectionLost(WorkspaceError):
    """The SSH connection was lost. Only attachment may be retried."""


class OutcomeUnknown(WorkspaceError):
    """A submitted operation may have completed; never replay it automatically."""


class IdentityMismatch(WorkspaceError):
    """The remote workspace is not the instance the user selected."""
