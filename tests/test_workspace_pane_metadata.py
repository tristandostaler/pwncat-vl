"""Pane metadata must remain usable when tmux cannot report a working directory."""

import pytest

from pwncat.workspace import WorkspaceError
from pwncat.workspace.tmux import TmuxWorkspace


def workspace_with_rows(rows):
    workspace = object.__new__(TmuxWorkspace)
    workspace.request = lambda *_args: rows
    return workspace


def test_panes_preserve_empty_and_quoted_working_directories():
    workspace = workspace_with_rows(
        [
            b"@0 %0 123 80 24 1 0",
            b"@1 %2 234 100 40 0 1 /tmp/a\\ b",
        ]
    )
    panes = workspace.panes()
    assert [pane.directory for pane in panes] == ["", "/tmp/a b"]
    assert workspace.pane("%0").id == "%0"


@pytest.mark.parametrize(
    "row",
    [
        b"@0 %0 123 80 24 1",  # missing a required flag
        b"@0 %0 123 80 24 1 0 /tmp/bad\\",  # malformed quoted path
        b"@0 %0 not-a-pid 80 24 1 0 /tmp",
    ],
)
def test_malformed_pane_metadata_still_fails_closed(row):
    with pytest.raises(WorkspaceError, match="Unexpected pane metadata"):
        workspace_with_rows([row]).panes()
