"""Console completion, metadata rendering, and explicit color preferences."""

from unittest.mock import Mock

import pytest
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import fragment_list_to_text

from pwncat.workspace import WorkspaceError
from pwncat.workspace.console import COMMANDS, ConsoleState, WorkspaceConsole
from pwncat.workspace.console_ui import (
    WorkspaceCompleter,
    colors_enabled,
    output_console,
    prompt_text,
    toolbar_text,
)


@pytest.mark.parametrize(
    "line, completed",
    [
        ("hel", "help"),
        ("help sta", "help status"),
        ("forward a", "forward add"),
        ("split ve", "split vertical"),
        ("split %12 ho", "split %12 horizontal"),
        ("color of", "color off"),
        (
            'upload "source file" /tmp/destination --o',
            'upload "source file" /tmp/destination --overwrite',
        ),
        (
            'download /tmp/source "local file" --b',
            'download /tmp/source "local file" --background',
        ),
    ],
)
def test_completion_understands_argument_position(line, completed):
    results = list(
        WorkspaceCompleter(COMMANDS).get_completions(
            Document(line), CompleteEvent(completion_requested=True)
        )
    )
    assert len(results) == 1
    result = results[0]
    assert line[: len(line) + result.start_position] + result.text == completed


@pytest.mark.parametrize(
    "line",
    [
        'help "sta',
        'help "sta"',
        'window "my files',
        "upload a /tmp/des",
        "forward add 8080 ",
        "unknown ",
    ],
)
def test_completion_does_not_rewrite_quotes_paths_or_unavailable_commands(line):
    assert not list(
        WorkspaceCompleter(COMMANDS).get_completions(
            Document(line), CompleteEvent(completion_requested=True)
        )
    )


def test_download_background_completion_matches_dispatch(monkeypatch):
    console = WorkspaceConsole(Mock(), ConsoleState())
    started = Mock()
    monkeypatch.setattr(console, "start_transfer", started)
    console.execute("download /remote local --overwrite --background")
    started.assert_called_once_with(
        "download", "/remote", console.local_path("local"), True
    )


def test_color_override_is_local_and_respects_automatic_mode(monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    state = ConsoleState()
    backend = Mock()
    console = WorkspaceConsole(backend, state)
    assert not colors_enabled(state)
    console.execute("color on")
    assert colors_enabled(state)
    assert "\x1b[1;35m" in capsys.readouterr().out
    console.execute("color off")
    console.execute("help upload")
    assert "\x1b" not in capsys.readouterr().out
    console.execute("color auto")
    assert not colors_enabled(state)
    monkeypatch.delenv("NO_COLOR")
    assert colors_enabled(state)
    assert not backend.mock_calls
    with pytest.raises(WorkspaceError, match="Usage"):
        console.execute("color invalid")
    assert state.color_mode == "auto"


def test_redirected_output_stays_plain_in_automatic_mode(monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    output_console(ConsoleState()).print("example", style="bold magenta")
    assert capsys.readouterr().out == "example\n"


def test_prompt_and_toolbar_render_remote_metadata_as_literal_text():
    state = ConsoleState(selected="%3")
    name = "[red]lab\x1b]52;c;ignored\x07"
    prompt = fragment_list_to_text(prompt_text(state, name))
    toolbar = fragment_list_to_text(toolbar_text(state, name))
    assert prompt.startswith("(local) pwncat [workspace:")
    assert "[red]lab" in prompt and "[red]lab" in toolbar
    assert "\x1b" not in prompt + toolbar
    assert "\x07" not in prompt + toolbar
    assert "%3" in toolbar
