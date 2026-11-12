"""Command arguments without suggestions must not break Tab completion."""

import asyncio
from types import SimpleNamespace

import pytest
from prompt_toolkit.completion import CompleteEvent, DynamicCompleter
from prompt_toolkit.document import Document

from pwncat.commands import CommandCompleter
from pwncat.commands.alias import Command as AliasCommand
from pwncat.commands.download import Command as BuiltinDownloadCommand
from pwncat.commands.sessions import Command as SessionsCommand
from pwncat.commands.upload import Command as BuiltinUploadCommand
from pwncat.workspace.console_commands import WORKSPACE_COMMANDS


@pytest.fixture
def completer():
    manager = SimpleNamespace(target=None)
    commands = [cls(manager) for cls in [
        AliasCommand, SessionsCommand, *WORKSPACE_COMMANDS,
        BuiltinUploadCommand, BuiltinDownloadCommand,
    ]]
    commands.append(SimpleNamespace(PROG="raw", ARGS=None))
    return CommandCompleter(manager, commands)


def completions(completer, text, asynchronous=False):
    document = Document(text)
    event = CompleteEvent(completion_requested=True)
    if not asynchronous:
        return list(completer.get_completions(document, event))

    async def collect():
        # PromptSession uses this same asynchronous wrapper path.
        dynamic = DynamicCompleter(lambda: completer)
        return [
            result async for result in dynamic.get_completions_async(document, event)
        ]

    return asyncio.run(collect())


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("command", ["sessions", "alias", "select", "split", "window"])
def test_first_argument_without_completer_still_offers_flags(
    completer, command, asynchronous
):
    results = completions(completer, command + " ", asynchronous)
    words = {result.text for result in results}
    assert {"--help", "-h"} <= words
    if command == "sessions":
        assert {"--list", "--kill", "-l", "-k"} <= words


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "text, expected",
    [
        ("color ", {"auto", "on", "off", "--help", "-h"}),
        ("forward ", {"add", "list", "stop", "reverse", "--help", "-h"}),
        ("sessions --l", {"--list"}),
        ("sessions --", {"--list", "--kill", "--help"}),
        ("sessions -", {"--list", "--kill", "--help", "-l", "-k", "-h"}),
        ("select --h", {"--help"}),
        ("select %", set()),
        ("window title", set()),
        ("resume ", {"--help", "-h"}),
        ("download /remote /local --b", {"--background"}),
        ("download /remote /local ", {"--background", "-b", "--overwrite", "--help", "-h"}),
        ("upload /local /remote --b", {"--background"}),
        ("upload --b", {"--background"}),
        ("download --b", {"--background"}),
        ("raw ", set()),
        ("unknown ", set()),
    ],
)
def test_existing_completion_types_still_work(completer, text, expected, asynchronous):
    assert {item.text for item in completions(completer, text, asynchronous)} == expected


@pytest.mark.parametrize("asynchronous", [False, True])
def test_local_file_suggestions_still_work(completer, tmp_path, monkeypatch, asynchronous):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fixture.txt").write_text("fixture")
    results = completions(completer, "upload ./fi", asynchronous)
    assert [item.text for item in results] == ["fixture.txt"]
    assert results[0].start_position == -2
