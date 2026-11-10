"""Terminal presentation shared by the workspace console's safe command set."""

from __future__ import annotations

import os
import re
import shlex
from typing import ClassVar

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, WordCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style, merge_styles, style_from_pygments_cls
from pygments.lexer import RegexLexer, words
from pygments.styles import get_style_by_name
from pygments.token import Name, Number, String, Text
from rich.console import Console

from .model import safe_text


def colors_enabled(state):
    if state.color_mode != "auto":
        return state.color_mode == "on"
    return "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


def prompt_color_depth(state):
    if not colors_enabled(state):
        return ColorDepth.DEPTH_1_BIT
    return ColorDepth.DEPTH_8_BIT if state.color_mode == "on" else None


def output_console(state):
    return Console(
        emoji=False,
        highlight=False,
        no_color=not colors_enabled(state),
        force_terminal=True if state.color_mode == "on" else None,
    )


def prompt_text(state, name):
    return [
        ("class:prompt.local", "(local) "),
        ("class:prompt.name", "pwncat"),
        (
            "class:prompt.context",
            f" [workspace:{safe_text(name)}:{safe_text(state.selected or '-')}]",
        ),
        ("class:prompt.symbol", "$ "),
    ]


def toolbar_text(state, name):
    return [
        (
            "class:bottom-toolbar",
            f" Workspace: {safe_text(name)} | Pane: {safe_text(state.selected or '-')} ",
        ),
        ("class:bottom-toolbar", "| Tab: complete | Ctrl+R: history | Ctrl+Q: resume "),
    ]


class WorkspaceCompleter(Completer):
    def __init__(self, commands):
        self.commands = commands

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        raw_word = re.search(r"\S*$", text).group()
        if any(character in raw_word for character in "'\"\\"):
            return
        try:
            parts = shlex.split(text)
        except ValueError:
            return  # Do not rewrite an unfinished quoted path or window title.
        if not parts or text[-1:].isspace():
            parts.append("")
        choices, metadata = [], {}
        if len(parts) == 1 or (len(parts) == 2 and parts[0] == "help"):
            choices = list(self.commands)
            metadata = {name: info[1] for name, info in self.commands.items()}
        elif len(parts) == 2 and parts[0] == "forward":
            choices = ["add", "list", "stop"]
        elif len(parts) == 2 and parts[0] == "color":
            choices = ["auto", "on", "off"]
        elif parts[0] == "split" and (
            len(parts) == 2 or (len(parts) == 3 and re.fullmatch(r"%[0-9]+", parts[1]))
        ):
            choices = ["horizontal", "vertical"]
        elif len(parts) >= 4 and parts[0] in ("upload", "download"):
            choices = ["--overwrite", "--background", "-b"]
        # Static choices only: completion never runs a remote command or reads
        # a directory, and cannot suggest legacy modules unavailable here.
        yield from WordCompleter(
            choices, meta_dict=metadata, WORD=True
        ).get_completions(Document(parts[-1]), complete_event)


def command_lexer(commands):
    class WorkspaceLexer(RegexLexer):
        tokens: ClassVar[dict] = {
            "root": [
                (words(tuple(commands), prefix=r"^\s*", suffix=r"\b"), Name.Function),
                (r'"([^"\\]|\\.)*("|$)', String),
                (r"'[^']*('|$)", String),
                (r"--[a-z][a-z-]*\b", Name.Label),
                (r"%[0-9]+\b", Name.Variable),
                (r"\b[0-9]+\b", Number),
                (r"\s+", Text),
                (r".", Text),
            ]
        }

    return PygmentsLexer(WorkspaceLexer)


def create_prompt(state, commands, name):
    bindings = KeyBindings()

    @bindings.add("c-q")
    def resume(event):
        # Abandon pending input. Returning a command keeps pane validation in
        # WorkspaceConsole instead of switching terminal ownership here.
        event.app.exit(result="resume")

    theme = merge_styles(
        [
            style_from_pygments_cls(get_style_by_name("monokai")),
            Style.from_dict(
                {
                    "prompt.local": "ansiyellow bold",
                    "prompt.name": "ansimagenta bold",
                    "prompt.context": "ansicyan",
                    "prompt.symbol": "bold",
                    "bottom-toolbar": "#d8dee9 bg:#30343f",
                    "auto-suggestion": "#777777",
                    "completion-menu.completion": "#d8dee9 bg:#30343f",
                    "completion-menu.completion.current": "#ffffff bg:#5f5f87 bold",
                }
            ),
        ]
    )
    return PromptSession(
        message=lambda: prompt_text(state, name),
        bottom_toolbar=lambda: toolbar_text(state, name),
        history=state.history,
        auto_suggest=AutoSuggestFromHistory(),
        enable_history_search=True,
        completer=WorkspaceCompleter(commands),
        lexer=command_lexer(commands),
        style=theme,
        color_depth=prompt_color_depth(state),
        include_default_pygments_style=False,
        complete_while_typing=False,
        key_bindings=bindings,
    )
