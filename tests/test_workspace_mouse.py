"""Mouse packets from Screen and tmux must not crash the workspace console."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from prompt_toolkit.key_binding.bindings.mouse import load_mouse_bindings
from prompt_toolkit.keys import Keys

from pwncat.workspace.console import _handle_workspace_mouse


@pytest.mark.parametrize("button", [71, 99, 125])
def test_unsupported_x10_mouse_packets_are_ignored(button):
    default_mouse = next(
        binding.handler for binding in load_mouse_bindings().bindings
        if binding.keys == (Keys.Vt100MouseEvent,)
    )
    scrollback = Mock()
    event = SimpleNamespace(data="\x1b[M" + chr(button) + "!!")

    with pytest.raises(KeyError):
        default_mouse(event)
    _handle_workspace_mouse(event, default_mouse, scrollback)

    scrollback.assert_not_called()


@pytest.mark.parametrize("data", ["\x1b[M`!!", "\x1b[Md!!", "\x1b[<64;5;3M", "\x1b[<68;5;3M"])
def test_wheel_up_opens_scrollback(data):
    default_mouse = Mock()
    scrollback = Mock()

    _handle_workspace_mouse(SimpleNamespace(data=data), default_mouse, scrollback)

    default_mouse.assert_not_called()
    scrollback.assert_called_once_with()


@pytest.mark.parametrize("data", ["\x1b[M !!", "\x1b[Ma!!", "\x1b[<65;5;3M"])
def test_supported_mouse_packets_reach_prompt_toolkit(data):
    default_mouse = Mock(return_value="handled")
    scrollback = Mock()
    event = SimpleNamespace(data=data)

    assert _handle_workspace_mouse(event, default_mouse, scrollback) == "handled"

    default_mouse.assert_called_once_with(event)
    scrollback.assert_not_called()
