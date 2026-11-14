"""Keep a live workspace client in a private local screen session."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from . import WorkspaceError


INNER = "PWNCAT_WORKSPACE_SCREEN_INNER"
DISABLE = "PWNCAT_WORKSPACE_SCREEN_DISABLE"


def _screen_env(*, inner=False):
    env = os.environ.copy()
    # Older Screen releases reject terminal names longer than 20 characters.
    if len(env.get("TERM", "")) > 20:
        env["TERM"] = "xterm-256color"
    if inner:
        env[INNER] = "1"
    return env


@contextmanager
def _scrollback_screenrc():
    """Start Screen with the terminal's normal alternate-screen behavior."""
    with tempfile.NamedTemporaryFile(
        mode="w", prefix="pwncat-screen-", suffix=".screenrc"
    ) as config:
        user_config = Path.home() / ".screenrc"
        if user_config.is_file():
            quoted = str(user_config).replace("\\", "\\\\").replace('"', '\\"')
            config.write(f'source "{quoted}"\n')
        # A user screenrc may disable ti/te, leaving cmux on its normal buffer
        # where the wheel cannot navigate remote tmux copy mode. Re-enable the
        # outer terminal's alternate buffer for this workspace display.
        config.write(r"termcapinfo * ti=\E[?1049h:te=\E[?1049l" + "\n")
        config.write("defscrollback 50000\n")
        # In copy mode, terminals may send either normal or application cursor
        # sequences for the wheel. Translate both without changing the prompt's
        # Up/Down history bindings outside copy mode.
        for sequence, direction in ((r"\033[A", "k"), (r"\033[B", "j"),
                                    (r"\033OA", "k"), (r"\033OB", "j")):
            config.write(f'bindkey -m "{sequence}" stuff {direction}\n')
        config.flush()
        yield config.name


def managed():
    return os.environ.get(INNER) == "1" and bool(os.environ.get("STY"))


def available():
    return (
        os.name != "nt"
        and os.environ.get(INNER) != "1"
        and os.environ.get(DISABLE) != "1"
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and shutil.which("screen") is not None
    )


def session_name(alias, connection, remote_name):
    identity = "\0".join(
        (alias, connection.host, connection.user, str(connection.port), remote_name)
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"pwncat-{alias}-{digest}"


def _existing(screen, name):
    result = subprocess.run(
        [screen, "-ls", name], capture_output=True, text=True, timeout=5,
    )
    pattern = re.compile(r"^\s*(\d+\." + re.escape(name) + r")\s+\((Detached|Attached)\)")
    sessions = [match.groups() for line in result.stdout.splitlines() if (match := pattern.match(line))]
    if len(sessions) > 1:
        raise WorkspaceError("Multiple local clients match this workspace; inspect 'screen -ls' before attaching.")
    return sessions[0] if sessions else None


def attach_or_start(argv, alias, connection, remote_name, *, takeover=False, new=False):
    screen = shutil.which("screen")
    if screen is None:
        raise WorkspaceError("Local screen is required to preserve live sessions.")
    name = session_name(alias, connection, remote_name)
    current = _existing(screen, name)
    if current:
        ident, state = current
        if new:
            raise WorkspaceError("A local client already owns this workspace. Attach to it before creating another.")
        if state == "Attached" and not takeover:
            raise WorkspaceError("This workspace client is attached in another terminal. Use --takeover to move it here.")
        with _scrollback_screenrc() as config:
            command = [screen, "-c", config]
            command += ["-d", "-r", ident] if state == "Attached" else ["-r", ident]
            return subprocess.call(command, env=_screen_env())
    env = _screen_env(inner=True)
    with _scrollback_screenrc() as config:
        command = [
            screen, "-c", config, "-m", "-S", name,
            sys.executable, "-m", "pwncat.workspace.screen_client", *argv,
        ]
        return subprocess.call(command, env=env)


def park():
    """Detach the terminal while the child process and all sessions continue."""
    if not managed():
        raise WorkspaceError("This workspace client is not managed by local screen.")
    screen = shutil.which("screen")
    if screen is None:
        raise WorkspaceError("Local screen is unavailable; live sessions were retained.")
    result = subprocess.run(
        [screen, "-S", os.environ["STY"], "-X", "detach"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode:
        raise WorkspaceError("Could not detach local screen; live sessions were retained.")
