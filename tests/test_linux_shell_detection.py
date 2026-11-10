"""Shell detection through a real local terminal, without remote connections."""

import logging
import os
import shutil
import subprocess
import time
from unittest.mock import Mock

import pytest

from pwncat.channel import Channel, ChannelClosed
from pwncat.platform.linux import Linux


class LocalTerminal(Channel):
    """Bound terminal reads so a bootstrap regression cannot hang the test."""

    def __init__(self, descriptor):
        super().__init__(host="local-test")
        self.descriptor = descriptor
        self.deadline = time.monotonic() + 5
        os.set_blocking(descriptor, False)

    @property
    def connected(self):
        return self.descriptor is not None

    def send(self, data):
        return os.write(self.descriptor, data)

    def recv(self, count=None):
        if time.monotonic() > self.deadline:
            raise AssertionError("shell detection did not finish within five seconds")
        count = 65536 if count is None else count
        if self.peek_buffer:
            data = self.peek_buffer[:count]
            self.peek_buffer = self.peek_buffer[len(data):]
            return data
        try:
            data = os.read(self.descriptor, count)
        except BlockingIOError:
            return b""
        if not data:
            raise ChannelClosed(self)
        return data

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX terminal")
@pytest.mark.parametrize("terminal_formatting", [False, True])
def test_detect_shell_after_delayed_terminal_startup(tmp_path, terminal_formatting):
    import pty

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("requires bash")

    startup = tmp_path / "bashrc"
    startup.write_text(
        "sleep 0.1\nprintf 'Fixture startup banner\\n'\n"
        + (
            # Model terminal integration that emits a control sequence alongside
            # output. These bytes must not become part of the process ID.
            "echo() { builtin printf '\\033[?2004l'; builtin echo \"$@\"; }\n"
            if terminal_formatting else ""
        )
    )
    master, slave = pty.openpty()
    channel = LocalTerminal(master)
    try:
        process = subprocess.Popen(
            [bash, "--noprofile", "--rcfile", str(startup), "-i"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "TERM": "xterm", "PS1": "fixture$ "},
        )
    except BaseException:
        channel.close()
        raise
    finally:
        os.close(slave)

    try:
        platform = Linux.__new__(Linux)
        platform.channel = channel
        platform.logger = logging.getLogger(__name__)
        platform.command_running = None
        platform._interactive = True
        # /proc is not available on macOS; only metadata lookup is stubbed.
        platform.readlink = Mock(return_value=bash)
        platform.refresh_uid = Mock()

        platform.interactive = False

        platform.readlink.assert_called_once_with(f"/proc/{process.pid}/exe")
        platform.refresh_uid.assert_called_once()
        assert platform.shell == bash
    finally:
        process.kill()
        process.wait(timeout=3)
        channel.close()
