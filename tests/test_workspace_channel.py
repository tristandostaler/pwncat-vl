"""Workspace SSH reads distinguish idle channels from actual disconnects."""

import socket
from types import SimpleNamespace
from unittest.mock import Mock

import paramiko
import pytest

from pwncat.channel import ChannelClosed
from pwncat.workspace.platform import WorkspaceChannel


@pytest.fixture
def channel():
    # Exercise Paramiko's actual nonblocking buffer without any network access.
    ssh_channel = paramiko.Channel(0)
    backend = SimpleNamespace(
        connection=SimpleNamespace(
            profile=SimpleNamespace(host="example.invalid", port=22, user="user"),
            client=Mock(invoke_shell=Mock(return_value=ssh_channel)),
        )
    )
    instance = WorkspaceChannel(backend)
    try:
        yield instance
    finally:
        ssh_channel.close()


@pytest.mark.parametrize("count", [None, 1024])
def test_idle_channel_can_receive_later_data(channel, count):
    assert channel.recv(count) == b""
    assert channel.connected

    channel.channel.in_buffer.feed(b"ready\n")
    assert channel.recv(count) == b"ready\n"
    assert channel.recv(count) == b""
    assert channel.connected


def test_peeked_data_survives_an_idle_read(channel):
    channel.channel.in_buffer.feed(b"ready\n")
    assert channel.peek() == b"ready\n"
    assert channel.recv(1024) == b"ready\n"
    assert channel.recv(1024) == b""
    assert channel.connected


def test_actual_eof_is_still_reported_as_closed(channel):
    channel.channel.in_buffer.close()
    with pytest.raises(ChannelClosed):
        channel.recv(1024)
    assert not channel.connected


def test_connection_error_is_still_reported_as_closed(channel, monkeypatch):
    failure = ConnectionResetError("connection reset")
    monkeypatch.setattr(channel.channel, "recv", Mock(side_effect=failure))
    with pytest.raises(ChannelClosed) as error:
        channel.recv(1024)
    assert error.value.__cause__ is failure
    assert not channel.connected


def test_full_ssh_window_retries_the_unsent_bytes(channel, monkeypatch):
    send = Mock(side_effect=[socket.timeout(), 2, 2])
    monkeypatch.setattr(channel.channel, "send", send)
    monkeypatch.setattr("pwncat.workspace.platform.time.sleep", Mock())

    assert channel.send(b"data") == 4
    assert [bytes(call.args[0]) for call in send.call_args_list] == [
        b"data", b"data", b"ta"
    ]
    assert channel.connected


def test_zero_write_on_closed_ssh_channel_ends_send(channel, monkeypatch):
    monkeypatch.setattr(channel.channel, "send", Mock(return_value=0))
    channel.channel.closed = True

    with pytest.raises(ChannelClosed):
        channel.send(b"data")
    assert not channel.connected


def test_zero_write_after_ssh_eof_ends_send(channel, monkeypatch):
    monkeypatch.setattr(channel.channel, "send", Mock(return_value=0))
    channel.channel.eof_sent = True

    with pytest.raises(ChannelClosed):
        channel.send(b"data")
    assert not channel.connected


def test_stalled_ssh_window_does_not_retry_forever(channel, monkeypatch):
    monkeypatch.setattr(channel.channel, "send", Mock(return_value=0))
    clock = SimpleNamespace(monotonic=Mock(side_effect=[0, 31]), sleep=Mock())
    monkeypatch.setattr("pwncat.workspace.platform.time", clock)

    with pytest.raises(ChannelClosed):
        channel.send(b"data")
    assert not channel.connected
