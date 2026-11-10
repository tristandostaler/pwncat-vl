"""Malformed shell identifiers and file metadata must fail without retries."""

from subprocess import CalledProcessError, CompletedProcess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from pwncat.platform import PlatformError
from pwncat.platform.linux import Linux


def platform_with_response(response):
    platform = SimpleNamespace()
    platform._parse_stat = lambda output: Linux._parse_stat(platform, output)
    platform.run = Mock(
        side_effect=[response, AssertionError("metadata request was repeated")]
    )
    return platform


@pytest.mark.parametrize("operation", [Linux.stat, Linux.lstat])
@pytest.mark.parametrize("output", ["", " ".join(["0"] * 9), " ".join(["0"] * 15)])
def test_incomplete_response_stops_after_one_request(operation, output):
    platform = platform_with_response(CompletedProcess([], 0, stdout=output))

    with pytest.raises(PlatformError, match="Invalid stat response"):
        operation(platform, "/fixture/example")

    platform.run.assert_called_once()


@pytest.mark.parametrize("operation", [Linux.stat, Linux.lstat])
def test_valid_metadata_with_spaces_in_filename_still_parses(operation):
    output = (
        "fixture file 123 8 81a4 1000 1001 801 42 1 0 0 "
        "1700000000 1700000001 1700000002 0 4096\n"
    )
    platform = platform_with_response(CompletedProcess([], 0, stdout=output))

    result = operation(platform, "/fixture/fixture file")

    assert result.st_mode == 0o100644
    assert result.st_ino == 42
    assert result.st_uid == 1000
    assert result.st_gid == 1001
    assert result.st_size == 123
    platform.run.assert_called_once()


@pytest.mark.parametrize("operation", [Linux.stat, Linux.lstat])
def test_failed_command_still_reports_missing_file(operation):
    platform = platform_with_response(CalledProcessError(1, ["stat"]))

    with pytest.raises(FileNotFoundError):
        operation(platform, "/fixture/missing")

    platform.run.assert_called_once()


@pytest.mark.parametrize(
    "pid",
    ["", "unexpected output", "12345\nfixture$ ", "12345\n67890", "１２３"],
)
def test_invalid_shell_pid_stops_before_metadata_lookup(pid):
    platform = SimpleNamespace(
        getenv=Mock(return_value=pid), readlink=Mock(), refresh_uid=Mock()
    )

    with pytest.raises(PlatformError, match="numeric process ID"):
        Linux.context_changed(platform)

    platform.readlink.assert_not_called()
    platform.refresh_uid.assert_not_called()


@pytest.mark.parametrize(
    "pid",
    [
        "12345\n",
        "\x1b[?2004l\r12345\r\n\x1b[?2004h",
        "\x1b[32m12345\x1b[0m\n",
    ],
)
def test_numeric_shell_pid_still_identifies_shell(pid):
    platform = SimpleNamespace(
        getenv=Mock(return_value=pid),
        readlink=Mock(return_value="/bin/sh"),
        refresh_uid=Mock(),
    )

    Linux.context_changed(platform)

    platform.readlink.assert_called_once_with("/proc/12345/exe")
    assert platform.shell == "/bin/sh"
    platform.refresh_uid.assert_called_once()
