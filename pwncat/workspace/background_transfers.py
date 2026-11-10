"""One background transfer per live workspace console."""

from __future__ import annotations

import threading
import time
from contextlib import closing
from dataclasses import dataclass, replace

from pwncat.util import human_readable_size

from . import WorkspaceError
from .files import FileService
from .model import safe_text
from .platform import WorkspaceChannel


@dataclass(frozen=True)
class TransferStatus:
    number: int
    action: str
    session_id: int
    source: str
    destination: str
    state: str
    transferred: int = 0
    total: int | None = None
    phase: str = "starting"
    size: int | None = None
    sha256: str | None = None
    error: str | None = None


def progress_text(status):
    """Format a snapshot without treating copied bytes as a published file."""
    copied = human_readable_size(status.transferred, 1)
    if status.total is None:
        return f"{copied} copied; {status.phase}"
    total = human_readable_size(status.total, 1)
    percentage = 100.0 if status.total == 0 else min(
        100.0, 100.0 * status.transferred / status.total
    )
    return f"{copied} / {total} ({percentage:.1f}%) copied; {status.phase}"


class BackgroundTransfers:
    def __init__(self, on_update=None):
        self._lock = threading.Lock()
        self._status = None
        self._session = None
        self._thread = None
        self._on_update = on_update
        self._last_notification = 0.0

    def status(self):
        with self._lock:
            return self._status

    def active(self):
        with self._lock:
            return self._status is not None and self._status.state == "running"

    def busy_session(self, session):
        with self._lock:
            return (
                self._status is not None
                and self._status.state == "running"
                and self._session is session
                and not isinstance(session.platform.channel, WorkspaceChannel)
            )

    def start(self, session, connection, action, source, destination, *, overwrite=False):
        if action not in ("upload", "download"):
            raise ValueError(action)
        with self._lock:
            if self._status is not None and self._status.state == "running":
                raise WorkspaceError("A transfer is already running. Use 'transfers' to check it.")
            number = 1 if self._status is None else self._status.number + 1
            status = TransferStatus(number, action, session.id, source, destination, "running")
            self._status = status
            self._session = session
            worker = threading.Thread(
                target=self._run,
                args=(status, session, connection, overwrite),
                name=f"workspace-transfer-{number}",
                daemon=True,
            )
            self._thread = worker
            try:
                worker.start()
            except RuntimeError:
                self._status = None
                self._session = None
                self._thread = None
                raise
            return status

    def _update(self, status, **changes):
        notify = False
        with self._lock:
            current = self._status
            if current is not None and current.number == status.number and current.state == "running":
                self._status = replace(current, **changes)
                now = time.monotonic()
                if (
                    self._on_update is not None
                    and ("phase" in changes or "state" in changes or now - self._last_notification >= 0.2)
                ):
                    self._last_notification = now
                    notify = True
        if notify:
            try:
                self._on_update()
            except Exception:
                pass  # A terminal redraw failure must not corrupt a transfer.

    def _run(self, status, session, connection, overwrite):
        try:
            if isinstance(session.platform.channel, WorkspaceChannel):
                # A separate SFTP channel leaves the workspace shell and the
                # metadata SFTP channel free for console and pane operations.
                with closing(connection.new_filesystem()) as sftp:
                    result = getattr(FileService(sftp), status.action)(
                        status.source, status.destination, overwrite=overwrite,
                        progress=lambda count: self._update(status, transferred=count),
                        status=lambda phase, total: self._update(
                            status, phase=phase, total=total
                        ),
                    )
            else:
                from . import session_files

                result = getattr(session_files, status.action)(
                    session.platform, status.source, status.destination,
                    overwrite=overwrite,
                    progress=lambda count: self._update(status, transferred=count),
                    status=lambda phase, total: self._update(
                        status, phase=phase, total=total
                    ),
                )
            self._update(
                status, state="completed", phase="completed",
                transferred=result.size, total=result.size,
                size=result.size, sha256=result.sha256,
            )
        except Exception as exc:
            self._update(status, state="failed", phase="failed", error=safe_text(exc))
