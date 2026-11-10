"""One isolated background module run per live workspace console."""

from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, field, replace
from typing import Any

from . import WorkspaceError
from .model import safe_text


@dataclass(frozen=True)
class ModuleRunStatus:
    number: int
    name: str
    session_id: int
    state: str
    raw: bool = False
    traceback_requested: bool = False
    error: str | None = None
    traceback: str | None = None
    result: Any = field(default=None, repr=False, compare=False)
    session: Any = field(default=None, repr=False, compare=False)


class BackgroundModules:
    def __init__(self, on_update=None):
        self._lock = threading.Lock()
        self._status = None
        self._session = None
        self._thread = None
        self._on_update = on_update

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
            )

    def start(self, session, module, values, config, *, raw=False, traceback_requested=False):
        with self._lock:
            if self._status is not None and self._status.state == "running":
                raise WorkspaceError(
                    "A module is already running. Use 'module status' to check it."
                )
            number = 1 if self._status is None else self._status.number + 1
            status = ModuleRunStatus(
                number, module.name, session.id, "running", raw=raw,
                traceback_requested=traceback_requested, session=session,
            )
            self._status = status
            self._session = session
            worker = threading.Thread(
                target=self._run,
                args=(status, session, module, dict(values), config),
                name=f"workspace-module-{number}",
                daemon=True,
            )
            self._thread = worker
            try:
                worker.start()
            except Exception:
                self._status = None
                self._session = None
                self._thread = None
                raise
        return status

    def _update(self, status, **changes):
        with self._lock:
            if self._status is None or self._status.number != status.number:
                return
            self._status = replace(self._status, **changes)
        if self._on_update is not None:
            try:
                self._on_update()
            except Exception:
                pass

    def _run(self, status, session, module, values, config):
        config_slot = getattr(session, "_background_config", None)
        if config_slot is not None:
            config_slot.value = config
        try:
            # Keep the instance checked at launch even if its source is edited
            # before this worker begins. Nested session.run calls still work.
            result = module.run(session, progress=False, **values)
            self._update(status, state="completed", result=result)
        except BaseException as exc:
            self._update(
                status,
                state="failed",
                error=safe_text(str(exc) or type(exc).__name__),
                traceback=traceback.format_exc(),
            )
        finally:
            if config_slot is not None:
                del config_slot.value
