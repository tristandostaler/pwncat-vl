"""Opt-in credential storage using native OS vaults; no file-based fallback."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from dataclasses import dataclass, field

from . import WorkspaceError

SERVICE = "pwncat-vl.workspace.credentials.v1"
BACKENDS = {
    "darwin": [("keyring.backends.macOS", "Keyring")],
    "win32": [("keyring.backends.Windows", "WinVaultKeyring")],
    "linux": [
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
    ],
}


def native_backend():
    candidates = []
    for module, name in BACKENDS.get(sys.platform, []):
        try:
            cls = getattr(importlib.import_module(module), name)
            if module.endswith("kwallet"):

                class WorkspaceWallet(cls):
                    def _migrate(self, service):
                        # Never enumerate or migrate credentials belonging to other apps.
                        pass

                cls = WorkspaceWallet
            backend = cls()
            if backend.priority > 0:
                candidates.append((backend.priority, backend))
        except Exception:  # noqa: BLE001, S112 - unavailable probes must not log vault details
            continue
    if not candidates:
        raise WorkspaceError(
            "No supported secure credential store is available. Install this clone's dependencies "
            "and enable macOS Keychain, Windows Credential Manager, or Linux Secret Service/KWallet. "
            "WSL needs a Linux user credential service. No plaintext fallback is used."
        )
    return max(candidates, key=lambda item: item[0])[1]


@dataclass(frozen=True)
class Secrets:
    password: str | None = field(default=None, repr=False)
    passphrase: str | None = field(default=None, repr=False)


class CredentialStore:
    def __init__(self, root, alias, profile):
        binding = [
            os.path.abspath(root),
            alias,
            profile.host,
            profile.user,
            profile.port,
            profile.identity,
        ]
        self.reference = hashlib.sha256(
            json.dumps(binding, ensure_ascii=True).encode()
        ).hexdigest()
        self._backend = None

    @property
    def backend(self):
        if self._backend is None:
            self._backend = native_backend()
        return self._backend

    def check_reference(self, reference):
        if reference != self.reference:
            raise WorkspaceError(
                "Saved credentials belong to different connection/key settings. "
                "Run 'forget-credentials NAME' before changing those settings."
            )

    def _call(self, method, *args):
        backend = self.backend
        try:
            return getattr(backend, method)(SERVICE, self.reference, *args)
        except Exception:  # noqa: BLE001 - never include a vault exception or its secret arguments
            raise WorkspaceError(
                "The system credential store could not complete the request. Unlock it or allow access, "
                "then retry. Use --password or --passphrase to enter a replacement explicitly."
            ) from None

    def read(self, reference):
        self.check_reference(reference)
        raw = self._call("get_password")
        if raw is None:
            raise WorkspaceError(
                "Saved credentials are missing. Use --password --save-credentials to save them again."
            )
        try:
            if not isinstance(raw, str) or len(raw) > 16384:
                raise ValueError
            value = json.loads(raw)
            if (
                not isinstance(value, dict)
                or set(value) != {"password", "passphrase"}
                or any(v is not None and not isinstance(v, str) for v in value.values())
            ):
                raise ValueError
            return Secrets(**value)
        except (TypeError, ValueError):
            raise WorkspaceError(
                "Saved credential data is invalid. Forget the saved credentials and save them again."
            ) from None

    def write(self, secrets):
        if secrets.password is None and secrets.passphrase is None:
            raise WorkspaceError(
                "No password or key passphrase was supplied to save. SSH agent authentication needs no saved secret."
            )
        raw = json.dumps(
            {"password": secrets.password, "passphrase": secrets.passphrase},
            ensure_ascii=True,
        )
        self._call("set_password", raw)
        if self._call("get_password") != raw:
            raise WorkspaceError(
                "The system credential store did not confirm the saved value. Credentials were not confirmed saved."
            )

    def delete(self, reference):
        self.check_reference(reference)
        if self._call("get_password") is not None:
            self._call("delete_password")
        if self._call("get_password") is not None:
            raise WorkspaceError(
                "The system credential store did not confirm deletion; the profile was retained."
            )
