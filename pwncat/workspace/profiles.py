"""Private local shortcuts. Store connection choices, never authentication secrets."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from urllib.parse import quote

from . import IdentityMismatch, WorkspaceError
from .credentials import CredentialStore, Secrets
from .model import ForwardRule, ListenerRule, ReverseForwardRule, WorkspaceRef, workspace_name
from .ssh import SSHProfile


def normalize_hostname(value):
    """Accept a hostname or IP address, without changing other SSH settings."""
    try:
        if not value or any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
            if ":" not in value:
                raise ValueError
        if ":" in value:
            if "%" in value:
                raise ValueError
            return str(ipaddress.IPv6Address(value))
        value = value.encode("idna").decode("ascii").lower()
        if (
            len(value.rstrip(".")) > 253
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in value.rstrip(".").split(".")
            )
            or value.endswith("..")
        ):
            raise ValueError
        return value
    except (ValueError, UnicodeError, AttributeError, TypeError) as exc:
        raise WorkspaceError(
            "Use a hostname or IP address for --host, without a username, URL, or port."
        ) from exc


def validate_username(value):
    """Keep literal SSH account names, including DOMAIN\\user and user@domain."""
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise WorkspaceError("Use a nonempty SSH username without control characters.")
    return value


@dataclass(frozen=True)
class SavedWorkspace:
    alias: str
    connection: SSHProfile
    password_prompt: bool
    passphrase_prompt: bool
    ref: WorkspaceRef
    credential_ref: str | None = None
    forwards: tuple[ForwardRule, ...] = ()
    history_binding: str | None = None
    reverse_forwards: tuple[ReverseForwardRule, ...] = ()
    listeners: tuple[ListenerRule, ...] = ()

    @property
    def console_history_binding(self):
        # Keep existing history after an explicit connection edit. Ordinary
        # destination changes and replacement workspaces still get new bindings.
        if self.history_binding is not None:
            return self.history_binding
        context = [
            self.alias,
            self.connection.host,
            self.connection.user,
            self.connection.port,
            asdict(self.ref),
        ]
        return hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()

    def check_destination(self, connection, remote_name):
        if (
            self.connection.host,
            self.connection.user,
            self.connection.port,
            self.ref.name,
        ) != (connection.host, connection.user, connection.port, remote_name):
            raise WorkspaceError(
                "Local workspace name already points to another destination. "
                "Choose a different --alias, or forget the old local profile first."
            )

    def document(self):
        # Explicit allowlist: SSHProfile also holds in-memory secrets.
        profile = self.connection
        return {
            "version": 1,
            "alias": self.alias,
            "ssh": {
                "host": profile.host,
                "user": profile.user,
                "port": profile.port,
                "identity": profile.identity,
                "known_hosts": profile.known_hosts,
                "password_prompt": self.password_prompt,
                "passphrase_prompt": self.passphrase_prompt,
            },
            "workspace": asdict(self.ref),
            "credential_ref": self.credential_ref,
            "forwards": [asdict(rule) for rule in self.forwards],
            "reverse_forwards": [asdict(rule) for rule in self.reverse_forwards],
            "listeners": [asdict(rule) for rule in self.listeners],
            "history_binding": self.history_binding,
        }

    @classmethod
    def parse(cls, value, alias):
        try:
            if value["version"] != 1 or value["alias"] != alias:
                raise ValueError
            ssh = value["ssh"]
            if set(ssh) != {
                "host",
                "user",
                "port",
                "identity",
                "known_hosts",
                "password_prompt",
                "passphrase_prompt",
            }:
                raise ValueError
            if not isinstance(ssh["host"], str) or not isinstance(ssh["user"], str):
                raise TypeError
            if type(ssh["port"]) is not int or not 1 <= ssh["port"] <= 65535:
                raise ValueError
            for key in ("password_prompt", "passphrase_prompt"):
                if type(ssh[key]) is not bool:
                    raise ValueError
            for key in ("identity", "known_hosts"):
                if ssh[key] is not None and (
                    not isinstance(ssh[key], str)
                    or not os.path.isabs(ssh[key])
                    or any(ord(c) < 32 for c in ssh[key])
                ):
                    raise ValueError
            host = f"[{ssh['host']}]" if ":" in ssh["host"] else ssh["host"]
            connection = SSHProfile.parse(
                f"ssh://{quote(ssh['user'], safe='')}@{host}:{ssh['port']}",
                identity=ssh["identity"],
                known_hosts=ssh["known_hosts"],
            )
            if (connection.host, connection.user) != (ssh["host"], ssh["user"]):
                raise ValueError
            ref = WorkspaceRef(**value["workspace"])
            credential_ref = value.get("credential_ref")
            if credential_ref is not None and not re.fullmatch(
                r"[0-9a-f]{64}", credential_ref
            ):
                raise ValueError
            history_binding = value.get("history_binding")
            if history_binding is not None and not re.fullmatch(
                r"[0-9a-f]{64}", history_binding
            ):
                raise ValueError
            workspace_name(ref.name)
            if not re.fullmatch(r"[0-9a-f]{32}", ref.uuid) or not re.fullmatch(
                r"\d+:\d+", ref.server_epoch
            ):
                raise ValueError
            if not ref.socket_path.startswith("/") or any(
                ord(c) < 32 for c in ref.socket_path
            ):
                raise ValueError
            raw_forwards = value.get("forwards", [])
            if not isinstance(raw_forwards, list) or len(raw_forwards) > 8:
                raise ValueError
            forwards = tuple(ForwardRule(**rule) for rule in raw_forwards)
            if len({rule.local_port for rule in forwards}) != len(forwards):
                raise ValueError
            raw_reverse = value.get("reverse_forwards", [])
            if not isinstance(raw_reverse, list) or len(raw_reverse) > 8:
                raise ValueError
            reverse_forwards = tuple(ReverseForwardRule(**rule) for rule in raw_reverse)
            if len({rule.remote_port for rule in reverse_forwards}) != len(reverse_forwards):
                raise ValueError
            raw_listeners = value.get("listeners", [])
            if not isinstance(raw_listeners, list) or len(raw_listeners) > 8:
                raise ValueError
            listeners = tuple(ListenerRule(**rule) for rule in raw_listeners)
            if len({(rule.host, rule.port) for rule in listeners}) != len(listeners):
                raise ValueError
            return cls(
                alias,
                connection,
                ssh["password_prompt"],
                ssh["passphrase_prompt"],
                ref,
                credential_ref,
                forwards,
                history_binding,
                reverse_forwards,
                listeners,
            )
        except (KeyError, ValueError, TypeError, AttributeError, WorkspaceError) as exc:
            raise WorkspaceError(
                "Invalid saved workspace profile; existing file was preserved."
            ) from exc


class ProfileStore:
    def __init__(self):
        config = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        self.root = Path(
            os.environ.get(
                "PWNCAT_WORKSPACE_CONFIG", config / "pwncat-vl" / "workspaces"
            )
        )

    def _check(self, path, *, directory=False):
        attrs = path.lstat()
        if (
            (
                not stat.S_ISDIR(attrs.st_mode)
                if directory
                else not stat.S_ISREG(attrs.st_mode)
            )
            or (
                os.name != "nt"
                and (attrs.st_uid != os.getuid() or stat.S_IMODE(attrs.st_mode) & 0o077)
            )
            or getattr(attrs, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise WorkspaceError(
                "Saved workspace path must be owned by you and private: " + str(path)
            )
        return attrs

    def _path(self, alias):
        return self.root / (workspace_name(alias) + ".json")

    def history_path(self, alias):
        return self.root / (".history-" + workspace_name(alias) + ".json")

    def get(self, alias):
        path = self._path(alias)
        try:
            self._check(self.root, directory=True)
            attrs = self._check(path)
        except FileNotFoundError:
            return None
        if attrs.st_size > 16384:
            raise WorkspaceError("Saved workspace profile is oversized.")
        try:
            with path.open("rb") as stream:
                value = json.loads(stream.read(16385))
        except (ValueError, UnicodeError) as exc:
            raise WorkspaceError(
                "Invalid saved workspace profile; existing file was preserved."
            ) from exc
        return SavedWorkspace.parse(value, alias)

    def names(self):
        try:
            self._check(self.root, directory=True)
        except FileNotFoundError:
            return []
        return sorted(
            path.stem
            for path in self.root.glob("*.json")
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", path.stem)
        )

    @contextmanager
    def _lock(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._check(self.root, directory=True)
        path = self.root / ".lock"
        descriptor = os.open(
            path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        with os.fdopen(descriptor, "a+") as stream:
            self._check(path)
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream, fcntl.LOCK_EX)
                yield

    def save(self, saved, *, replace_identity=False):
        with self._lock():
            existing = self.get(saved.alias)
            if existing:
                existing.check_destination(saved.connection, saved.ref.name)
                if existing.ref != saved.ref and not replace_identity:
                    raise IdentityMismatch(
                        "Saved workspace identity changed; profile was not replaced."
                    )
                # Authentication updates must not erase another client's changes.
                # A newly created workspace gets no old forwarding definitions.
                saved = replace(
                    saved,
                    forwards=existing.forwards if existing.ref == saved.ref else (),
                    reverse_forwards=existing.reverse_forwards if existing.ref == saved.ref else (),
                    listeners=existing.listeners if existing.ref == saved.ref else (),
                    history_binding=(
                        existing.history_binding if existing.ref == saved.ref else None
                    ),
                )
            self._write(saved)

    def edit_hostname(self, alias, hostname):
        return self.edit_connection(alias, hostname=hostname)

    def edit_connection(
        self, alias, *, hostname=None, username=None, password_reader=None
    ):
        """Update a local destination; never connect or adopt a new remote identity."""
        if hostname is not None:
            hostname = normalize_hostname(hostname)
        if username is not None:
            username = validate_username(username)
        if hostname is None and username is None and password_reader is None:
            raise WorkspaceError(
                "Choose at least one of --host, --username, or --password."
            )
        with self._lock():
            saved = self.get(alias)
            if saved is None:
                raise WorkspaceError("No local workspace profile with that name.")
            connection = replace(
                saved.connection,
                host=hostname if hostname is not None else saved.connection.host,
                user=username if username is not None else saved.connection.user,
            )
            destination_changed = connection != saved.connection
            if not destination_changed and password_reader is None:
                return saved, False, False
            updated = replace(
                saved,
                connection=connection,
                password_prompt=True
                if password_reader is not None
                else saved.password_prompt,
                history_binding=saved.console_history_binding,
            )
            SavedWorkspace.parse(updated.document(), alias)
            old_vault = new_vault = None
            previous = Secrets()
            if saved.credential_ref:
                old_vault = CredentialStore(self.root, alias, saved.connection)
                previous = old_vault.read(saved.credential_ref)
            if old_vault or password_reader is not None:
                new_vault = CredentialStore(self.root, alias, connection)
                _ = new_vault.backend  # Check availability before asking for a secret.
                updated = replace(updated, credential_ref=new_vault.reference)
            secrets = previous
            if password_reader is not None:
                secrets = replace(previous, password=password_reader())
            # The OS vault and profile file cannot share a transaction. Keep the
            # previous secrets in memory until publication so failures can roll back.
            old_touched = False
            try:
                if new_vault:
                    old_touched = old_vault is not None and not destination_changed
                    new_vault.write(secrets)
                if old_vault and destination_changed:
                    old_touched = True
                    old_vault.delete(saved.credential_ref)
                self._write(updated)
            except BaseException as exc:
                try:
                    if old_touched:
                        old_vault.write(previous)
                    if new_vault and (destination_changed or old_vault is None):
                        new_vault.delete(new_vault.reference)
                except Exception:  # noqa: BLE001 - vault errors must never expose secrets
                    raise WorkspaceError(
                        "The edit failed and the credential store could not fully undo it. "
                        "Unlock the store and retry; saved credentials may need to be entered again."
                    ) from None
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise WorkspaceError(
                    "Workspace settings were not updated. Previous saved credentials were retained. "
                    "Check the profile directory and system credential store, then retry."
                ) from None
            return updated, True, bool(old_vault and destination_changed)

    def _write(self, saved):
        """Atomically publish a validated profile while holding _lock()."""
        document = saved.document()
        SavedWorkspace.parse(document, saved.alias)
        descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=self.root)
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(document, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path(saved.alias))
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def check_workspace(self, alias, connection, ref):
        saved = self.get(alias)
        if saved is None:
            raise WorkspaceError(
                "The local workspace profile was removed; local settings were not recreated."
            )
        saved.check_destination(connection, ref.name)
        if saved.ref != ref:
            raise IdentityMismatch(
                "Saved workspace identity changed; local settings were not used."
            )
        return saved

    def forward_rules(self, alias, connection, ref):
        return self.check_workspace(alias, connection, ref).forwards

    def remember_forward(self, alias, connection, ref, rule):
        with self._lock():
            saved = self.check_workspace(alias, connection, ref)
            rules = {item.local_port: item for item in saved.forwards}
            rules[rule.local_port] = rule
            if len(rules) > 8:
                raise WorkspaceError(
                    "At most eight forwards can be saved for a workspace."
                )
            self._write(
                replace(saved, forwards=tuple(rules[port] for port in sorted(rules)))
            )

    def forget_forward(self, alias, connection, ref, local_port):
        with self._lock():
            if self.get(alias) is None:
                return (
                    False  # The profile was forgotten; a live listener can still stop.
                )
            saved = self.check_workspace(alias, connection, ref)
            rules = tuple(
                rule for rule in saved.forwards if rule.local_port != local_port
            )
            if rules == saved.forwards:
                return False
            self._write(replace(saved, forwards=rules))
            return True

    def reverse_rules(self, alias, connection, ref):
        return self.check_workspace(alias, connection, ref).reverse_forwards

    def remember_reverse(self, alias, connection, ref, rule):
        with self._lock():
            saved = self.check_workspace(alias, connection, ref)
            rules = {item.remote_port: item for item in saved.reverse_forwards}
            rules[rule.remote_port] = rule
            if len(rules) > 8:
                raise WorkspaceError("At most eight reverse forwards can be saved per workspace.")
            self._write(replace(saved, reverse_forwards=tuple(rules[key] for key in sorted(rules))))

    def forget_reverse(self, alias, connection, ref, remote_port):
        with self._lock():
            if self.get(alias) is None:
                return False
            saved = self.check_workspace(alias, connection, ref)
            rules = tuple(rule for rule in saved.reverse_forwards if rule.remote_port != remote_port)
            if rules == saved.reverse_forwards:
                return False
            self._write(replace(saved, reverse_forwards=rules))
            return True

    def listener_rules(self, alias, connection, ref):
        return self.check_workspace(alias, connection, ref).listeners

    def remember_listener(self, alias, connection, ref, rule):
        with self._lock():
            saved = self.check_workspace(alias, connection, ref)
            rules = {(item.host, item.port): item for item in saved.listeners}
            rules[rule.host, rule.port] = rule
            if len(rules) > 8:
                raise WorkspaceError("At most eight listeners can be saved per workspace.")
            self._write(replace(saved, listeners=tuple(rules[key] for key in sorted(rules))))

    def forget_listener(self, alias, connection, ref, host, port):
        with self._lock():
            if self.get(alias) is None:
                return False
            saved = self.check_workspace(alias, connection, ref)
            rules = tuple(rule for rule in saved.listeners if (rule.host, rule.port) != (host, port))
            if rules == saved.listeners:
                return False
            self._write(replace(saved, listeners=rules))
            return True

    def forget(self, alias):
        with self._lock():
            if self.get(alias) is None:
                raise WorkspaceError("No local workspace profile with that name.")
            history = self.history_path(alias)
            try:
                self._check(history)
            except FileNotFoundError:
                pass
            else:
                history.unlink()
            self._path(alias).unlink()
