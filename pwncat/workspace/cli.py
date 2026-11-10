"""Opt-in workspace command. Does not construct a pwncat Manager or Session."""

from __future__ import annotations

import argparse
import getpass
import os
import random
import sys
import time
import warnings
from dataclasses import replace

from . import ConnectionLost, WorkspaceError
from .console import ConsoleState, WorkspaceConsole, print_panes, transfer
from .console_history import ConsoleHistory
from .credentials import CredentialStore, Secrets
from .hostkeys import confirm_host_key
from . import local_screen
from .model import safe_text, workspace_name
from .profiles import ProfileStore, SavedWorkspace
from .saved_forwards import SavedForwards, SavedListeners
from .ssh import SSHConnection, SSHProfile
from .terminal import display, terminal_size
from .tmux import TmuxWorkspace

ACTION_NAMES = {
    "list",
    "new",
    "attach",
    "console",
    "status",
    "panes",
    "split",
    "upload",
    "download",
    "destroy",
    "archive",
    "edit",
    "forget",
    "forget-credentials",
}


def connection_options(target, *, child=False):
    default = argparse.SUPPRESS if child else None
    target.add_argument("-p", "--port", type=int, default=default)
    target.add_argument("-i", "--identity", default=default)
    target.add_argument(
        "--known-hosts",
        help="Additional known_hosts file; accepted keys are saved here",
        default=default,
    )
    target.add_argument(
        "--alias", help="Local shortcut name (default: workspace name)", default=default
    )
    target.add_argument(
        "--password",
        action=argparse.BooleanOptionalAction,
        default=default,
        help="Prompt for an SSH password; remember this choice",
    )
    target.add_argument(
        "--passphrase",
        action=argparse.BooleanOptionalAction,
        default=default,
        help="Prompt for the private key passphrase; remember this choice",
    )
    target.add_argument(
        "--save-credentials",
        action="store_true",
        default=default,
        help="Save supplied passwords/passphrases in the native OS credential store",
    )


def uses_saved_name(argv):
    values = {"-p", "--port", "-i", "--identity", "--known-hosts", "--alias"}
    skip = False
    for word in argv:
        if skip:
            skip = False
        elif word in values:
            skip = True
        elif not word.startswith("-"):
            return word in ACTION_NAMES
    return False


def parser(*, saved_name=False):
    root = argparse.ArgumentParser(
        prog="pwncat-vl workspace",
        description="Persistent panes on an authenticated SSH host.",
        epilog="Saved shortcuts: pwncat-vl workspace attach NAME | workspace list | workspace edit NAME [--host HOST] [--username USER] [--password] | workspace forget NAME. "
        "A successful connection with an explicit host saves its connection settings locally.",
    )
    if saved_name:
        root.set_defaults(host=None)
    else:
        root.add_argument(
            "host",
            help="[ssh://]user@host[:port] (actual hostname; SSH aliases are not expanded)",
        )
    connection_options(root)
    actions = root.add_subparsers(dest="action", required=True)
    actions.add_parser(
        "list",
        help="List saved local names, or remote workspaces when a host is supplied",
    )
    new = actions.add_parser("new", help="Create and attach a workspace")
    new.add_argument("name")
    new.add_argument(
        "--history",
        choices=("memory", "private"),
        default="memory",
        help="private writes plaintext per-pane Bash history; default retains live history only",
    )
    new.add_argument("--history-limit", type=int, default=50000)
    new.add_argument("--no-attach", action="store_true")
    attach = actions.add_parser(
        "attach",
        help="Attach to a workspace; recover a saved workspace after a server reset",
    )
    attach.add_argument("name")
    attach.add_argument(
        "--takeover", action="store_true", help="Detach an existing display client"
    )
    attach.add_argument("--reconnect-seconds", type=int, default=60)
    console = actions.add_parser(
        "console", help="Open the local workspace command console"
    )
    console.add_argument("name")
    console.add_argument("--reconnect-seconds", type=int, default=60)
    status = actions.add_parser(
        "status", help="Show workspace, SSH account, and pane context"
    )
    status.add_argument("name")
    panes = actions.add_parser(
        "panes", help="Inspect pane IDs and observed directories"
    )
    panes.add_argument("name")
    split = actions.add_parser("split", help="Split a pane without attaching")
    split.add_argument("name")
    split.add_argument("pane")
    split.add_argument(
        "--direction", choices=("horizontal", "vertical"), default="horizontal"
    )
    for action in ("upload", "download"):
        transfer = actions.add_parser(
            action, help=f"{action.capitalize()} using the SSH account's SFTP"
        )
        transfer.add_argument("name")
        transfer.add_argument("source")
        transfer.add_argument("destination")
        transfer.add_argument("--overwrite", action="store_true")
    destroy = actions.add_parser(
        "destroy", help="Terminate workspace processes; retain history files"
    )
    destroy.add_argument("name")
    destroy.add_argument(
        "--yes", action="store_true", help="Confirm termination of every workspace pane"
    )
    archive = actions.add_parser(
        "archive", help="Preserve a stopped workspace's files and free its name"
    )
    archive.add_argument("name")
    edit = actions.add_parser(
        "edit",
        help="Change a saved workspace's host, username, or saved password locally",
    )
    edit.add_argument("name", help="Saved local workspace name")
    edit.add_argument(
        "--host",
        dest="new_hostname",
        help="New hostname or IP address; retain the SSH username and port",
    )
    edit.add_argument(
        "--username", "--user", dest="new_username", help="New SSH username"
    )
    edit.add_argument(
        "--password",
        dest="edit_password",
        action="store_true",
        help="Privately prompt for a replacement password and save it in the OS credential store",
    )
    forget = actions.add_parser(
        "forget", help="Remove a local shortcut; leave the remote workspace intact"
    )
    forget.add_argument("name")
    forget_credentials = actions.add_parser(
        "forget-credentials",
        help="Delete saved secrets; retain the local connection profile",
    )
    forget_credentials.add_argument("name")
    for action in actions.choices.values():
        if action is not edit:
            connection_options(action, child=True)
    return root


def resolve_connection(args, store):
    alias = workspace_name(args.alias or args.name)
    source = None
    if args.host is None:
        source = store.get(args.name)
        if source is None:
            raise WorkspaceError(
                f"No saved workspace named '{args.name}'. Connect once with an explicit host: "
                "pwncat-vl workspace USER@HOST --password attach NAME"
            )
        base = source.connection
        remote_name = source.ref.name
        overrides = {
            key: getattr(args, key)
            for key in ("port", "identity", "known_hosts")
            if getattr(args, key) is not None
        }
        base = replace(base, **overrides)
        if not 1 <= base.port <= 65535:
            raise WorkspaceError("Port must be between 1 and 65535.")
    else:
        remote_name = workspace_name(args.name)
        base = SSHProfile.parse(
            args.host,
            port=args.port,
            identity=args.identity,
            known_hosts=args.known_hosts,
        )
    base = replace(
        base,
        **{
            key: os.path.abspath(os.path.expanduser(getattr(base, key)))
            for key in ("identity", "known_hosts")
            if getattr(base, key) is not None
        },
    )
    saved = store.get(alias)
    if saved:
        saved.check_destination(base, remote_name)
    seed = source or saved
    if seed:
        base = replace(
            base,
            **{
                key: getattr(seed.connection, key)
                for key in ("identity", "known_hosts")
                if getattr(args, key) is None
            },
        )
    password_prompt = (
        args.password
        if args.password is not None
        else bool(seed and seed.password_prompt)
    )
    passphrase_prompt = (
        args.passphrase
        if args.passphrase is not None
        else bool(seed and seed.passphrase_prompt)
    )
    expected = (
        (source or saved).ref if (source or saved) and args.action != "new" else None
    )
    return alias, remote_name, base, password_prompt, passphrase_prompt, expected


def authenticate_profile(args, store, alias, base, password_prompt, passphrase_prompt):
    seed = store.get(args.name if args.host is None else alias) if alias else None
    cached = Secrets()
    reference = seed.credential_ref if seed and seed.alias == alias else None
    if reference:
        CredentialStore(store.root, alias, base).check_reference(reference)
    if args.save_credentials and not password_prompt and not passphrase_prompt:
        if base.identity or args.password is False:
            raise WorkspaceError(
                "Use --password or --passphrase with --save-credentials. SSH agent/key paths already work without storing a secret."
            )
        password_prompt = True
    vault = CredentialStore(store.root, alias, base) if args.save_credentials else None
    if vault:
        _ = vault.backend  # Check availability before prompting or connecting.
        reference = vault.reference
    if (
        seed
        and seed.credential_ref
        and (
            (password_prompt and args.password is not True)
            or (passphrase_prompt and args.passphrase is not True)
        )
    ):
        cached = CredentialStore(store.root, seed.alias, base).read(seed.credential_ref)
    profile = replace(
        base,
        password=(
            getpass.getpass("SSH password: ")
            if args.password is True or cached.password is None
            else cached.password
        )
        if password_prompt
        else None,
        passphrase=(
            getpass.getpass("Key passphrase: ")
            if args.passphrase is True or cached.passphrase is None
            else cached.passphrase
        )
        if passphrase_prompt
        else None,
    )
    return profile, password_prompt, passphrase_prompt, reference, vault


def remember_connection(
    store,
    alias,
    base,
    ref,
    profile,
    password_prompt,
    passphrase_prompt,
    reference,
    vault,
    *,
    replace_identity=False,
):
    # Reserve the vault reference first: interrupted saves can still be forgotten.
    store.save(
        SavedWorkspace(alias, base, password_prompt, passphrase_prompt, ref, reference),
        replace_identity=replace_identity,
    )
    if vault:
        vault.write(Secrets(profile.password, profile.passphrase))
        print("Credentials saved in the system credential store.")


def forget_credentials(store, alias):
    saved = store.get(alias)
    if saved is None:
        raise WorkspaceError("No local workspace profile with that name.")
    if saved.credential_ref:
        CredentialStore(store.root, alias, saved.connection).delete(
            saved.credential_ref
        )
        store.save(replace(saved, credential_ref=None))


def read_replacement_password():
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("New SSH password: ")
            confirmation = getpass.getpass("Confirm SSH password: ")
    except getpass.GetPassWarning:
        raise WorkspaceError(
            "Run the password edit in a terminal with hidden input."
        ) from None
    if not password:
        raise WorkspaceError("Password was empty; saved settings were not changed.")
    if password != confirmation:
        raise WorkspaceError(
            "Passwords did not match; saved settings were not changed."
        )
    return password


def list_saved(store):
    names = store.names()
    if not names:
        print(
            "No locally saved workspaces. Connect once using a host and workspace name."
        )
    for name in names:
        saved = store.get(name)
        profile = saved.connection
        method = (
            ("saved password" if saved.credential_ref else "password prompt")
            if saved.password_prompt
            else (
                "key " + profile.identity
                if profile.identity
                else "SSH agent/default keys"
            )
        )
        if saved.passphrase_prompt:
            method += (
                "; saved key passphrase"
                if saved.credential_ref
                else "; key passphrase prompt"
            )
        print(
            safe_text(
                f"{name}  {profile.user}@{profile.host}:{profile.port}  remote={saved.ref.name}  {method}"
            )
        )
    if names:
        print("Saved connection settings; remote running status has not been checked.")


def interact(
    backend,
    profile,
    *,
    takeover=False,
    reconnect_seconds=60,
    start_console=False,
    forward_settings=None,
    listener_settings=None,
    console_history=None,
):
    expected = backend.ref
    state = ConsoleState(
        forward_settings=forward_settings, listener_settings=listener_settings,
        history_store=console_history
    )
    restore_pending = forward_settings is not None or listener_settings is not None
    mode = "console" if start_console else "display"
    workspace_console = WorkspaceConsole(backend, state)
    print(
        "Ctrl+B: tmux controls. Ctrl+G then p: workspace console. Ctrl+G then d: detach. Ctrl+] also works."
    )
    try:
        while True:
            try:
                if restore_pending:
                    if listener_settings is not None:
                        try:
                            if listener_settings.rules():
                                for message in listener_settings.restore(workspace_console.prepare_manager()):
                                    print(safe_text(message))
                        except (WorkspaceError, OSError) as exc:
                            print("Saved listeners could not be restored: " + safe_text(exc))
                    if isinstance(forward_settings, SavedForwards):
                        try:
                            for message in forward_settings.restore_reverse(
                                backend.connection.reverse_forwards()
                            ):
                                print(safe_text(message))
                        except (WorkspaceError, OSError) as exc:
                            print("Saved reverse forwards could not be restored: " + safe_text(exc))
                    if forward_settings is not None:
                        try:
                            for message in forward_settings.restore(
                                backend.connection.local_forwards()
                            ):
                                print(safe_text(message))
                        except (WorkspaceError, OSError) as exc:
                            print("Saved forwards could not be restored: " + safe_text(exc))
                    restore_pending = False
                if mode == "console":
                    action = workspace_console.run()
                    if action == "park":
                        try:
                            local_screen.park()
                        except WorkspaceError as exc:
                            print("Could not preserve the local terminal: " + safe_text(exc))
                        continue
                    if action == "detach":
                        return
                    if action == "busy":
                        continue
                    mode = "display"
                else:
                    channel = backend.display(terminal_size(), takeover=takeover)
                    takeover = False
                    if display(channel, backend.connection) == "detach":
                        if local_screen.managed():
                            try:
                                local_screen.park()
                            except WorkspaceError as exc:
                                print("Could not preserve the local terminal: " + safe_text(exc))
                            continue
                        if workspace_console.transfers.active() or workspace_console.modules.active():
                            print("A background transfer or module is still running; wait for it before leaving this client.")
                            mode = "console"
                            continue
                        return
                    mode = "console"
            except ConnectionLost:
                workspace_console.close()
                backend.close()
                backend.connection.close()
                deadline = time.monotonic() + reconnect_seconds
                delay = 1.0
                while True:
                    if time.monotonic() >= deadline:
                        raise ConnectionLost(
                            "Reconnect limit reached. Attach again when connectivity returns."
                        )
                    print(
                        "Connection lost; reconnecting to the same workspace. Ctrl+C cancels."
                    )
                    time.sleep(
                        min(
                            delay + random.random() / 4,
                            max(0, deadline - time.monotonic()),
                        )
                    )
                    connection = SSHConnection(profile)
                    try:
                        connection.connect()
                        replacement = TmuxWorkspace(connection)
                        replacement.load(expected.name, expected=expected)
                        backend = replacement
                        workspace_console = WorkspaceConsole(backend, state)
                        restore_pending = forward_settings is not None or listener_settings is not None
                        break
                    except ConnectionLost:
                        connection.close()
                        delay = min(delay * 2, 15)
                    except BaseException:
                        connection.close()
                        raise
    finally:
        try:
            workspace_console.close()
        finally:
            backend.close()
            backend.connection.close()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = parser(saved_name=uses_saved_name(argv)).parse_args(argv)
    if args.action == "destroy" and not args.yes:
        print(
            "Destroy terminates every workspace pane. Add --yes to confirm.",
            file=sys.stderr,
        )
        return 2
    if getattr(args, "reconnect_seconds", 60) < 0:
        print("--reconnect-seconds cannot be negative.", file=sys.stderr)
        return 2
    connection = backend = None
    try:
        store = ProfileStore()
        if args.action in ("new", "attach", "console") and not getattr(args, "no_attach", False) and local_screen.available():
            alias, remote_name, base, _password, _passphrase, _expected = resolve_connection(args, store)
            return local_screen.attach_or_start(
                argv, alias, base, remote_name,
                takeover=getattr(args, "takeover", False), new=args.action == "new",
            )
        if args.action == "edit":
            if any(
                getattr(args, option) is not None
                for option in (
                    "host",
                    "port",
                    "identity",
                    "known_hosts",
                    "alias",
                    "password",
                    "passphrase",
                    "save_credentials",
                )
            ):
                raise WorkspaceError(
                    "Use 'workspace edit NAME [--host HOST] [--username USER] [--password]' "
                    "without connection options. This command only edits saved local settings."
                )
            saved, changed, migrated = store.edit_connection(
                args.name,
                hostname=args.new_hostname,
                username=args.new_username,
                password_reader=read_replacement_password
                if args.edit_password
                else None,
            )
            if not changed:
                print("Saved connection settings are unchanged.")
                return 0
            if args.new_hostname is not None:
                print(
                    f"Saved hostname for '{saved.alias}': {safe_text(saved.connection.host)}"
                )
            if args.new_username is not None:
                print(
                    f"Saved username for '{saved.alias}': {safe_text(saved.connection.user)}"
                )
            if args.edit_password:
                print(
                    "Password saved in the system credential store; it will be used on the next connection."
                )
            if migrated:
                print(
                    "Saved credentials were retained for the updated connection settings."
                )
            print("Workspace identity and console history were retained.")
            print(f"Reconnect with: pwncat-vl workspace attach {saved.alias}")
            return 0
        if args.save_credentials and (
            args.action in ("list", "forget", "forget-credentials")
        ):
            raise WorkspaceError(
                "Use --save-credentials with a named workspace connection, such as attach, new, console or status."
            )
        if args.action == "forget-credentials":
            forget_credentials(store, args.name)
            print("Saved credentials removed. The connection profile was retained.")
            return 0
        if args.action == "forget":
            forget_credentials(store, args.name)
            store.forget(args.name)
            print("Local shortcut removed. The remote workspace was not changed.")
            return 0
        if args.action == "list" and args.host is None:
            list_saved(store)
            return 0
        if args.action == "list":
            alias = remote_name = expected = None
            base = SSHProfile.parse(
                args.host,
                port=args.port,
                identity=args.identity,
                known_hosts=args.known_hosts,
            )
            password_prompt, passphrase_prompt = (
                bool(args.password),
                bool(args.passphrase),
            )
        else:
            alias, remote_name, base, password_prompt, passphrase_prompt, expected = (
                resolve_connection(args, store)
            )
        profile, password_prompt, passphrase_prompt, reference, vault = (
            authenticate_profile(
                args, store, alias, base, password_prompt, passphrase_prompt
            )
        )
        connection = SSHConnection(profile, confirm_host_key=confirm_host_key).connect()
        backend = TmuxWorkspace(connection)
        if args.action == "list":
            for name in backend.store.names():
                try:
                    backend.load(name)
                    print(name + "  running")
                except (WorkspaceError, OSError) as exc:
                    print(name + "  unavailable: " + safe_text(exc))
            return 0
        if args.action == "new":
            backend.create(
                remote_name, history=args.history, history_limit=args.history_limit
            )
            try:
                remember_connection(
                    store,
                    alias,
                    base,
                    backend.ref,
                    profile,
                    password_prompt,
                    passphrase_prompt,
                    reference,
                    vault,
                    replace_identity=True,
                )
            except (WorkspaceError, OSError) as exc:
                raise WorkspaceError(
                    "Remote workspace was created, but saving its local settings or credentials failed: "
                    + str(exc)
                ) from exc
            print(
                f"Saved local workspace '{alias}'. Reconnect with: pwncat-vl workspace attach {alias}"
            )
            if not args.no_attach:
                interact(
                    backend,
                    profile,
                    forward_settings=SavedForwards(store, alias, base, backend.ref),
                    listener_settings=SavedListeners(store, alias, base, backend.ref),
                    console_history=ConsoleHistory(store, alias, base, backend.ref),
                )
        elif args.action == "archive":
            if vault:
                from .model import WorkspaceRef

                manifest = backend.store.load(remote_name)
                import posixpath

                archived_ref = WorkspaceRef(
                    remote_name,
                    manifest["uuid"],
                    manifest["server_epoch"],
                    posixpath.join(backend.store.directory(remote_name), "tmux.sock"),
                )
            destination = backend.archive(remote_name, expected=expected)
            print("Saved workspace files archived at " + safe_text(destination))
            if vault:
                remember_connection(
                    store,
                    alias,
                    base,
                    archived_ref,
                    profile,
                    password_prompt,
                    passphrase_prompt,
                    reference,
                    vault,
                )
            print(f"Name '{remote_name}' is available for a new workspace.")
        else:
            recovered = False
            if args.action in ("attach", "console") and expected is not None:
                recovered = backend.attach_or_recover(remote_name, expected)
            else:
                backend.load(remote_name, expected=expected)
            remember_connection(
                store,
                alias,
                base,
                backend.ref,
                profile,
                password_prompt,
                passphrase_prompt,
                reference,
                vault,
                replace_identity=recovered,
            )
            if recovered:
                print(
                    "The previous remote workspace was gone or stopped. Started a fresh workspace; any surviving files were archived."
                )
            if args.host is not None and args.action in ("attach", "console"):
                print(f"Saved local workspace '{alias}'.")
            if args.action == "attach":
                interact(
                    backend,
                    profile,
                    takeover=args.takeover,
                    reconnect_seconds=args.reconnect_seconds,
                    forward_settings=SavedForwards(store, alias, base, backend.ref),
                    listener_settings=SavedListeners(store, alias, base, backend.ref),
                    console_history=ConsoleHistory(store, alias, base, backend.ref),
                )
            elif args.action == "console":
                interact(
                    backend,
                    profile,
                    reconnect_seconds=args.reconnect_seconds,
                    start_console=True,
                    forward_settings=SavedForwards(store, alias, base, backend.ref),
                    listener_settings=SavedListeners(store, alias, base, backend.ref),
                    console_history=ConsoleHistory(store, alias, base, backend.ref),
                )
            elif args.action == "status":
                WorkspaceConsole(backend).status()
            elif args.action == "panes":
                print_panes(backend)
            elif args.action == "split":
                print(
                    safe_text(
                        b" ".join(backend.split(args.pane, args.direction)).decode()
                    )
                )
            elif args.action in ("upload", "download"):
                transfer(
                    backend, args.action, args.source, args.destination, args.overwrite
                )
            elif args.action == "destroy":
                backend.destroy()
                print(
                    "Workspace stopped. Saved files were retained. "
                    f"Use 'archive {alias}' to free its name."
                )
        return 0
    except KeyboardInterrupt:
        print("\nDetached/cancelled. No operation will be replayed.", file=sys.stderr)
        return 130
    except (WorkspaceError, OSError, ValueError, EOFError) as exc:
        print("Workspace error: " + safe_text(exc), file=sys.stderr)
        return 1
    finally:
        if backend:
            backend.close()
        if connection:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())
