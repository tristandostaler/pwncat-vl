Persistent SSH workspace
========================

Workspace mode keeps interactive shells in a remote tmux server. Closing the
Mac terminal, losing connectivity, or exiting workspace mode detaches clients;
it does not send ``exit`` to the pane shells. This is an opt-in authenticated
SSH feature, independent of the existing pwncat Manager, Session and Platform
lifecycles.

Requirements
------------

* macOS, Linux/WSL, or a native Windows 10+ client with a real terminal for
  interactive attachment. Native Windows uses a separate virtual-terminal
  bridge (Windows Terminal recommended); legacy pwncat commands retain their
  existing platform requirements.
* An SSH account on a host with tmux 3.3+, Bash and SFTP. The SFTP namespace must
  expose the same home directory as SSH command execution. Atomic manifest
  replacement uses the OpenSSH SFTP ``posix-rename`` extension.
* A verified host key in ``~/.ssh/known_hosts`` or ``--known-hosts FILE``, or
  interactive confirmation of the host's fingerprint on first connection.
* A home directory owned by the SSH account and not writable by other accounts.
* Host policy must allow tmux to survive logout. Workspace mode does not alter
  system services or logout policy.

Use an actual hostname: this initial version does not expand SSH config aliases,
ProxyJump or ProxyCommand. Authentication supports an SSH agent, discoverable
keys, ``-i KEY``, ``--password`` and ``--passphrase``. Passwords and passphrases
are prompted for; they are not accepted in connection URLs. Optional saved
credentials use the native OS vault described below.

On first connection to an unknown host, workspace mode displays the hostname,
port (when nonstandard), key type and SHA-256 fingerprint. Compare the fingerprint
with a trusted source for that server, then type the full word ``yes`` to accept.
Any other answer, EOF or ``Ctrl+C`` cancels. The accepted public key is appended
to ``~/.ssh/known_hosts``, or to ``--known-hosts FILE`` when specified. Existing
entries and comments are preserved. Trust is saved before SSH authentication;
an incorrect login password does not undo an explicitly accepted host key.

Changed host keys are rejected without an acceptance prompt. Piped input cannot
approve an unknown key, and automatic reconnect never prompts for new trust.
If the key cannot be saved, the connection stops before authentication. To
automate connections, provision a verified known-hosts file first.

Start and reconnect
-------------------

.. code-block:: sh

    pwncat-vl workspace user@host new lab --history private
    pwncat-vl workspace user@host attach lab
    pwncat-vl workspace user@host list
    pwncat-vl workspace user@host panes lab
    pwncat-vl workspace user@host status lab
    pwncat-vl workspace user@host console lab

Connection options may be placed before or after the action:

.. code-block:: sh

    pwncat-vl workspace user@host -p 2222 -i ~/.ssh/id_ed25519 attach lab

``new`` creates a workspace only when its directory does not exist.
``--no-attach`` creates it without entering terminal mode. ``attach`` always
requires the original live server; it never recreates missing shells.

The workspace uses a separate tmux server and configuration at
``~/.pwncat-workspaces/NAME/``. Ordinary SSH/tmux can attach independently:

.. code-block:: sh

    tmux -S ~/.pwncat-workspaces/lab/tmux.sock attach -t workspace

That command is run on the workspace host. Closing an application client does
not require the application to remain running on the Mac.

Saved local names and authentication
-----------------------------------

A successful ``new``, ``attach``, ``console`` or other command that loads a live
workspace records its connection settings on the Mac. Subsequent commands can
use just its local name:

.. code-block:: sh

    pwncat-vl workspace user@host --password new lab
    pwncat-vl workspace attach lab
    pwncat-vl workspace console lab
    pwncat-vl workspace status lab
    pwncat-vl workspace list

The first command saves the host, username, port, selected key file, known-hosts
file, and whether to prompt for a password or key passphrase. By default, a saved
password authentication method still prompts for the password on each connection.
Passwords, passphrases and private key contents are never written to a profile.
SSH agent/key authentication remains available. ``--no-password`` and
``--no-passphrase`` override saved prompt preferences; successful live-workspace
connections save those preferences for later use.

For a workspace created before local profiles were introduced, connect once
using the full host form of ``attach`` or ``status`` to register its local name.
The host form also remains available after a Mac replacement; local profiles
are conveniences, not a prerequisite for remote tmux persistence.

``workspace list`` lists saved local connections without contacting a server.
It does not claim that those workspaces are currently running. The explicit
``workspace user@host list`` form checks workspaces on that remote host.

Use ``--alias`` when the same remote name occurs on multiple servers:

.. code-block:: sh

    pwncat-vl workspace user@host --password attach lab --alias worklab
    pwncat-vl workspace attach worklab
    pwncat-vl workspace forget worklab

``forget`` removes the local shortcut and its saved credentials, leaving the
remote workspace untouched. Local name collisions with another
server/account/port or remote workspace are rejected. Profiles pin the remote
workspace UUID, server epoch and socket path; a short attach refuses a replaced
server instead of silently adopting it. Only an explicit successful ``new``
updates that identity. After intentional out-of-band replacement, inspect it,
forget the old local profile, then register the replacement with a full-host
connection.

Profiles are stored under ``~/.config/pwncat-vl/workspaces/`` (relative to the
Windows user home on native Windows), with mode 0700 for the directory and 0600
for files on POSIX. Native Windows uses inherited filesystem ACLs in the user
profile directory. ``XDG_CONFIG_HOME`` changes the configuration
base; ``PWNCAT_WORKSPACE_CONFIG`` overrides the profile directory itself.
Writes are locked and atomic; symlinks/reparse points, invalid profiles, and unsafe
POSIX ownership/permissions are rejected. These files contain connection metadata and key paths,
so keep them private even though they contain no authentication secrets.

Changing a saved hostname
------------------------

If the same server has a new hostname or IP address, edit its local shortcut:

.. code-block:: sh

    pwncat-vl workspace edit lab --host new-host.example
    pwncat-vl workspace attach lab

``edit`` works offline on macOS, Linux/WSL and Windows. Supply a hostname, IPv4
address, or IPv6 address (optionally bracketed), without a username or port.
The saved username, port, key path, known-hosts path, remote workspace identity
and console history are retained. An already connected client keeps its current
connection; detach and attach again to use the new hostname.

Changing the hostname removes saved passwords and key passphrases from the OS
vault. Prompt preferences remain, so enter them again on the next connection;
add ``--save-credentials`` to save them for the new hostname. Editing to the same
hostname changes nothing and keeps saved credentials. If the vault cannot remove
the old credentials, the edit stops and the hostname remains unchanged. If the
subsequent profile write fails, credentials may already be removed; the error
explains this and the edit can be retried.

Host key verification still applies on the next connection. This command does
not create or adopt a workspace on a different server: attachment still requires
the saved workspace UUID, tmux server epoch and socket path to match.

Saving passwords and key passphrases
-----------------------------------

Opt in on a named workspace connection, including ``new``, ``attach``,
``console`` or ``status``:

.. code-block:: sh

    pwncat-vl workspace attach lab --save-credentials
    pwncat-vl workspace attach lab

Enter the password once when saving; later connections retrieve it from the
system vault. With no authentication method selected, ``--save-credentials``
selects password authentication. For an encrypted key, use ``-i KEY
--passphrase --save-credentials``. An SSH agent or an unencrypted key needs no
saved authentication secret.

Supported vaults are macOS Keychain, Windows Credential Manager, and Linux
Secret Service (for example GNOME Keyring) or KWallet. WSL uses a Linux service
inside WSL and does not read Windows Credential Manager. Linux/WSL needs a
running, configured user credential service and D-Bus session. KWallet's native
backend additionally requires ``dbus-python``; modern KDE can also expose Secret
Service. A headless system without a usable vault reports an error. No plaintext
or third-party file backend is selected as a fallback. The OS can still request
vault unlock or access approval.

Secrets are saved only after successful authentication and workspace validation.
The profile stores an opaque reference bound to the local name, connection,
configuration location and selected key path. Vault contents are never placed in
shell arguments, environment variables, profile JSON, or application logs.
The native service name is ``pwncat-vl.workspace.credentials.v1``.

To replace a saved password or remove saved secrets:

.. code-block:: sh

    pwncat-vl workspace attach lab --password --save-credentials
    pwncat-vl workspace forget-credentials lab

``--password`` explicitly asks for a new password, overriding the saved value
for that connection; ``--passphrase`` does the same for a key passphrase.
``forget-credentials`` retains the profile and returns it to prompting.
Credentials are not shared across separate local aliases or operating systems.
Forget saved credentials before changing the key path associated with a profile.

Failed authentication never writes to the vault. Interrupted saves may leave a
profile pointing to a missing vault entry; re-enter credentials with
``--password --save-credentials`` or use ``forget-credentials`` to recover.
If vault deletion fails, the profile remains so deletion can be retried.

Controls and pane context
-------------------------

Native tmux controls work: ``Ctrl+B`` then ``%`` splits side by side, ``"``
splits above/below, ``c`` creates a window, ``[`` enters copy mode, and ``d``
detaches. ``Ctrl+G`` then ``p`` opens the workspace console. ``Ctrl+G`` then ``d``
detaches locally. ``Ctrl+]`` is an alternative prefix. The letter shortcut is
easier on layouts such as French Canadian. Release Control before pressing the
letter; keeping Control held is also accepted. Press the chosen prefix twice
to send it literally to the remote application.

The console uses pwncat's yellow ``(local)`` and magenta name, a visible workspace
label, syntax highlighting, a status bar, and colored help/status/pane tables.
Tab completes commands and supported arguments, including ``help``, ``split``,
``forward`` and ``color`` choices. Up/Down recall commands, ``Ctrl+R`` searches
history, and history suggestions appear while typing. ``Ctrl+Q`` discards pending
input and resumes the selected remote pane; ``Ctrl+D`` at an empty prompt detaches.

Colors default to ``auto``, respecting ``NO_COLOR``, terminal capabilities and
redirected output. Use ``color on`` to explicitly enable colors, even with
``NO_COLOR`` set; ``color off`` disables them, and ``color auto`` restores automatic
selection. This preference survives returning to panes and automatic reconnects
in the same client invocation. A newly launched client starts in automatic mode.
``help`` lists available commands and ``help COMMAND`` shows their usage.
Successful console commands are saved locally per workspace and reloaded on the
next launch. The private file is ``.history-NAME.json`` beside the local workspace
profile: owner-only permissions on Unix, and the inherited per-user directory
ACL on Windows. History is plaintext, bounded to 500 entries and 256 KiB, and
bound to the workspace identity. Reusing an alias for a new workspace does not
reuse its old history. ``workspace forget NAME`` removes the local history too.

Password/passphrase prompts, unsupported commands and failed commands are not
recorded. Start a console command with a space to keep it out of saved history.
If history cannot be read or written, the console reports that and continues
in memory without discarding the existing file. ``--history private`` continues
to control remote Bash history separately; console history stays on this client.

Example console commands:

.. code-block:: text

    help
    color on
    status
    panes
    select %0
    split horizontal
    split %0 vertical
    window "files and logs"
    lcd ~/Downloads
    lpwd
    upload "local file.txt" /home/user/remote.txt
    download /home/user/remote.txt "local copy.txt"
    forward add 8080 8000
    forward list
    forward stop 8080
    resume
    detach

``select %ID`` selects a pane across windows. ``split`` without an ID splits
the selected pane; a successful split or new window selects the new pane.
``resume`` returns to the selected pane and its window. The prompt displays the
workspace and selected pane ID; ``panes`` marks it with ``*``. A pane that
disappears is not silently replaced: choose another using ``select``.
Entering the console from tmux follows tmux's current pane.

``status`` shows the SSH/file account, history policy, local transfer directory,
and selected pane's process ID and observed directory. ``lcd`` changes only the
local directory used for relative upload sources and download destinations.
It does not change any remote shell's directory. That local setting and console
history survive automatic reconnection during the same client invocation.

New panes start in the workspace account's home directory. Pane processes retain
their own directories, environments and jobs. Reported directories are metadata;
they are not used to guess the identity or filesystem inside a nested SSH,
container or user-switching shell. File operations require absolute remote paths
and always use the original workspace SSH account.

The local console temporarily replaces the display, while the remote panes keep
running. The display, tmux control protocol and SFTP each have their own SSH
channel. Existing pwncat upload/download/enumeration remain available through
ordinary pwncat sessions in a separate terminal. They are not routed into tmux
panes, automatically retried, or given the selected pane's credentials.
This workspace console has its own explicit command set; it does not expose the
legacy module runner. Unsupported commands produce an error and are never sent
to a shell. ``resume`` returns to the remote terminal for ordinary shell input.

An additional display is rejected unless ``attach NAME --takeover`` is used.
Takeover explicitly detaches existing clients. This is a single-user workflow,
not a distributed lock against simultaneous manual tmux attachments.

Local service forwarding
------------------------

Open the workspace console with ``Ctrl+G`` then ``p`` to start or stop a local
forward without disconnecting SSH or restarting panes:

.. code-block:: text

    forward add 8080 8000
    resume

This listens on ``127.0.0.1:8080`` on your computer and connects through the
existing authenticated SSH connection to ``127.0.0.1:8000`` on the SSH host.
To supply a destination address explicitly, use:

.. code-block:: text

    forward add LOCAL_PORT SERVER_IP REMOTE_PORT

For example, ``forward add 8080 192.0.2.20 80`` exposes the SSH server's website
at ``http://127.0.0.1:8080``, if that connection's SSH server IP is ``192.0.2.20``.
Replace that example address with the IP actually used by your SSH connection.
The destination must be a literal IPv4/IPv6 loopback address or that connected
SSH peer's IP. Hostnames, URLs, zone IDs and addresses of other machines are
rejected. The connected address is pinned to the existing SSH transport; no DNS
lookup is performed. Omit ``SERVER_IP`` to retain the original ``127.0.0.1``
destination. ``forward list`` shows each selected destination address and port.

The local listener always binds to IPv4 loopback. The SSH host is the original
workspace host, regardless of any nested connection in a pane. This command does
not provide SOCKS, reverse forwarding or public listeners.

The forward remains active while you use your panes or the workspace console.
Return to the console to run ``forward list`` or ``forward stop 8080``. A stop
also closes that forward's active clients. Forwards belong to the current local
client process; they close on detach, exit or SSH loss and are not restored
automatically after reconnect. They are not saved in workspace profiles or
remote tmux state. A separate ``workspace console`` process manages only the
forwards it started.

The service is contacted when a local application connects to the listening port.
A successful ``forward add`` confirms that the local listener is ready; it does
not prove the remote service is reachable. The SSH server must permit local TCP
forwarding. ``forward list`` includes the active connection count and last error.
At most eight forwards and sixteen clients per forward are allowed. Relay buffers
are bounded, traffic is not logged, and interrupted connections are never replayed.

History and privacy
-------------------

Default ``--history memory`` retains the live Bash history and tmux scrollback
across Mac disconnects without adding disk history recording. ``--history
private`` creates per-pane Bash history files, flushed at prompt boundaries.
Directories use mode 0700; files use 0600. These are plaintext files, not encrypted
archives. Existing Bash startup configuration is sourced before workspace
settings; custom user logging hooks and applications may record independently.

``--history-limit`` controls tmux scrollback and Bash in-memory history, default
50,000 lines, allowed range 100–200,000. Bash history files are bounded by its
``HISTFILESIZE`` behavior at shell exit; a long-running append-mode shell can
temporarily exceed that limit. No byte quota or automatic disk retention policy
is provided. Bash 3.2 uses atomic per-pane history snapshots to work around its
empty-history append behavior; newer Bash versions append new entries.

Raw keystrokes and terminal transcripts are not recorded by workspace code.
Clipboard forwarding and tmux passthrough are disabled in its isolated config.
Tmux scrollback remains in remote memory, is bounded, and disappears with the
server. Permission checks do not protect against the same SSH account or remote
root. History recording is not a complete or tamper-proof command audit trail.

Transfers
---------

.. code-block:: sh

    pwncat-vl workspace user@host upload lab ./report.txt /home/user/report.txt
    pwncat-vl workspace user@host download lab /home/user/report.txt ./copy.txt

Transfers stage data privately and verify a SHA-256 digest before publishing the
destination. Existing files require ``--overwrite``; symlink sources on the
remote host and symlink destinations are refused. Upload overwrite requires the
server's atomic rename extension. Download no-clobber publication requires local
hard-link support. No remove-then-rename fallback is used.

Interrupted transfers are not replayed or resumed. Cleanup is attempted; if the
connection is lost, a private ``.workspace-UUID`` staging directory may remain
beside the remote destination. Check it before removing it manually. Transfers
are of file contents only: directory recursion and metadata preservation are not
included. Concurrent modification checks cannot make the remote source an
atomic filesystem snapshot.

Recovery and shutdown
---------------------

Live display loss triggers bounded reconnection, default 60 seconds. Change it
with ``attach NAME --reconnect-seconds N``; zero disables automatic reconnection.
``Ctrl+C`` cancels reconnection. Host-key and authentication failures stop it.
The manifest UUID and the live server PID/start time must still match. Input
typed before disconnection is never replayed. Layout commands whose replies are
lost report an unknown outcome; inspect before repeating them.

If creation is interrupted after starting tmux, ``list`` may report an incomplete
manifest. Files and any live server are preserved. Use ordinary SSH/tmux to
inspect the socket before administrative cleanup; do not repeat ``new`` expecting
it to adopt or overwrite that state.

Remote reboot or tmux termination loses running processes and live scrollback.
This release does not restore layout after reboot or restart previous commands.
Saved private history files remain if the host's disk survives. Host destruction
requires an independent backup; workspace mode does not make one.

To deliberately terminate all workspace panes:

.. code-block:: sh

    pwncat-vl workspace user@host destroy lab --yes

History and metadata are retained, so the stopped workspace still reserves its
name. To preserve those files and reuse the name:

.. code-block:: sh

    pwncat-vl workspace user@host archive lab
    pwncat-vl workspace user@host new lab

``archive`` moves the entire stopped workspace directory into a private
``~/.pwncat-workspaces/.archives/lab-UUID/`` directory and prints its path. Saved
history and metadata remain there. The new workspace has a fresh identity and
shells; it does not rerun old commands or load archived history automatically.

Archiving refuses a reachable tmux server, a still-present recorded server PID,
or an inconclusive process check. It requires ``ps -p PID -o pid=`` support.
A reused PID, damaged metadata or an unexpected socket error needs manual inspection. Do not
modify the workspace concurrently through ordinary SSH/tmux while archiving.
An interrupted archive is never retried automatically; inspect the original
directory and ``.archives`` before repeating it. Ordinary detach never stops
or archives a workspace.

Testing
-------

``tests/test_workspace.py`` checks framing, no-replay behavior, identity,
permissions, file publication and terminal restoration. Integration tests start
a disposable loopback-only SSH/SFTP server with generated test keys and real
tmux in a temporary home; no user SSH server or external host is required.

.. code-block:: sh

    python -m pytest tests/test_workspace.py tests/test_workspace_integration.py

Install tmux 3.3+ or set ``PWNCAT_TEST_TMUX`` to its executable. Integration tests
skip when it is unavailable. CI sets ``PWNCAT_REQUIRE_TMUX=1`` so those tests
cannot silently skip. The fixture never modifies user known_hosts or SSH config.
