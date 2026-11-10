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
``--no-attach`` creates it without entering terminal mode. ``attach`` and
``console`` reuse a running workspace. For a saved local shortcut, if a server
reset removed its remote directory, they create a fresh workspace and update
the saved identity. If its metadata survives but tmux has stopped, they first
verify that the recorded server and process have stopped, archive the surviving
files, then create a fresh workspace with the previous history policy.
Processes and shell variables lost during a reset cannot be restored.

Recovery does not replace a running workspace with a different identity, or
overwrite corrupt/incomplete metadata. Permission errors and uncertain server
state stop recovery. SSH authentication and host key verification still apply.
Other commands, and reconnect attempts within an already open client, continue
to require the original live workspace.

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

Changing saved connection settings
---------------------------------

Edit the host, SSH username, or saved password of a local shortcut:

.. code-block:: sh

    pwncat-vl workspace edit lab --host new-host.example
    pwncat-vl workspace edit lab --username newuser
    pwncat-vl workspace edit lab --password
    pwncat-vl workspace edit lab --host new-host.example --username newuser --password
    pwncat-vl workspace attach lab

``edit`` works offline on macOS, Linux/WSL and Windows. For ``--host``, supply a
hostname, IPv4 address, or IPv6 address (optionally bracketed), without a username
or port. ``--username`` (also ``--user``) takes a literal SSH account name,
including domain-qualified names. The options can be used separately or together.
Unspecified settings, the port, key path, known-hosts path, saved forwards,
remote workspace identity, and local console history are retained.

Changing the host or username keeps saved passwords and key passphrases by
moving them to the credential-store entry for the updated connection. Editing
to the same host and username does not access the vault. ``--password`` prompts
privately for the new password and confirmation, then saves it in the OS vault;
it preserves any saved key passphrase. No password is accepted as an argument
or written to the profile file. This updates the locally saved login password,
not the account password on the server, and does not test authentication.

Cancelling the prompt or entering mismatched passwords leaves the profile and
credentials unchanged. If publication fails, the previous credentials are
restored; if the vault also prevents rollback, the error reports the incomplete
recovery. An already connected client keeps its current connection; detach and
attach again to use the edited settings. Host key verification still applies.

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

Connection commands save secrets only after successful authentication and
workspace validation. The explicit offline ``edit --password`` command saves
the replacement without connecting or validating it against the server.
The profile stores an opaque reference bound to the local name, connection,
configuration location and selected key path. Vault contents are never placed in
shell arguments, environment variables, profile JSON, or application logs.
The native service name is ``pwncat-vl.workspace.credentials.v1``.

To replace a saved password or remove saved secrets:

.. code-block:: sh

    pwncat-vl workspace attach lab --password --save-credentials
    pwncat-vl workspace edit lab --password
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
history, and history suggestions appear while typing. With a local ``screen``
session, ``Ctrl+Q`` parks the live console and ``workspace attach NAME`` returns
to the same pwncat sessions and selected session. ``resume`` returns to the
selected remote pane. The explicit ``detach`` command closes the local pwncat
sessions. Without local ``screen``, ``Ctrl+Q`` closes the local client.

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

``resume`` keeps the console's sessions, active session selection,
and aliases in memory while you use tmux. Press ``Ctrl+G`` then ``p`` to return
to that same console. On macOS or other systems with local ``screen``, the
interactive ``new``, ``attach`` and ``console`` actions run inside a private
local screen session. ``Ctrl+Q`` in the console or ``Ctrl+G`` then ``d`` in the
pane detaches the terminal while the client, SSH connection, listeners and
pwncat sessions keep running. A later ``workspace attach NAME`` reconnects to
that local client without creating another pwncat shell. The explicit
``detach`` command or SSH loss closes local console sessions. The remote tmux
panes retain their separate lifetime. Set ``PWNCAT_WORKSPACE_SCREEN_DISABLE=1``
to use the previous process lifetime.

``status`` shows the SSH/file account, history policy, local transfer directory,
and selected pane's process ID and observed directory. ``lcd`` changes only the
local directory used for relative upload sources and download destinations.
It does not change any remote shell's directory. That local setting and console
history survive automatic reconnection during the same client invocation.

Inside the pwncat console, ``sessions ID`` selects the active pwncat session.
``upload`` writes to that session's host, and ``download`` reads from it. The
workspace SSH session uses SFTP; other sessions use their platform file
operations. ``select %ID`` selects a tmux pane and does not change the file
transfer target. If no pwncat session is active, transfers stop with an error.

Add ``--background`` (or ``-b``) to ``upload`` or ``download`` to keep the
console responsive. Foreground transfers show a progress bar. The console
toolbar shows byte count, percent and phase for a background transfer; the
``transfers`` command shows the same progress or its final result. The copy
can reach 100% while verification and publication are still in progress.
Only one background transfer runs at a time. The final result includes the
verified size and SHA-256 on success. The workspace SSH session uses a separate SFTP channel,
so its shell remains usable. For another pwncat session, the transfer uses that
session's command channel; the console switches to the workspace session while
it runs. The transferring session cannot be selected or closed until the
transfer finishes. ``resume`` can still be used while it runs, and Ctrl+Q
parks a screen-managed client. Closing the client is refused until the
transfer finishes.

New panes start in the workspace account's home directory. Pane processes retain
their own directories, environments and jobs. Reported directories are metadata;
they are not used to guess the identity or filesystem inside a nested SSH,
container or user-switching shell. Workspace SSH file operations require
absolute remote paths. A selected pwncat session can use a path relative to
its own working directory.

The local console temporarily replaces the display, while the remote panes keep
running. The display, tmux control protocol and SFTP each have their own SSH
channel. Transfers into another pwncat session use that session's file access;
tmux panes are not treated as pwncat sessions or given the selected pane's
credentials.
The console includes normal pwncat commands and modules alongside workspace
commands. ``resume`` returns to the remote terminal for ordinary shell input.

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
workspace host, regardless of any nested connection in a pane. Local forwarding
does not provide SOCKS or public listeners.

The forward remains active while you use your panes or the workspace console.
Return to the console to run ``forward`` (or ``forward list``) for one view of
local and reverse forwards, or ``forward stop 8080``. A stop
also closes that forward's active clients. Forwards belong to the current local
client process; they close on detach, exit or SSH loss. Their settings are
saved in the local workspace profile and restored on attach or reconnect.
``forward stop`` removes the saved setting. A separate ``workspace console``
process manages only the live forwards it started.

The service is contacted when a local application connects to the listening port.
A successful ``forward add`` confirms that the local listener is ready; it does
not prove the remote service is reachable. The SSH server must permit local TCP
forwarding. ``forward list`` includes the active connection count and last error.
At most eight forwards and sixteen clients per forward are allowed. Relay buffers
are bounded, traffic is not logged, and interrupted connections are never replayed.

Reverse forwarding
------------------

To expose a local pwncat listener through the existing SSH connection, open
the workspace console and run:

.. code-block:: text

    listen -m linux -H 127.0.0.1 4444
    forward reverse add 4444 4444
    forward reverse list

This requests a listener on the SSH host's ``127.0.0.1:4444``. A connection to
that remote port is relayed to your computer's ``127.0.0.1:4444``. For another
host to reach the SSH host's listener, explicitly request an external bind:

.. code-block:: text

    forward reverse add 4444 4444 0.0.0.0

The SSH server must allow remote TCP forwarding and external binds
(``GatewayPorts`` in OpenSSH). It may refuse the request or restrict the actual
bind address; the SSH protocol does not report the effective address. Use
``forward reverse stop 4444`` to close the remote listener and its active
connections. No program or separate listener is needed on the SSH host.

Reverse forwards are limited to one per SSH connection and sixteen clients per
forward. They use bounded relay buffers and do not log traffic. Their settings
are saved with the local workspace profile and restored on attach or reconnect.
The live connection ends on detach, SSH loss or process exit. If restoration
fails, the saved setting remains and ``forward reverse list`` shows the error.
``forward reverse stop`` removes both the live forward and its saved setting.
The destination on your computer is always IPv4 loopback; start the local
listener first. A successful ``forward reverse add`` confirms the SSH server
accepted the listener request, not that the local destination is reachable.
If an old ``forward add 4444 4444`` still occupies local port 4444, run
``forward stop 4444`` before starting the pwncat listener.

Listeners created with ``listen`` inside a workspace console are saved in the
local workspace profile and restored on attach before reverse forwards. They
remain active while you move between the console and panes. ``listeners -k ID``
stops a listener and removes its saved setting. A failed restore leaves the
setting in place for the next attach. A separate pwncat process does not share
these live listeners. Incoming sessions are not restored after a restart.

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
