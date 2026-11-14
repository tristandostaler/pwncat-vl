# Repository guidance for agents

## Workspace behavior

- Treat the workspace CLI, console, local Screen client, and pwncat session manager as separate lifecycle owners. Keep `workspace ... --help` usable without importing `pwncat.manager` or `pwncat.util`; load the console only after argument parsing or when entering an interactive workspace.
- Preserve native terminal text selection in the managed console. Do not enable prompt_toolkit mouse reporting just to handle scrollback; test selection and Screen/tmux history behavior independently.
- A nonblocking Paramiko send may raise `socket.timeout` when the SSH window is full. Retry the same unsent bytes, respect short writes, and treat a closed channel as a disconnect. Test these cases without a network connection.
- Validate a forward command's shape and ports before asking the backend for a forwarding manager or opening a listener. Local forward destinations are literal loopback IPs or the IP pinned to the current SSH transport. Apply the same rule to saved-forward restoration. If that policy changes deliberately, update implementation, tests, and user documentation together.
- Keep background transfer and module ownership explicit. A session running background work must remain unavailable for conflicting interactive operations, and detach must not discard live work.
- After replacing a workspace execution path, search for callers of the old path and remove an unused parallel implementation. The interactive console has one owner in `workspace/console.py`.

## Local modules

- A module name in `sys.modules` does not prove that it came from the requested directory. Compare the cached module's source with the requested import specification before reusing it. Restore the prior cache entry if loading a replacement fails.
- Creating one module should load that module and its parent packages only. Do not replace unrelated live module instances or the selected module context.
- Exercise module creation, deletion, and reload with duplicate names in different directories and with malformed source. Preserve the prior loaded instance when an edited module fails to compile.
- A malformed user module must not prevent the manager from starting. Skip and report only that local module during startup, retain the source for repair or deletion, and keep explicit loads strict so their failures are visible to the caller.
- Keep file creation and deletion inside the local user module directory, reject symlinked module paths, and never overwrite an existing module file.
- Recently edited user-local modules can live outside this checkout. Include them when the review scope calls for them, keep endpoints and credentials out of reports, and check idempotent recovery paths with mocks. A marked tmux pane may be dead and need respawning before its command can be restarted.

## Verification

- Run the full test suite in a project environment with dependencies (`python -m pytest -q`) after changing workspace or module loading behavior. Report skipped integration tests separately; real tmux tests need tmux and explicit test setup.
- Run focused tests for changed paths, `git diff --check`, and a Python lint pass for undefined names and unused imports. Fix stale fixtures when an interface changes; use explicit fixture collaborators so an unconfigured `Mock` cannot accidentally act truthy or return a fake byte count.
- Keep history-only tests focused on history loading, and test console bootstrap and connection loss in their own lifecycle tests. Do not make a history test depend on a real shell channel.
