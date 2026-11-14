# Repository guidance for agents

## Workspace behavior

- Treat the workspace CLI, console, local Screen client, and pwncat session manager as separate lifecycle owners. Keep `workspace ... --help` usable without importing `pwncat.manager` or `pwncat.util`; load the console only after argument parsing or when entering an interactive workspace.
- Preserve native terminal text selection in the managed console. Do not enable prompt_toolkit mouse reporting just to handle scrollback; test selection and Screen/tmux history behavior independently.
- A nonblocking Paramiko send may raise `socket.timeout` when the SSH window is full. Retry the same unsent bytes within a bounded no-progress period, respect short writes, and stop if the channel closes, sends EOF, or loses its transport. Test these cases without a network connection.
- Validate a forward command's shape, ports, and literal destination IP before opening a listener. Destinations may include internal addresses reachable from the SSH host; this is required by Pwnbox bootstrap and other pivot workflows. Keep the local listener bound to loopback and save the destination for restoration under the same workspace identity. Update implementation, tests, and user documentation together when forwarding behavior changes.
- Before restoring a restriction because tests or documentation expect it, inspect active callers and user-local modules. Older tests and prose can describe an obsolete policy; preserve working workflows and then align the tests and documentation.
- Keep background transfer and module ownership explicit. A session running background work must remain unavailable for conflicting interactive operations, and detach must not discard live work.
- After replacing a workspace execution path, search for callers of the old path and remove an unused parallel implementation. The interactive console has one owner in `workspace/console.py`.

## Local modules

- A module name in `sys.modules` does not prove that it came from the requested directory. Compare the cached module's source with the requested import specification before reusing it. Restore the prior cache entry if loading a replacement fails.
- Creating one module should load that module and its parent packages only. Do not replace unrelated live module instances or the selected module context.
- Exercise module creation, deletion, and reload with duplicate names in different directories and with malformed source. Preserve the prior loaded instance when an edited module fails to compile.
- A malformed user module must not prevent the manager from starting. Skip and report only that local module during startup, retain the source for repair or deletion, and keep explicit loads strict so their failures are visible to the caller.
- Keep file creation and deletion inside the local user module directory, reject symlinked module paths, and never overwrite an existing module file.
- Recently edited user-local modules can live outside this checkout. Include them when the review scope calls for them, keep endpoints and credentials out of reports, and check recovery paths with mocks. Preserve a dead pane's diagnostic output unless the module's intended behavior explicitly permits respawning it.

## Verification

- Run the full test suite in a project environment with dependencies (`python -m pytest -q`) after changing workspace or module loading behavior. Report skipped integration tests separately; real tmux tests need tmux and explicit test setup.
- Run focused tests for changed paths, `git diff --check`, and a Python lint pass for undefined names and unused imports. Fix stale fixtures when an interface changes; use explicit fixture collaborators so an unconfigured `Mock` cannot accidentally act truthy or return a fake byte count.
- Keep history-only tests focused on history loading, and test console bootstrap and connection loss in their own lifecycle tests. Do not make a history test depend on a real shell channel.
