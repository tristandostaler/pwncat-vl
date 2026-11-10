Grouped console commands
========================

The local console groups related actions by object. These names work in
configuration scripts and the workspace console. Tab completes each level, and
``help`` accepts a full command path such as ``help module run``. The older
short names remain available for existing scripts and history; the main help
screen shows the grouped names.

.. code-block:: text

    module list
    module search PATTERN
    module info NAME
    module edit NAME
    module reload NAME
    module run NAME key=value
    module run --background NAME key=value
    module status
    module result
    module load LOCAL_DIRECTORY
    module use NAME

    listener start -m linux 4444
    listener list
    listener list --all
    listener show 0
    listener stop 0
    listener init 0

    transfers upload LOCAL_PATH REMOTE_PATH
    transfers download REMOTE_PATH LOCAL_PATH
    transfers between SOURCE_ID SOURCE_PATH DEST_ID DEST_PATH [--overwrite]
    transfers status

Inside an SSH workspace console, pane and window commands are grouped too:

.. code-block:: text

    workspace status
    workspace pane list
    workspace pane select %0
    workspace pane split %0 vertical
    workspace window new sliver

``workspace pane select`` changes the pane shown by ``resume``. It does not
change the active pwncat session used by modules or transfers; ``sessions ID``
selects that session. ``forward`` already groups local and reverse forwarding
actions, so its command names remain the same.

``transfers between`` streams a regular file between two active pwncat sessions
through the local process without saving an intermediate local file. It verifies
the staged destination before publishing it. Existing destination files require
``--overwrite``. The older ``upload`` and ``download`` commands still work, and
bare ``transfers`` still shows background transfer status.
