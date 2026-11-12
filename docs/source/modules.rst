Modules
=======

pwncat has two programmable building blocks: commands and modules. Modules are
specific to an open session. They are intended to retrieve some information or
make a modification to a specific target. By default, modules are loaded from
the ``pwncat/modules`` directory, but more modules can be loaded from a custom
location via the ``module load`` command.

Module Contexts
---------------

You can enter a module "context" which means that any ``set`` commands will
operate specifically on that modules arguments by default. This is useful
when a module takes a large number of arguments or complex arguments. In
this case, the local prompt prefix changes to ``([module_name])`` vice
the normal ``(local)``. The context is exited automatically after using the
``run`` command.

When in a module context, commands like ``module info`` and ``module run`` no longer
require the module name as a parameter. It is inferred by the current context.

Locating Modules
----------------

``module list`` shows every loaded module, including custom modules and modules
for other platforms. ``module search`` finds modules matching a pattern for the
active session. You can also locate modules using tab completion at the local
prompt.

.. code-block:: bash

   module list
   module search enumerate.*

Viewing Documentation
---------------------

Module documentation can be viewed with ``module info``. When within
a module context, the module name is inferred from the current context
if not specified.

.. code-block:: bash

   module info escalate.auto

Running Modules
---------------

``module run`` executes a module. The module name is inferred
from the module context if not specified. Key-value parameters can be specified
in ``module run`` or with ``set`` within a module context.
For the active platform, the full name and the name without its platform prefix
resolve to the same module.

.. code-block:: bash

   module run escalate.auto user=root
   module run linux.enumerate.software.pkexec.cve_2021_4034
   module run enumerate.software.pkexec.cve_2021_4034
   module use escalate.auto
   set user root
   module run

Background Modules
------------------

In a workspace console, ``module run --background NAME`` runs a module while
the console stays available. The console switches to a separate workspace SSH
session so it never shares the running module's shell. Use ``module status``
to check whether it is running and ``module result`` to display the completed result or
error. ``sessions ID`` cannot select the busy session until the module ends.
``Ctrl+Q`` can park the live client; ``detach`` waits for background work to
finish before closing it.

Only modules that declare ``BACKGROUND_SAFE = True`` can use this option.
Such a module must not read terminal input or change the manager's active
session. Enumeration modules and the local ``bootstrap.pwnbox`` module opt in.
Interactive modules remain in the foreground. Background file transfers still
use ``upload --background`` and ``download --background``.

.. code-block:: text

   module run --background bootstrap.pwnbox
   module status
   module result

Editing Modules
---------------

Use ``module new bootstrap.pwnbox`` to create a local module under
``~/.local/share/pwncat/modules`` (or ``$XDG_DATA_HOME/pwncat/modules``),
including the package files needed to load it. The command loads a starter
``Module`` class and opens its source in the same editor as ``module edit``.
It refuses to overwrite an existing module. Use ``module delete NAME`` to
remove a local module after confirmation; ``--yes`` skips the prompt.
Built-in modules cannot be deleted this way.

Use ``module edit MODULE`` at the local pwncat prompt to open a module's Python source
on your own computer. On macOS, this opens Visual Studio Code when installed;
``VISUAL`` or ``EDITOR`` can select another editor. The console stays usable
while a graphical editor is open. Saving the file makes its changes available
the next time that module runs. Use ``module reload MODULE`` to refresh the module
immediately, for example before ``module info MODULE``. Within a ``module use`` context,
both commands can omit the module name.
``module reload all`` reloads every loaded module, reports failures, and continues
with the remaining modules.

.. code-block:: text

   module edit bootstrap.pwnbox
   module reload all
   module run bootstrap.pwnbox

If edited source has a syntax or import error, ``module run`` reports the reload
error and does not execute the previous version. The previous loaded module
remains available so the file can be fixed and saved again. A running module
finishes with the version it started with; edits take effect on the next run.
