Run
===

The ``run`` command gives you access to all pwncat modules at runtime. Most functionality in
pwncat is implemented using modules. This includes privilege escalation, enumeration and
persistence. You can locate modules using the ``search`` command or tab-complete their name
with the ``run`` command.

The ``run`` command is similar to the command with the same name in frameworks like Metasploit.
The grouped spelling is ``module run``; the older ``run`` spelling still works.
The first argument to ``run`` is the name of the module you would like to execute. This takes
the form of a Python fully-qualified package name. The default modules are within the ``pwncat/modules``
directory, but other can be loaded with the ``load`` command.

Modules may take arguments, which can be appended as key-value pairs to the end of a call to
the ``run`` command:

.. code-block:: bash

    # Enumerate setuid files on the remote host
    run enumerate.gather types=file.suid

In a workspace console, opted-in modules can run on a background thread with
``module run --background NAME``. The console switches to a separate workspace
SSH session to keep the module's shell free. ``module status`` shows whether it
is still running, and ``module result`` shows its result or error. Modules
that require terminal input or change the active session cannot use this mode.

.. code-block:: text

    module run --background enumerate.gather types=file.suid
    module status
    module result


Required module arguments are first taken from these key-value pairs. If they aren't present,
they are taken from the global configuration.


Run Within A Context
--------------------

In pwncat, the ``use`` command can enter a module context. Within a module context, the
pwncat prompt will change from "(pwncat) local$" to "(module_name) local$". In this state,
you can set module arguments with the ``set`` command. After the arguments are set, you can
run the module with ``run``. Within a module context, no arguments are required for ``run``,
however you are allowed to specify other key-value items as well. For example:

.. code-block:: bash
  
    # Perform the same enumeration as seen above
    use enumerate.gather
    set types file.suid
    run
