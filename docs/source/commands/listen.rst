Listen
======

``listener start`` creates a background listener to asynchronously establish sessions via a reverse shell payload. The older ``listen`` name remains available. Background listeners can operate in two different modes: with a platform and without. If a platform type is not specified when creating a listener, channels will be queued until you initialize them with ``listener init``.

Using the ``--drop-duplicate`` option will cause pwncat to drop any new sessions which duplicate both the target host and user of an existing session. This could be useful when using an infinite reverse shell implant.

Currently, listeners can only be used with the ``socket`` protocol, however listeners are capable of wrapping the socket server in an SSL context. A background listener can effectively replace the ``bind://`` and ``ssl-bind://`` protocols.

The ``--count`` option can be used to restrict background listeners to a set number of active sessions. After reaching the number specified by ``--count``, the listener will automatically be stopped.

.. code-block:: bash

    # Create a basic listener for linux sessions on port 9999
    listener start -m linux 9999
    # Create an SSL listener for linux sessions on port 6666
    listener start -m linux --ssl 6666
    # Create a listener with no platform which caches channels until initialization
    listener start 8888
    # Create a listener which automatically exits after 4 established sessions
    listener start --count 4 --platform windows 5555
