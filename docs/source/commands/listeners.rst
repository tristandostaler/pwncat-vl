Listeners
=========

The ``listener`` command group manages active and stopped listeners. The older ``listeners`` command remains available. Use the group to view listener configuration, stop active listeners, view failure messages, and initialize queued channels.

When initializing a channel, you will be shown a list of pending channels, of which you can select and define a platform name. After specifying a platform, a session will be established with the channel and you will have the option of initializing other queue channels.

.. code-block:: bash
    :caption: Interacting with Listeners

    # List only running and failed listeners
    listener list
    # List all listeners (running, stopped, and failed)
    listener list --all
    # Kill listener with ID 0
    listener stop 0
    # View listener configuration (and failure message)
    listener show 0
    # Initialize pending channels
    listener init 0
