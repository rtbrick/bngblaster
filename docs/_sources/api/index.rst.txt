.. _api:

.. raw:: html

   <link rel="stylesheet" type="text/css" href="_static/custom.css">

API/CLI
=======

The control socket is an unix domain stream socket that 
allows interacting with the BNG Blaster using JSON RPC. 

We developed this interface for the BNG Blaster Controller 
it can also be used by other tools. One example is the 
included CLI tool ``bngblaster-cli``. You can use this for 
interactive communication with the BNG Blaster.

You need to enable the control socket by providing the path to 
the control socket file with the argument ``-S`` (``bngblaster -S run.sock``).

Each request must contain at least the ``command`` element which carries
the actual command with optional arguments.

.. code-block:: json

    {
        "command": "<command>",
        "arguments": {
            "<argument-key>": "<argument-value>"
        }
    }

The following is an example RPC request with its corresponding response.

``$ cat command.json | jq .``

.. code-block:: json

    {
        "command": "session-counters"
    }

``$ cat command.json | sudo nc -U run.sock | jq .``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "session-counters": {
            "sessions": 3,
            "sessions-established": 3,
            "sessions-flapped": 3,
            "dhcpv6-sessions-established": 3
        }
    }

The response contains at least the status element with the
value ``ok`` and status code ``2xx`` if the request was successful.
The status can also be set to ``warning`` or ``error`` with
corresponding error code and an optional error message.

``$ cat command.json | sudo nc -U run.sock | jq .``

.. code-block:: json

    {
        "status": "warning",
        "code": 404,
        "message": "session not found"
    }


The ``session-id`` is the same as used for ``{session-global}`` in the
configuration. This number starts with 1 and is increased
per session added. For example, if the username is configured as
``user{session-global}@rtbrick.com`` and logged in user is
``user10@rtbrick.com`` the ``session-id`` of this user is ``10``.

.. tip:: 
    The argument ``session-id`` can be alternatively replaced 
    with interface and VLAN of the session. The first access 
    interface is automatically used if the argument ``interface`` 
    is not present in the command.

    This is not supported for N:1 sessions because multiple 
    sessions can be assigned to a single VLAN.

    .. code-block:: json

        {
            "command": "session-info",
            "arguments": {
                "interface": "eth0",
                "outer-vlan": 1,
                "inner-vlan": 1
            }
        }

BNG Blaster CLI
---------------

The python script ``bngblaster-cli`` provides a simple CLI tool
for interactive communication with the BNG Blaster.

.. code-block:: none

    $ sudo bngblaster-cli
    BNG Blaster CLI Tool

    The CLI tool is a simple control socket client
    for interactive communication with the BNG Blaster.

    bngblaster-cli <socket> <command> [arguments]

    Examples:
        bngblaster-cli run.sock session-info session-id 1
        bngblaster-cli run.sock interface-topology
        bngblaster-cli run.sock interface-topology interface eth0
        bngblaster-cli run.sock igmp-join session-id 1 group 239.0.0.1 source1 1.1.1.1 source2 2.2.2.2 source3 3.3.3.3
        bngblaster-cli run.sock igmp-info session-id 1
        bngblaster-cli run.sock l2tp-csurq tunnel-id 1 sessions [1,2]

Bash completion for ``bngblaster-cli`` is installed to
``/usr/share/bash-completion/completions/bngblaster-cli`` and picked up
automatically by the ``bash-completion`` package (or can be sourced manually).
It completes the socket path, the command name and its arguments by querying
the ``commands`` endpoint of the running instance referenced by the socket
path already typed, so suggestions always match that instance.

``$ sudo bngblaster-cli run.sock session-counters | jq .``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "session-counters": {
            "sessions": 1,
            "sessions-established": 1,
            "sessions-flapped": 0,
            "dhcpv6-sessions-established": 1
        }
    }


Here's a more complex example that chains CLI commands. The first command 
returns a list of all pending sessions. Then, it extracts the session.id 
from those sessions into a flat list. Finally, it iterates over this list, 
using each session-id as an argument for the session-restart command.

``$ sudo bngblaster-cli run.sock sessions-pending | jq '.["sessions-pending"][]["session-id"]' | while read line; do sudo bngblaster-cli run.sock session-restart session-id $line; done``


Test
----

+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **test-info**                     | | Display information about the test instance, including its         |
|                                   | | status (starting, running or stopping) and current task,           |
|                                   | | which is available also during the startup (see below).            |
+-----------------------------------+----------------------------------------------------------------------+
| **threads**                       | | Display the main thread and all I/O threads with the CPU           |
|                                   | | they are pinned to, available once all threads are started.        |
+-----------------------------------+----------------------------------------------------------------------+
| **test-stop**                     | | Stop/teardown the test (graceful, global).                         |
+-----------------------------------+----------------------------------------------------------------------+
| **terminate**                     | | Deprecated. Terminate the given ``session-id``, or                 |
|                                   | | stop/teardown the whole test if no ``session-id`` is               |
|                                   | | given. Use ``session-start``/``session-stop`` instead              |
|                                   | | for terminating single sessions.                                   |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id``                                                     |
|                                   | | ``reconnect-delay``                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **monkey-start**                  | | Start monkey test.                                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **monkey-stop**                   | | Stop monkey test.                                                  |
+-----------------------------------+----------------------------------------------------------------------+

The control socket is opened right after the log file, before the configuration
is loaded, so that a controller can follow the startup and shutdown of the
instance with ``test-info``. During the startup and after the test has finished,
only ``test-info``, ``commands`` and ``threads`` (once all threads are started)
are available, while all other commands are answered with status code 503
(``not available while starting`` or ``not available while stopping``). A
controller should therefore wait until the status is ``running`` before sending
other commands. During the teardown (task ``teardown``), all commands remain
available.

The startup can be aborted with ``test-stop`` or ``terminate`` (without
``session-id``) via control socket, or with the signals ``SIGINT``,
``SIGTERM`` or ``SIGHUP``, also while waiting for the startup of other
instances. The instance then restores the interface configuration, releases
all resources and exits with status 3 without generating reports, which
distinguishes an aborted startup from a test (0) or an error (1).

``$ sudo bngblaster-cli run.sock test-info``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "test-info": {
            "state": "init",
            "duration": 0,
            "status": "starting",
            "task": "wait-startup-lock",
            "pid": 4712,
            "startup-lock-pid": 4711
        }
    }

The ``status`` is ``starting``, ``running`` or ``stopping``, and the ``task``
shows what the instance is currently doing:

+-----------------------+----------------------------------------------------------------------+
| Task                  | Description                                                          |
+=======================+======================================================================+
| load-config           | Load the configuration (status starting).                            |
+-----------------------+----------------------------------------------------------------------+
| wait-startup-lock     | Wait for the startup of another instance, which is shown as          |
|                       | ``startup-lock-pid`` (status starting).                              |
+-----------------------+----------------------------------------------------------------------+
| init-dpdk             | Initialize DPDK (status starting).                                   |
+-----------------------+----------------------------------------------------------------------+
| init-protocols        | Initialize IS-IS, OSPF and LDP (status starting).                    |
+-----------------------+----------------------------------------------------------------------+
| init-interfaces       | Initialize the interfaces (status starting).                         |
+-----------------------+----------------------------------------------------------------------+
| init-bgp              | Initialize the BGP sessions (status starting).                       |
+-----------------------+----------------------------------------------------------------------+
| init-streams          | Initialize the traffic streams (status starting).                    |
+-----------------------+----------------------------------------------------------------------+
| init-sessions         | Initialize the access sessions (status starting).                    |
+-----------------------+----------------------------------------------------------------------+
| start-threads         | Select the CPUs and start the I/O threads (status starting).         |
+-----------------------+----------------------------------------------------------------------+
| resolve-gateways      | Wait for the gateways of the network interfaces to be resolved       |
|                       | (status running).                                                    |
+-----------------------+----------------------------------------------------------------------+
| running               | Test is running (status running).                                    |
+-----------------------+----------------------------------------------------------------------+
| teardown              | Teardown of sessions and protocols (status stopping).                |
+-----------------------+----------------------------------------------------------------------+
| stop-threads          | Stop the I/O threads (status stopping).                              |
+-----------------------+----------------------------------------------------------------------+
| reports               | Generate the final reports (status stopping).                        |
+-----------------------+----------------------------------------------------------------------+
| cleanup               | Restore the interface configuration and release all resources        |
|                       | (status stopping).                                                   |
+-----------------------+----------------------------------------------------------------------+

The ``state`` (``init``, ``active`` or ``teardown``) is kept for compatibility,
where ``init`` lasts until all gateways are resolved.

``$ sudo bngblaster-cli run.sock threads``

.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "threads": [
            {
                "name": "main",
                "type": "main",
                "cpu": 2,
                "cpu-auto": true,
                "cpu-shared": false,
                "tid": 4712
            },
            {
                "name": "rx0-eth1",
                "type": "rx",
                "interface": "eth1",
                "cpu": 0,
                "cpu-auto": true,
                "cpu-shared": false,
                "tid": 4714
            }
        ]
    }

The ``cpu`` is ``null`` for threads which are not pinned. ``cpu-auto`` shows
whether the CPU was selected by the automatic CPU placement, and ``cpu-shared``
whether the CPU is shared with another thread of this or another instance.
The ``tid`` is the Linux thread ID (e.g. for ``top -H`` or ``perf``).

Interfaces
----------
This is explained in detail in the
:ref:`interfaces <interfaces>` section.

.. include:: interfaces.rst

Sessions
--------
.. include:: sessions.rst

PPP
---
This is explained in detail in the
:ref:`PPPoE <pppoe>` section.

.. include:: ppp.rst

L2TP
----
This is explained in detail in the
:ref:`L2TP <l2tp>` section.

.. include:: l2tp.rst

IGMP
----
.. include:: igmp.rst

DHCP
----
.. include:: dhcp.rst

Traffic
-------
.. include:: traffic.rst

Streams
-------
This is explained in detail in the
:ref:`streams <streams>` section.

.. include:: streams.rst

ISIS
----
This is explained in detail in the
:ref:`ISIS <isis>` section.

.. include:: isis.rst

OSPF
----
This is explained in detail in the
:ref:`OSPF <ospf>` section.

.. include:: ospf.rst

BGP
---
This is explained in detail in the
:ref:`BGP <bgp>` section.

.. include:: bgp.rst

LDP
---
This is explained in detail in the
:ref:`LDP <ldp>` section.

.. include:: ldp.rst

CFM
---
.. include:: cfm.rst

Legal Interception (LI)
-----------------------
This is explained in detail in the
:ref:`Legal Interception (LI) <li>` section.

.. include:: li.rst

HTTP
----
This is explained in detail in the
:ref:`HTTP <http>` section.

.. include:: http.rst

ICMP
----
This is explained in detail in the
:ref:`ICMP <icmp>` section.

.. include:: icmp.rst

ARP
----

.. include:: arp.rst

PCAP
----

.. include:: pcap.rst