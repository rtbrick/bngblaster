.. _api:

.. raw:: html

   <link rel="stylesheet" type="text/css" href="_static/custom.css">

API/CLI
=======

The control socket is an unix domain stream socket that 
allows interacting with the BNG Blaster using JSON RPC. 

We developed this interface for the BNG Blaster Controller 
but it can be also used by other tools. One example is the 
included CLI tool ``bngblaster-cli``. You can use this for 
interactive communication with the BNG Blaster.

You need to enable the control socket by providing the path to 
the control socket file with the argument ``-S`` (``bngblaster -S run.sock``).

Each request must contain at least the ``command`` element which carries
the actual command with optional arguments.

.. code-block:: json

    {
        "command": "<command>"
        "arguments": {
            "<argument-key>": "<argument-value>"
        }
    }

Following an example RPC request with corresponding response.

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
value ``ok`` and status code ``2xx`` if request was successfully. 
The status can be also set to ``warning`` or ``error`` with 
corresponding error code and an optional error message.

``$ cat command.json | sudo nc -U test.socket | jq .``

.. code-block:: json

    {
        "status": "warning",
        "code": 404,
        "message": "session not found"
    }


The ``session-id`` is the same as used for ``{session-global}`` in the
configuration. This number starts with 1 and is increased
per session added. In example if username is configured as
``user{session-global}@rtbrick.com`` and logged in user is
``user10@rtbrick.com`` the ``session-id`` of this user is ``10``.

.. tip:: 
    The argument ``session-id`` can be alternatively replaced 
    with interface and VLAN of the session. The last access 
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
    BNG Blaster Control Socket Client

    bngblaster-cli <socket> <command> [arguments]

    Examples:
        bngblaster-cli run.sock session-info session-id 1
        bngblaster-cli run.sock igmp-join session-id 1 group 239.0.0.1 source1 1.1.1.1 source2 2.2.2.2 source3 3.3.3.3
        bngblaster-cli run.sock igmp-info session-id 1
        bngblaster-cli run.sock l2tp-csurq tunnel-id 1 sessions [1,2]

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

``$ sudo bngblaster-cli run.sock sessions-pending | jq '.["sessions-pending"][]["session-id"]' | while read line; do sudo bngblaster-cli run.sock session-restart session-id $line; done


Test
----

+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **test-info**                     | | Display information about the running test instance.               |
+-----------------------------------+----------------------------------------------------------------------+
| **test-stop**                     | | Stop/teardown the test.                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **terminate**                     | | Stop/teardown the test.                                            |
+-----------------------------------+----------------------------------------------------------------------+
| **monkey-start**                  | | Start monkey test.                                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **monkey-stop**                   | | Stop monkey test.                                                  |
+-----------------------------------+----------------------------------------------------------------------+

Interfaces
----------
This is explained detailed in the 
:ref:`interfaces <interfaces>` section.

.. include:: interfaces.rst

Sessions
--------
.. include:: sessions.rst

PPP
---
This is explained detailed in the 
:ref:`PPPoE <pppoe>` section.

.. include:: ppp.rst

L2TP
----
This is explained detailed in the 
:ref:`L2TP <l2tp>` section.

.. include:: l2tp.rst

IGMP
----
.. include:: igmp.rst

Traffic
-------
.. include:: traffic.rst

Streams
-------
This is explained detailed in the 
:ref:`streams <streams>` section.

.. include:: streams.rst

ISIS
----
This is explained detailed in the 
:ref:`ISIS <isis>` section.

.. include:: isis.rst

OSPF
----
This is explained detailed in the 
:ref:`OSPF <ospf>` section.

.. include:: ospf.rst

BGP
---
This is explained detailed in the 
:ref:`BGP <bgp>` section.

.. include:: bgp.rst

LDP
---
This is explained detailed in the 
:ref:`LDP <ldp>` section.

.. include:: ldp.rst

CFM
---
.. include:: cfm.rst

Legal Interception (LI)
-----------------------
This is explained detailed in the 
:ref:`Legal Interception (LI) <li>` section.

.. include:: li.rst

HTTP
----
This is explained detailed in the 
:ref:`HTTP <http>` section.

.. include:: http.rst