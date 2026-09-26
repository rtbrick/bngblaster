+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **l2tp-tunnels**                  | | Display all L2TP tunnels.                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **l2tp-sessions**                 | | Display all matching L2TP sessions.                                |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``tunnel-id``                                                      |
|                                   | | ``session-id``                                                     |
+-----------------------------------+----------------------------------------------------------------------+
| **l2tp-csurq**                    | | Send L2TP CSURQ.                                                   |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``tunnel-id`` Mandatory                                            |
|                                   | | ``sessions`` list of remote session-id.                            |
+-----------------------------------+----------------------------------------------------------------------+
| **l2tp-tunnel-terminate**         | | Terminate L2TP tunnel.                                             |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``tunnel-id`` Mandatory                                            |
|                                   | | ``result-code``                                                    |
|                                   | | ``error-code``                                                     |
|                                   | | ``error-message``                                                  |
+-----------------------------------+----------------------------------------------------------------------+
| **l2tp-session-terminate**        | | Terminate L2TP session.                                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
|                                   | | ``result-code``                                                    |
|                                   | | ``error-code``                                                     |
|                                   | | ``error-message``                                                  |
|                                   | | ``disconnect-code``                                                |
|                                   | | ``disconnect-protocol``                                            |
|                                   | | ``disconnect-direction``                                           |
|                                   | | ``disconnect-message``                                             |
+-----------------------------------+----------------------------------------------------------------------+
| **l2tp-lcp-restart**              | | Restart LCP of an L2TP session terminated on the BNG Blaster LNS.  |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``session-id`` Mandatory                                           |
+-----------------------------------+----------------------------------------------------------------------+

The L2TP CSURQ command expects the local tunnel-id and a list of remote
session-id for which a connect speed update is requested.

.. code-block:: json

    {
        "command": "l2tp-csurq",
        "arguments": {
            "tunnel-id": 1,
            "sessions": [
                1,
                2,
                3,
                4
            ]
        }
    }

This command can be executed as shown below using the CLI tool.

``$ sudo bngblaster-cli run.sock l2tp-csurq tunnel-id 1 sessions [1,2,3,4]``

The L2TP session terminate command allows testing of result (RFC2661) and disconnect (RFC3145) codes.

``$ sudo bngblaster-cli run.sock l2tp-session-terminate session-id 1 result-code 2 error-message "LCP request" disconnect-code 3 disconnect-message "LCP terminate request"``

The L2TP LCP restart command lets the BNG Blaster LNS send a new LCP
Configure-Request to the client of an established L2TP session,
which forces LCP renegotiation, for example to test how the BNG behaves
after proxy LCP. The ``session-id`` is the BNG Blaster session
tunnelled to the BNG Blaster LNS.

``$ sudo bngblaster-cli run.sock l2tp-lcp-restart session-id 1``
