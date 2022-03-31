.. list-table::
   :header-rows: 1

   * - Attribute
     - Description
     - Mandatory Arguments
     - Optional Arguments
   * - `l2tp-tunnels`
     - Display all L2TP tunnels
     - 
     - 
   * - `l2tp-sessions`
     - L2TP all matching sessions
     - 
     - `tunnel-id`, `session-id`
   * - `l2tp-csurq`
     - Send L2TP CSURQ
     - `tunnel-id`
     - `sessions` (list of remote session-id)
   * - `l2tp-tunnel-terminate`
     - Terminate L2TP tunnel
     - `tunnel-id`
     - `result-code`, `error-code`, `error-message`
   * - `l2tp-session-terminate`
     - Terminate L2TP session
     - `session-id`
     - `result-code`, `error-code`, `error-message`, `disconnect-code`, `disconnect-protocol`, `disconnect-direction`, `disconnect-message`

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

The L2TP session terminate command allows to test result (RFC2661) and disconnect (RFC3145) codes.

``$ sudo bngblaster-cli run.sock l2tp-session-terminate session-id 1 result-code 2 error-message "LCP request" disconnect-code 3 disconnect-message "LCP terminate request"``
