.. _monkey:

Monkey
------

Monkey testing allows testing a BNG for robustness. If enabled, 
it will randomly kill sessions using different methods. For PPPoE 
sessions, it may restart sessions without a termination request or 
PADT (e.g. CPE power outage), gracefully with LCP terminate request, 
flaps IPCP (IPv4) and IP6CP (IPv6) independently, and many more. This 
works similarly for IPoE by flapping DHCPv4 and DHCPv6 sessions.

Monkey testing must be enabled per access function and starts automatically 
per default, which can be changed using the monkey-autostart option. It is 
also required to enable session auto-reconnect for monkey testing!

.. code-block:: json

    {
        "interfaces": {
            "access": [
                {
                    "interface": "eth1",
                    "monkey": true
                }
            ]
        },
        "sessions": {
            "reconnect": true,
            "monkey-autostart": true
        }
    }

It is possible to start and stop the monkey test feature globally using 
the following two :ref:`commands <api>`:

``$ sudo bngblaster-cli run.sock monkey-start``

``$ sudo bngblaster-cli run.sock monkey-stop``

A common test could be to start a test with the maximum number of session and
monkey test autostart disabled. As soon as all sessions are established, start
monkey testing with the corresponding start :ref:`command <api>` and keep it running. 
After 24 hours stop monkey testing with the corresponding stop :ref:`command <api>`
and wait for all sessions to become established again. The device under test should
fully recover without hanging sessions, crashes or memory leaks.  