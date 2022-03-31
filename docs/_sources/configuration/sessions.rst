.. code-block:: json

    { "sessions": {} }


.. list-table::
   :widths: 25 50 25
   :header-rows: 1

   * - Attribute
     - Description
     - Default
   * - `count`
     - Sessions (PPPoE + IPoE)
     - 1
   * - `max-outstanding`
     - Max outstanding sessions
     - 800
   * - `start-rate`
     - Setup request rate in sessions per second
     - 400
   * - `stop-rate`
     - Teardown request rate in sessions per second
     - 400
   * - `iterate-vlan-outer`
     - Iterate on outer VLAN first
     - false
   * - `start-delay`
     - Wait N seconds after all interface are resolved before starting sessions
     - 0

Per default sessions are created by iteration over inner VLAN range first and 
outer VLAN second. Which can be changed by ``iterate-vlan-outer`` to iterate 
on outer VLAN first and inner VLAN second.

Therefore the following configuration generates the sessions on VLAN (outer:inner) 
1:3, 1:4, 2:3, 2:4 per default or alternative 1:3, 2:3, 1:4, 2:4 with 
``iterate-vlan-outer`` enabled.

.. code-block:: json

    {
        "outer-vlan-min": 1,
        "outer-vlan-max": 2,
        "inner-vlan-min": 3,
        "inner-vlan-max": 4
    }
