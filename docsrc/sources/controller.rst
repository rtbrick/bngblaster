.. _controller:

Controller
==========

The BNG Blaster controller provides a REST API to start and stop multiple test instances. 
It exposes the BNG Blaster :ref:`JSON RPC API <api>` as REST API and provides endpoints 
to download logs and reports.

https://github.com/rtbrick/bngblaster-controller

Installation
------------

The BNG Blaster controller should run on any modern linux distribution
but is primary tested on Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.

Download and install debian package: https://github.com/rtbrick/bngblaster-controller/releases

.. code-block:: none

    $ wget https://github.com/rtbrick/bngblaster-controller/releases/download/<version>/bngblaster-controller_<version>_amd64.deb
    $ sudo dpkg -i bngblaster-controller_<version>_amd64.deb


The corresponding service will be started automatically. 

.. code-block:: none

    $ systemctl status rtbrick-bngblasterctrl.service
    ● rtbrick-bngblasterctrl.service - RtBrick BNG Blaster Controller
        Loaded: loaded (/lib/systemd/system/rtbrick-bngblasterctrl.service; enabled; vendor preset: enabled)
        Active: active (running) since Fri 2022-07-01 11:14:01 UTC; 7min ago
    Main PID: 682535 (bngblasterctrl)
        Tasks: 8 (limit: 309235)
        Memory: 2.6M
        CGroup: /system.slice/rtbrick-bngblasterctrl.service
                └─682535 /usr/local/bin/bngblasterctrl


The BNG Blaster controller listens on port `8001` per default, 
which can be changed using the argument `-addr` in the systemd
service unit `/etc/systemd/system/bngblaster-controller.service`. 

.. code-block:: none

    $ sudo bngblasterctrl --help
    Usage of bngblasterctrl:
    -addr string
            HTTP network address (default ":8001")
    -color
            turn on color of color output
    -console
            turn on pretty console logging (default true)
    -d string
            config folder (default "/var/bngblaster")
    -debug
            turn on debug logging
    -e string
            bngblaster executable (default "/usr/sbin/bngblaster")


API
---

OpenAPI: https://rtbrick.github.io/bngblaster-controller/

Create Test Instance
~~~~~~~~~~~~~~~~~~~~

`PUT /api/v1/instances/<instance-name>` 

This API endpoint creates a test instance if not already created. The body of this request 
is stored as bngblaster configuration (`config.json`).

Each test instance creates a directory in `/var/bngblaster/<instance-name>`. 
This directory contains the following files:

* `config.json`: bngblaster configuration
* `run.pid`: bngblaster process ID (if running)
* `run.json`: bngblaster arguments
* `run_report.json`: bngblaster report (if enabled)
* `run.pcap`: bngblaster traffic capture (if enabled)
* `run.sock`: bngblaster control socket
* `run.stderr`: bngblaster standard error
* `run.stdout`: bngblaster standard output 

Start Test 
~~~~~~~~~~~

`POST /api/v1/instances/<instance-name>/_start`

The start API endpoint will start the bngblaster with the argument options
defined in the body.

.. code-block:: json

    {
        "logging": true,
        "logging_flags": [
            "error",
            "ip"
        ]
    }

All supported argument options are explained in the OpenAPI schema.

Status
~~~~~~

`GET /api/v1/instances/<instance-name>`

The status API endpoint returns the status of the test. 

Command 
~~~~~~~

`POST /api/v1/instances/<instance-name>/_command`

The JSON body of this API call will be passed to the bngblaster instance 
control socket (`/var/bngbnlaster/<instance-name>/run.sock`). The result will 
be passed back to the client.

.. code-block:: none

    curl --location --request POST 'http://<IP>>:8001/api/v1/instances/<instance-name>/_command' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "command": "session-info",
        "arguments": {
            "session-id": 1
        }
    }'


.. code-block:: json

    {
        "status": "ok",
        "code": 200,
        "session-info": {
            "type": "pppoe",
            "session-id": 1,
            "session-state": "Established",
            "...": "..."
        }
    }


The result code is passed as HTTP response status code.

.. code-block:: json

    {
        "status": "warning",
        "code": 404, 
        "message": "session not found"
    }


Stop Test 
~~~~~~~~~

`POST /api/v1/instances/<instance-name>/_stop`

The stop API endpoint will send the SIGINT signal to the corresponding BNG blaster instance (`kill -INT <pid>`).

Delete Test Instance
~~~~~~~~~~~~~~~~~~~~

`DELETE /api/v1/instances/<instance-name>`

This API endpoint deletes the test instance directory. The corresponding
test run is forcefully terminated (`kill -9 <pid>`) if running. 

Metrics
~~~~~~~

`GET /metrics`

This endpoint returns metrics for all instances in prometheus text format. 

.. code-block:: none

    # HELP instances_running The number of running instances
    # TYPE instances_running gauge
    instances_running{hostname="blaster"} 0
    # HELP instances_total The total number of instances
    # TYPE instances_total gauge
    instances_total{hostname="blaster"} 4

The metric `instances_total` counts the number of test instance directories 
present and `instances_running` shows how many of them are running. 

Every metric is labelled with the hostname where the controller is running.

Per default there are no metrics per instance. This has to be explicitly 
enabled during instance start (`/api/v1/instances/<instance-name>/_start`) 
using the new  `metric_flags` option.

.. code-block:: json

    {
        "logging": true,
        "logging_flags": [
            "error",
            "ip"
        ],
        "metric_flags": [
            "session_counters",
            "interfaces"
        ]
    }

Currently the following metrics are supported:

* `session_counters` session statistics
* `interfaces` interface counters

.. code-block:: none

    # HELP sessions The total number of sessions
    # TYPE sessions counter
    sessions{hostname="blaster",instance_name="test"} 10
    # HELP sessions_established The number of sessions in state established
    # TYPE sessions_established gauge
    sessions_established{hostname="blaster",instance_name="test"} 10
    ...

Instance metrics are labelled with the instance name. All interface specific metrics
are also labelled with the corresponding interface name.

.. code-block:: none

    # HELP interfaces_rx_bytes Interface RX bytes
    # TYPE interfaces_rx_bytes counter
    interfaces_rx_bytes{hostname="blaster",instance_name="test",interface_name="eth1",interface_type="access"} 36270
    ...