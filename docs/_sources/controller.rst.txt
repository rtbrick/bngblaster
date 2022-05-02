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

API
---

OpenAPI: https://rtbrick.github.io/bngblaster-controller/

Create Test Instance
~~~~~~~~~~~~~~~~~~~~

`PUT /api/v1/bngblasters/<instance-name>` 

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
* `run.stdout``: bngblaster standard output 

Start Test 
~~~~~~~~~~~

`POST /api/v1/bngblasters/<instance-name>/_start`

The start API endpoint will start the bngblaster with the argument options
defined in the body.

Status
~~~~~~

`GET /api/v1/bngblasters/<instance-name>`

The status API endpoint returns the status of the test. 

Command 
~~~~~~~

`POST /api/v1/bngblasters/<instance-name>/_command`

The JSON body of this API call will be passed to the bngblaster instance 
control socket (`/var/bngbnlaster/<instance-name>/run.sock``). The result will 
be passed back to the client.

Stop Test 
~~~~~~~~~

`POST /api/v1/bngblasters/<instance-name>/_stop`

The stop API endpoint will send the SIGINT signal to the corresponding BNG blaster instance (`kill -INT <pid>`).

Delete Test Instance
~~~~~~~~~~~~~~~~~~~~

`DELETE /api/v1/bngblasters/<instance-name>`

This API endpoint deletes the test instance directory. The corresponding
test run is forcefully terminated (kill) if running. 
