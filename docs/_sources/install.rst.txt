.. _install:

Installation
============

The BNG Blaster should run on any modern linux distribution
but is primary tested on Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.

Install Ubuntu
--------------

Install dependencies:

.. code-block:: none

    sudo apt install -y libssl1.1 libncurses5 libjansson4

Download and install debian package: https://github.com/rtbrick/bngblaster/releases

.. code-block:: none

    sudo dpkg -i <package>

This command installs the BNG Blaster to `/usr/sbin/bngblaster`.

Build from Sources
------------------

Dependencies
^^^^^^^^^^^^

The BNG Blaster has dependencies to the RtBrick
`libdict fork <https://github.com/rtbrick/libdict>`_
and the following standard dependencies:

.. code-block:: none

    # libdict
    wget https://github.com/rtbrick/libdict/releases/download/v1.0.1/libdict-debian.zip
    sudo dpkg -i libdict_1.0.1_amd64.deb
    sudo dpkg -i libdict-dev_1.0.1_amd64.deb

    # standard dependencies
    sudo apt install -y cmake \
        libcunit1-dev \
        libncurses5-dev \
        libssl-dev \
        libjansson-dev

Build
^^^^^

Per default cmake (`cmake .`) will build the BNG Blaster as release
version with optimization and without debug symbols.

.. code-block:: none

    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make all

Alternative it is also possible to build a debug
version for detailed troubleshooting using gdb.

.. code-block:: none

    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    make all


There are also CPack files generated which allows to easily generate a debian
package by just executing `cpack` from build directory.

It is also recommended to provide the GIT commit details to be included in the
manually build version as shown below:

.. code-block:: none

    cmake -DGIT_REF=`git rev-parse --abbrev-ref HEAD` -DGIT_SHA=`git rev-parse HEAD` .

*Example:*

.. code-block:: none

    $ bngblaster -v
    GIT:
    REF: dev
    SHA: df453a5ee9dbf6440aefbfb9630fa0f06e326d44
    IO Modes: packet_mmap_raw (default), packet_mmap, raw

Install
^^^^^^^

Then BNG Blaster can be installed using make install target.

.. code-block:: none

    sudo make install

This command installs the BNG Blaster to `/usr/sbin/bngblaster`.

Build and Run Unit Tests
^^^^^^^^^^^^^^^^^^^^^^^^

Building and running unit tests requires CMocka to be installed:

.. code-block:: none

    sudo apt install libcmocka-dev

The option `BNGBLASTER_TESTS` enables to build unit tests.

.. code-block:: none

    cmake -DCMAKE_BUILD_TYPE=Debug -DBNGBLASTER_TESTS=ON .
    make all
    make test

*Example:*

.. code-block:: none

    $ make test
    Running tests...
    Test project
        Start 1: TestProtocols
    1/1 Test #1: TestProtocols ....................   Passed    0.00 sec

    100% tests passed, 0 tests failed out of 1

    Total Test time (real) =   0.00 sec

Running BNG Blaster
-------------------

The BNG Blaster needs permissions to send raw packets and change network interface
settings. The easiest way to run the BNG Blaster is either as the root user or with
sudo:

.. code-block:: none

    # As root
    bngblaster -C config.json -I

    # As a normal user:
    sudo bngblaster -C config.json -I


A third option is to set capabilities on the binary with in example `setcap`
as shown below:

.. code-block:: none

    sudo setcap cap_net_raw,cap_net_admin,cap_dac_read_search+eip `which bngblaster`

    # As normal user:
    bngblaster -C config.json -I

