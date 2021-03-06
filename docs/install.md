# Installation

## Install Ubuntu

Install dependencies:
```
sudo apt install -y libssl1.1 libncurses5 libjansson4
```

Download and install debian package:
https://github.com/rtbrick/bngblaster/releases

```
sudo dpkg -i <package>
```

This command installs the BNG Blaster to `/usr/sbin/bngblaster`. 

## Build from Sources

### Dependencies

The BNG Blaster has dependencies to the RtBrick libdict fork
(https://github.com/rtbrick/libdict) and the following standard
dependencies:
```
sudo apt install -y cmake \
    libcunit1-dev \
    libncurses5-dev \
    libssl-dev \
    libjansson-dev
```

### Build

Per default cmake (`cmake .`) will build the BNG Blaster as release
version with optimization and without debug symbols.
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make all
```

Alternative it is also possible to build a debug
version for detailed troubleshooting using gdb.
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make all
```

There are also CPack files generated which allows to easily generate a debian
package by just executing `cpack` from build directory.

It is also recommended to provide the GIT commit details to be included in the
manually build version as shown below:
```
cmake -DGIT_REF=`git rev-parse --abbrev-ref HEAD` -DGIT_SHA=`git rev-parse HEAD` ..
```

*Example:*
```
$ bngblaster -v
GIT:
  REF: dev
  SHA: df453a5ee9dbf6440aefbfb9630fa0f06e326d44
IO Modes: packet_mmap_raw (default), packet_mmap, raw
```

### Install

Then BNG Blaster can be installed using make install target.
```
sudo make install
```

This command installs the BNG Blaster to `/usr/local/sbin/bngblaster`. 

An existing version installed from debian package in `/usr/sbin` is 
not automatically replaced or removed here and should be deleted manually
before install. Otherwise it might be possible that two versions remain
in parallel. 
```
sudo rm /usr/sbin/bngblaster
```

### Build and Run Unit Tests

Building and running unit tests requires CMocka to be installed:
```
sudo apt install libcmocka-dev
```

The option `BNGBLASTER_TESTS` enables to build unit tests.
```
cmake -DCMAKE_BUILD_TYPE=Debug -DBNGBLASTER_TESTS=ON .
make all
make test
```

*Example*
```
$ make test
Running tests...
Test project
    Start 1: TestProtocols
1/1 Test #1: TestProtocols ....................   Passed    0.00 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) =   0.00 sec
```
