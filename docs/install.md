# Installation

## Build from Sources

### Dependencies

The BNG Blaster has dependencies to the RtBrick libdict fork 
(https://github.com/rtbrick/libdict) and the following standard 
dependencies: 
```
sudo apt install -y cmake 
sudo apt install -y libcunit1-dev
sudo apt install -y libncurses5-dev
sudo apt install -y libssl-dev
sudo apt install -y libjansson-dev
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

### Install 

Then BNG Blaster can be installed using make install target.  
```
sudo make install
```

### Build and Run Unit Tests

Building and running unit tests requires CMocka to be installed:
```
sudo apt install libcmocka-dev
```

The option `BNGBLASTER_TESTS` enables to build unit tests. 
```
cmake -DBNGBLASTER_TESTS=ON .
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
