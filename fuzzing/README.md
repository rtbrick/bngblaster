# AFL Fuzzing

## Install AFL

```
sudo apt install afl
```

## Build Fuzzing Tests

```
# cd fuzzing
export AFL_USE_ASAN=1
cmake .
make clean all;
```

## Run Tests

### Protocols Decode

```
# cd fuzzing
afl-fuzz -m none -i protocols_decode_in -o protocols_decode_out ./fuzz-protocols-decode @@
```

## RAM Disks and Saving Your SSD From AFL Fuzzing

```
mkdir /tmp/afl-ramdisk && chmod 777 /tmp/afl-ramdisk
sudo mount -t tmpfs -o size=512M tmpfs /tmp/afl-ramdisk
cp -R bngblaster /tmp/afl-ramdisk/
cd /tmp/afl-ramdisk/bngblaster
```
