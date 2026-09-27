# BNG Blaster Integration Tests

Functional tests over veth pairs between network namespaces:

* BNG Blaster L2TP LAC against BNG Blaster L2TP LNS
  (`test_l2tp_lac_lns.py`)
* BNG Blaster BGP against GoBGP: IPv4/IPv6 unicast, connection
  collision, MD5, TCP-AO and EVPN (`test_bgp_*.py`)
* BNG Blaster ISIS and OSPFv2 against FRR: adjacency (P2P and
  broadcast, L1/L2/L1L2), database synchronization in both directions
  with routes installed by FRR, and authentication
  (`test_isis_frr.py`, `test_ospf_frr.py`)
* All examples of the quickstart guide: PPPoE, DHCP, ISIS, BGP, LDP
  and network traffic (`test_quickstart.py`)

Each test creates two namespaces `bbl-it-<n>-a` and `bbl-it-<n>-b`
connected by a veth pair. Configs, logs, pcaps and JSON reports of all
instances are kept in the pytest `tmp_path` of the test.

## Requirements

* root (network namespaces)
* Python 3 with `pip install -r requirements.txt`
* BNG Blaster build (default `build/code/bngblaster/bngblaster`)
* GoBGP with TCP-AO support (not released yet, build from master):

```
go install github.com/osrg/gobgp/v4/cmd/...@15e9be9198ae51abad50b3d9b42aa63c3b462834
```

* FRR 10 from the FRR Debian repository (https://deb.frrouting.org),
  tests are skipped if not installed unless `BBL_REQUIRE_FRR` is set.
  The FRR daemons are started per test (as root, with all sockets and
  logs in the test directory), so the FRR service can be stopped.
* Linux kernel with `CONFIG_TCP_MD5SIG` and `CONFIG_TCP_AO` (6.7+),
  tests are skipped otherwise unless `BBL_REQUIRE_TCP_MD5` or
  `BBL_REQUIRE_TCP_AO` is set.

## Run

The tests don't build the BNG Blaster, so rebuild after code changes:

```
cmake --build build
sudo -E python3 -m pytest test/integration
```

Without sudo, the tests also run in an unprivileged user namespace:

```
unshare -rnm sh -c "mount -t tmpfs tmpfs /run && mkdir -p /run/netns /run/lock && python3 -m pytest test/integration"
```

FRR additionally needs a writable `/var/lib/frr` and the groups `frr`
and `frrvty` in the user namespace, e.g. by bind mounting a tmpfs to
`/var/lib` and an `/etc/group` with both groups mapped to gid 0.

Binaries are found via `BNGBLASTER_BIN`, `BGPUPDATE_BIN`, `LDPUPDATE_BIN`,
`LSPGEN_BIN`, `GOBGPD_BIN`, `GOBGP_BIN`, `FRR_DIR` (daemon directory,
default `/usr/lib/frr`) and `VTYSH_BIN`, or the build directory,
`~/go/bin` of the invoking user (also with sudo) and `PATH`. Test artifacts are kept in `tmp/integration`
(owned by the invoking user after sudo runs) unless `--basetemp` is set.

Alternatively configure CMake with `-DBNGBLASTER_INTEGRATION_TESTS=ON`
and run `sudo -E ctest -L integration`.
