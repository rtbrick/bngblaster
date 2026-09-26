# BNG Blaster Integration Tests

Functional tests over veth pairs between network namespaces:

* BNG Blaster L2TP LAC against BNG Blaster L2TP LNS
  (`test_l2tp_lac_lns.py`)
* BNG Blaster BGP against GoBGP: IPv4/IPv6 unicast, connection
  collision, MD5, TCP-AO and EVPN (`test_bgp_*.py`)
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

Binaries are found via `BNGBLASTER_BIN`, `BGPUPDATE_BIN`, `LDPUPDATE_BIN`,
`LSPGEN_BIN`, `GOBGPD_BIN` and `GOBGP_BIN`, or the build directory,
`~/go/bin` of the invoking user (also with sudo) and `PATH`. Test artifacts are kept in `tmp/integration`
(owned by the invoking user after sudo runs) unless `--basetemp` is set.

Alternatively configure CMake with `-DBNGBLASTER_INTEGRATION_TESTS=ON`
and run `sudo -E ctest -L integration`.
