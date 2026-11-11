# BNG Blaster Integration Tests

Functional tests over veth pairs between network namespaces:

* BNG Blaster L2TP LAC against BNG Blaster L2TP LNS, including PPPoL2TP
  session traffic in both directions, stream ports, ICMP client,
  session-restart and the control message backoff (`test_l2tp_lac_lns.py`)
* BNG Blaster BGP against GoBGP: IPv4/IPv6 unicast and labeled
  unicast with End-of-RIB and withdraw, connection collision,
  negotiated and zero hold time, MD5, TCP-AO and EVPN
  (`test_bgp_*.py`)
* RAW update generator output: path attribute order, empty AS_PATH,
  End-of-RIB per family, labeled withdraw encoding and L2VPN routes
  that do not fit into a message (`test_bgpupdate.py`)
* BNG Blaster RAW updates over 1000 BGP sessions in parallel against
  a slow receiver with zero windows (`test_bgp_scale.py`, `bgp_sink.py`)
* BNG Blaster BGP sessions on 300 local addresses accepted from a peer
  that only connects actively (`test_bgp_listen.py`, `bgp_sink.py`)
* BNG Blaster BGP against a scripted peer: NOTIFICATION for invalid
  OPEN messages and headers and for messages unexpected in the current
  state, peer AS check, messages ignored while closing, connections
  refused without reconnect, collision Cease closed with FIN, and send
  MSS by interface MTU for IPv4 and IPv6 (`test_bgp_fsm.py`, `bgp_peer.py`)
* BNG Blaster ISIS and OSPFv2 against FRR: adjacency (P2P and
  broadcast, L1/L2/L1L2), database synchronization in both directions
  with routes installed by FRR (also by CSNP with HMAC-MD5 as DIS), and
  authentication (`test_isis_frr.py`, `test_ospf_frr.py`)
* BNG Blaster OSPFv2 against FRR: area and router-id mismatch, database
  exchange as master, router-id change of the neighbor, flush of the
  network LSA of a previous run, purge of opaque LSAs on teardown,
  SR-Algorithm TLV and LS request rate with 3000 LSAs (`test_ospf_frr.py`)
* BNG Blaster OSPFv3 against FRR: topology of P2P and broadcast links
  (BNG Blaster as DR, BDR and DROther), prefix encoding in 32-bit words
  and flush of the network LSA of a previous run (`test_ospf6_frr.py`)
* BNG Blaster OSPFv2 against another BNG Blaster instance: sequence
  number wrap of self originated LSAs (slow) and invalid input of the
  ospf-lsa-update command (`test_ospf_bbl.py`)
* BNG Blaster ISIS against a scripted neighbor (`isis_peer.py`): P2P
  three-way handshake, hello checks, DIS election, receive rules for
  LSPs and SNPs, CSNP ranges with HMAC-MD5, retransmission, purges,
  pseudonode LSP fragments and control commands (`test_isis_neighbor.py`)
* BNG Blaster OSPFv2 and OSPFv3 against BIRD: adjacency, DR/BDR
  election, database synchronization in both directions (OSPFv2 only
  from BNG Blaster to BIRD) and authentication (`test_ospf_bird.py`)
* All examples of the quickstart guide: PPPoE, DHCP, ISIS, BGP, LDP
  and network traffic (`test_quickstart.py`)
* Automatic CPU placement of BNG Blaster instances started in
  parallel on loopback links, running on the host without namespaces
  (`test_cpu_placement.py`)
* AF_XDP instances started in parallel on a veth pair, skipped if the
  BNG Blaster is built without AF_XDP (`test_af_xdp_parallel.py`)
* Static LAG interfaces over loopback links with stream traffic and
  stream updates of LACP LAG interfaces which are not up, running on
  the host without namespaces (`test_lag_loopback.py`)
* LDP label withdraw and session down, and BGP L2VPN label blocks,
  with streams sent by the main loop and by TX threads, and L2VPN
  counters reset on reconnect (`test_ldp.py`, `test_bgp_l2vpn.py`)
* LDP between two BNG Blaster instances: wildcard withdraw, fatal
  notification, invalid label mappings, prefix length, implicit null,
  two peers with the same FEC, ldp-disconnect with IPv6 filters and
  hellos from any source port (`test_ldp.py`)
* BNG Blaster LDP against FRR: label bindings (IPv4, IPv6, dual-stack),
  hold time, hello adjacency loss, teardown and stream labels
  (`test_ldp_frr.py`)
* BNG Blaster L2TP LNS and LAC against a scripted L2TP peer: Private
  Group ID of any length, Sequencing Required, missing Assigned Tunnel or
  Session ID, LNS echo reply magic and terminate-ack, CDN result code,
  peer strings with invalid UTF-8, SCCRQ retry to the second server and
  tunnel ID range of the control commands (`test_l2tp_protocol.py`,
  `l2tp_peer.py`)
* BNG Blaster L2TP LAC against xl2tpd (LNS) with pppd: sessions, CCP
  protocol-reject, ICMP client through the tunnel, session-restart and
  teardown (`test_l2tp_xl2tpd.py`)
* BNG Blaster PPPoE client against a scripted PPPoE server: rejected LCP
  options, Code-Reject and Discard-Request, NCP timeout, Max-Failure,
  terminate and renegotiation by the server, ipcp-close retransmission,
  disabled IPv4/IPCP, PADO validation and several Service-Name tags,
  missing CHAP challenge, protocol-reject during authentication and for
  unknown protocols, unsolicited terminate-ack, own MRU limit and
  outstanding sessions after lcp-restart (`test_pppoe_negotiation.py`,
  `ppp_peer.py`)
* BNG Blaster PPPoE client against pppd (rp-pppoe): PAP, IPCP and IP6CP,
  rejected Magic-Number and MRU, CHAP re-challenge and IPCP rejected by
  the server (`test_pppoe_pppd.py`)
* Jumbo frames (9000 byte stream packets) with PACKET_MMAP
  (`test_jumbo_frames.py`)
* Stream traffic with io-mode raw received by the main loop and by RX
  threads (`test_io_raw.py`)
* Stream capture with TX/RX threads including PCAP stop/start at
  runtime, and restored VLAN of received packets with PACKET_MMAP
  (`test_capture_streams.py`)
* Teardown order of BGP and IS-IS against FRR: the IGP withdraw waits
  until BGP sessions routed via the IGP are closed (`test_teardown_order.py`)
* PPPoE LCP MRU negotiation with PPP-Max-Payload (RFC 4638) against a
  minimal scapy PPPoE server requesting or suggesting MRUs above the
  allowed maximum (`test_pppoe_mru.py`, `pppoe_server.py`)
* Gratuitous ARP and unsolicited NA of primary and secondary addresses
  overriding stale neighbor entries of the Linux peer, periodic
  announcements and `network-announce` (`test_network_announce.py`)
* Control socket session arguments out of range, commands executed
  by the main loop, idle clients and clients not reading the response
  of a main loop command, terminate with session selectors
  (`test_ctrl_socket.py`)
* HTTP server tested with curl (IPv4 and IPv6) and connections reset
  by the client, HTTP client response after a session reconnect
  (`test_http.py`)
* A10NSP over a network interface with VLAN through a scripted access
  node pseudowire, and DHCPv6 renew of IPoE sessions (slow)
  (`test_a10nsp.py`, `a10nsp_relay.py`)
* BGP control command IPv4/IPv6 address filters with sessions of both
  address families (`test_bgp_ctrl_filter.py`)
* ICMP client on a network interface pinging the Linux peer with small
  data sizes (`test_icmp_client.py`)
* Configuration values out of range or of the wrong type rejected on
  start (`test_config_invalid.py`)

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
* BIRD 2 (Debian/Ubuntu package `bird2`), tests are skipped if not
  installed unless `BBL_REQUIRE_BIRD` is set. BIRD is started per test
  in foreground with config, control socket and log in the test
  directory, so the BIRD service can be stopped.
* pppd, rp-pppoe and xl2tpd (Debian/Ubuntu packages `ppp`, `pppoe` and
  `xl2tpd`), tests are skipped if not installed unless `BBL_REQUIRE_PPPD`
  or `BBL_REQUIRE_XL2TPD` is set. Without installing, the packages can be
  extracted with `dpkg-deb -x` into a directory given by `PPP_ROOT`
  (remove the setuid bit of the extracted pppd). The configuration is
  mounted at `/etc` per test with an overlay in a private mount
  namespace, xl2tpd runs in userspace mode (no kernel L2TP modules).
* Linux kernel with `CONFIG_TCP_MD5SIG` and `CONFIG_TCP_AO` (6.7+),
  tests are skipped otherwise unless `BBL_REQUIRE_TCP_MD5` or
  `BBL_REQUIRE_TCP_AO` is set.

## Run

The tests don't build the BNG Blaster, so rebuild after code changes:

```
cmake --build build
sudo -E python3 -m pytest test/integration
```

Tests marked `slow` wait for long protocol timers (hold timers, LCP
echo timeouts, LSP lifetimes) and are skipped unless `--slow` is given. Only the slow tests run with `--slow -m slow`
(GitHub workflow "Integration (slow)", started manually):

```
sudo -E python3 -m pytest test/integration --slow -m slow
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
default `/usr/lib/frr`), `VTYSH_BIN`, `BIRD_BIN` and `BIRDC_BIN`, or the build directory,
`~/go/bin` of the invoking user (also with sudo) and `PATH`. Test artifacts are kept in `tmp/integration`
(owned by the invoking user after sudo runs) unless `--basetemp` is set.

Alternatively configure CMake with `-DBNGBLASTER_INTEGRATION_TESTS=ON`
and run `sudo -E ctest -L integration`.
