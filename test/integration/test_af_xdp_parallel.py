"""
BNG Blaster AF_XDP on veth

Instances started at the same time: two instances use the two ends of a
veth pair in the same namespace.
libbpf < 1.0 probes BPF link support by attaching a program to the
loopback interface, which fails if another process probes at the same
time. The program is then attached via netlink, which the next queue
of this instance refuses and which remained attached after exit. The
startup lock initializes instances one after another, and a program
left behind by an instance is detached on exit.

veth has no RSS indirection table and receives on the TX queue index of
the peer, so AF_XDP binds the TX queues for RX as well. The NIC
configuration changed by AF_XDP (channels, RX VLAN offload) is restored
on exit, also after a killed instance by the next instance.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest

from helpers import BNGBLASTER_BIN, BngBlaster, wait_until

EXIT_TIMEOUT = 30


@pytest.fixture
def af_xdp():
    version = subprocess.run([str(BNGBLASTER_BIN), "-v"], capture_output=True, text=True).stdout
    if "af_xdp" not in version:
        pytest.skip("BNG Blaster built without AF_XDP")


def instance_config(ifname, index):
    return {
        "interfaces": {
            "io-mode": "af_xdp",
            "network": [
                {"interface": ifname, "address": "10.%d.0.1/24" % index,
                 "gateway": "10.%d.0.2" % index}
            ]
        }
    }


def xdp_attached(ns, ifname):
    return "prog/xdp" in ns.exec(["ip", "-d", "link", "show", ifname])


@pytest.mark.parametrize("round", range(5))
def test_parallel_start(af_xdp, local_veth, tmp_path, processes, round):
    veth = veth_queues(local_veth, 2)
    ifnames = (veth.if1, veth.if2)
    instances = [BngBlaster(veth.ns, tmp_path, "bbl%d" % i) for i in (1, 2)]
    processes.extend(instances)
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(instance.start, instance_config(ifname, i + 1),
                               ("info", "af_xdp"))
                   for i, (instance, ifname) in enumerate(zip(instances, ifnames))]
        for future in futures:
            future.result()
    for instance in instances:
        assert instance.terminate(EXIT_TIMEOUT) == 0
    # The log file is written completely once the instance exited.
    for instance in instances:
        with open(instance.path("log")) as f:
            log = f.read()
        assert "queue 0 bound" in log and "queue 1 bound" in log
    for ifname in ifnames:
        assert not xdp_attached(veth.ns, ifname), "XDP program left on %s" % ifname


def veth_queues(local_veth, queues):
    """Recreate the veth pair of local_veth (unique names) with queues."""
    ns = local_veth.ns
    ns.exec(["ip", "link", "del", local_veth.if1])
    ns.exec(["ip", "link", "add", local_veth.if1, "numtxqueues", str(queues), "numrxqueues", str(queues),
             "type", "veth", "peer", "name", local_veth.if2,
             "numtxqueues", str(queues), "numrxqueues", str(queues)])
    for ifname in (local_veth.if1, local_veth.if2):
        ns.exec(["sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % ifname])
        ns.exec(["ip", "link", "set", ifname, "up"])
    return local_veth


def nic_state(ns, ifname):
    """Current RX/TX channels and RX VLAN offload."""
    out = ns.exec(["ethtool", "-l", ifname]).split("Current hardware settings:")[1]
    channels = tuple(int(line.split()[1]) for line in out.splitlines() if line.startswith(("RX:", "TX:")))
    rxvlan = "rx-vlan-offload: on" in ns.exec(["ethtool", "-k", ifname])
    return channels, rxvlan


def state_file(ifname):
    return "/run/lock/bngblaster_%s.af_xdp" % ifname


def stream_config(link, ends):
    """Network interfaces and streams towards the other end of the pair
    for the given (ifname, index) ends."""
    network = []
    streams = []
    for ifname, index in ends:
        peer = 3 - index
        network.append({"interface": ifname, "address": "10.0.0.%d/24" % index, "gateway": "10.0.0.%d" % peer})
        streams.append({"name": "S%d" % index, "type": "ipv4", "direction": "downstream", "pps": 100,
                        "network-interface": ifname, "destination-ipv4-address": "10.0.0.%d" % peer})
    return {"interfaces": {"io-mode": "af_xdp", "links": [dict({"interface": i}, **link) for i, _ in ends],
                           "network": network},
            "traffic": {"autostart": True},
            "streams": streams}


def streams_received(instance, count):
    for stream in instance.ctrl("stream-summary")["stream-summary"]:
        info = instance.ctrl("stream-info", **{"flow-id": stream["flow-id"]})["stream-info"]
        if info["rx-packets"] < count:
            return False
    return True


THREADS = pytest.mark.parametrize("link", [{}, {"rx-threads": 1, "tx-threads": 1}], ids=["main", "threads"])


@THREADS
def test_back_to_back(af_xdp, local_veth, tmp_path, processes, link):
    """Two instances on the two ends of a veth pair exchange stream
    packets, which arrive on the TX queue of the other instance."""
    veth = veth_queues(local_veth, 2)
    instances = [BngBlaster(veth.ns, tmp_path, "bbl%d" % i) for i in (1, 2)]
    processes.extend(instances)
    for index, (instance, ifname) in enumerate(zip(instances, (veth.if1, veth.if2)), 1):
        instance.start(stream_config(link, [(ifname, index)]), ("info", "af_xdp"))
    wait_until(lambda: all(streams_received(i, 200) for i in instances), 20, message="stream packets received")
    for instance in instances:
        assert instance.terminate(EXIT_TIMEOUT) == 0


@THREADS
def test_both_ends_restore(af_xdp, local_veth, tmp_path, processes, link):
    """One instance on both ends of a veth pair with 4 queues exchanges
    stream packets and restores the channels of both ends on exit."""
    veth = veth_queues(local_veth, 4)
    instance = BngBlaster(veth.ns, tmp_path)
    processes.append(instance)
    instance.start(stream_config(link, [(veth.if1, 1), (veth.if2, 2)]), ("info", "af_xdp"))
    assert nic_state(veth.ns, veth.if1) == ((2, 2), False)
    wait_until(lambda: streams_received(instance, 200), 20, message="stream packets received")
    assert instance.terminate(EXIT_TIMEOUT) == 0
    for ifname in (veth.if1, veth.if2):
        assert nic_state(veth.ns, ifname) == ((4, 4), True), ifname
        assert not xdp_attached(veth.ns, ifname), "XDP program left on %s" % ifname
        assert not os.path.exists(state_file(ifname))


def test_restore_after_kill(af_xdp, local_veth, tmp_path, processes):
    """The NIC configuration left behind by a killed instance is restored
    by the next instance on exit."""
    veth = veth_queues(local_veth, 4)
    config = stream_config({}, [(veth.if1, 1)])
    try:
        killed = BngBlaster(veth.ns, tmp_path, "killed")
        processes.append(killed)
        killed.start(config, ("info", "af_xdp"))
        killed.proc.kill()
        killed.proc.wait(EXIT_TIMEOUT)
        assert nic_state(veth.ns, veth.if1) == ((2, 2), False)

        instance = BngBlaster(veth.ns, tmp_path)
        processes.append(instance)
        instance.start(config, ("info", "af_xdp"))
        assert instance.terminate(EXIT_TIMEOUT) == 0
        assert nic_state(veth.ns, veth.if1) == ((4, 4), True)
        assert not xdp_attached(veth.ns, veth.if1), "XDP program left on %s" % veth.if1
        assert not os.path.exists(state_file(veth.if1))
    finally:
        if os.path.exists(state_file(veth.if1)):
            os.unlink(state_file(veth.if1))


@pytest.mark.parametrize("tamper", ["mode", "owner", "symlink"])
def test_untrusted_state_file(af_xdp, local_veth, tmp_path, processes, tamper):
    """A state file in the world-writable lock directory, which might be
    written by another user (writable by others, other owner or symbolic
    link), is ignored and the NIC configuration found is restored."""
    veth = veth_queues(local_veth, 4)
    config = stream_config({}, [(veth.if1, 1)])
    path = state_file(veth.if1)
    ifindex = int(veth.ns.exec(["cat", "/sys/class/net/%s/ifindex" % veth.if1]))
    planted = str(tmp_path / "planted.af_xdp") if tamper == "symlink" else path
    try:
        with open(planted, "w") as f:
            f.write("ifindex %d\nchannels 0 1 1 0\nxdp 0\nend\n" % ifindex)
        os.chmod(planted, 0o600)
        if tamper == "symlink":
            os.symlink(planted, path)
        else:
            if tamper == "mode":
                os.chmod(path, 0o666)
            else:
                os.chown(path, 65534, 65534)
        instance = BngBlaster(veth.ns, tmp_path)
        processes.append(instance)
        instance.start(config, ("info", "af_xdp"))
        assert instance.terminate(EXIT_TIMEOUT) == 0
        with open(instance.path("log")) as f:
            log = f.read()
        assert "ignores NIC configuration" in log
        assert nic_state(veth.ns, veth.if1) == ((4, 4), True)
        assert not os.path.lexists(path)
    finally:
        if os.path.lexists(path):
            os.unlink(path)
