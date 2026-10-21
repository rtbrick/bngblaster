"""
BNG Blaster AF_XDP instances started at the same time

Two instances use the two ends of a veth pair in the same namespace.
libbpf < 1.0 probes BPF link support by attaching a program to the
loopback interface, which fails if another process probes at the same
time. The program is then attached via netlink, which the next queue
of this instance refuses and which remained attached after exit. The
startup lock initializes instances one after another, and a program
left behind by an instance is detached on exit.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest

from helpers import BNGBLASTER_BIN, BngBlaster

EXIT_TIMEOUT = 30
IF1 = "xsk1"
IF2 = "xsk2"


@pytest.fixture
def af_xdp():
    version = subprocess.run([str(BNGBLASTER_BIN), "-v"], capture_output=True, text=True).stdout
    if "af_xdp" not in version:
        pytest.skip("BNG Blaster built without AF_XDP")


@pytest.fixture
def veth(local_veth):
    """veth pair with both ends in one namespace and two queues each,
    as AF_XDP uses separate RX and TX queues."""
    ns = local_veth.ns
    ns.exec(["ip", "link", "add", IF1, "numtxqueues", "2", "numrxqueues", "2", "type", "veth",
             "peer", "name", IF2, "numtxqueues", "2", "numrxqueues", "2"])
    for ifname in (IF1, IF2):
        ns.exec(["sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % ifname])
        ns.exec(["ip", "link", "set", ifname, "up"])
    return ns


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
def test_parallel_start(af_xdp, veth, tmp_path, processes, round):
    instances = [BngBlaster(veth, tmp_path, "bbl%d" % i) for i in (1, 2)]
    processes.extend(instances)
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(instance.start, instance_config(ifname, i + 1),
                               ("info", "af_xdp"))
                   for i, (instance, ifname) in enumerate(zip(instances, (IF1, IF2)))]
        for future in futures:
            future.result()
    for instance in instances:
        assert instance.terminate(EXIT_TIMEOUT) == 0
    # The log file is written completely once the instance exited.
    for instance in instances:
        with open(instance.path("log")) as f:
            log = f.read()
        assert "queue 0 bound" in log and "queue 1 bound" in log
    for ifname in (IF1, IF2):
        assert not xdp_attached(veth, ifname), "XDP program left on %s" % ifname
