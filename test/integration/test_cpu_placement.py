"""
BNG Blaster automatic CPU placement of instances running in parallel

The instances use loopback links, which require neither network
namespaces nor real interfaces, and run directly on the host. They
coordinate their CPUs with lock files in /run/lock, so instances
started at the same time must not select the same CPU.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import re
import signal
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import pytest

from helpers import BngBlaster, wait_until

LOCK_DIR = "/run/lock"
LOCK_FILE = re.compile(r"^bngblaster_cpu(\d+)\.(\d+)\.lock$")
EXIT_TIMEOUT = 30


class Host:
    """Run the BNG Blaster on the host instead of a network namespace."""
    name = "host"

    def cmd(self, cmd):
        return cmd


def instance_config(index):
    """Two loopback links with one TX and one RX thread, which are
    placed automatically like the main thread (three CPUs)."""
    link_a = "lo%da" % index
    link_b = "lo%db" % index
    return {
        "interfaces": {
            "io-mode": "loopback",
            "links": [
                {"interface": link_a, "loopback-peer": link_b,
                 "tx-threads": 1, "tx-auto-cpuset": True},
                {"interface": link_b,
                 "rx-threads": 1, "rx-auto-cpuset": True}
            ],
            "network": [
                {"interface": link_a, "address": "10.%d.0.1/24" % index,
                 "gateway": "10.%d.0.2" % index},
                {"interface": link_b, "address": "10.%d.0.2/24" % index,
                 "gateway": "10.%d.0.1" % index}
            ]
        }
    }


def pinned_cpus(instance):
    """Map thread name to CPU of all threads pinned to a single CPU."""
    pinned = {}
    task_dir = "/proc/%d/task" % instance.proc.pid
    for tid in os.listdir(task_dir):
        try:
            with open("%s/%s/comm" % (task_dir, tid)) as f:
                name = f.read().strip()
            with open("%s/%s/status" % (task_dir, tid)) as f:
                allowed = [l.split()[1] for l in f if l.startswith("Cpus_allowed_list:")][0]
        except OSError:
            continue
        if allowed.isdigit():
            pinned[name] = int(allowed)
    return pinned


def lock_files():
    """Map PID to the CPUs locked by this process."""
    locks = {}
    for name in os.listdir(LOCK_DIR):
        match = LOCK_FILE.match(name)
        if match:
            locks.setdefault(int(match.group(2)), set()).add(int(match.group(1)))
    return locks


def available_cpus():
    return len(os.sched_getaffinity(0))


def start_parallel(tmp_path, processes, indexes, name="bbl"):
    """Start instances at the same time and wait until all I/O threads
    are pinned to their CPUs."""
    indexes = list(indexes)
    instances = [BngBlaster(Host(), tmp_path, "%s%d" % (name, i)) for i in indexes]
    processes.extend(instances)
    with ThreadPoolExecutor(len(instances)) as pool:
        list(pool.map(lambda pair: pair[0].start(instance_config(pair[1])),
                      zip(instances, indexes)))
    for instance, index in zip(instances, indexes):
        threads = {"rx0-lo%db" % index, "tx0-lo%da" % index}
        wait_until(lambda: threads <= set(pinned_cpus(instance)),
                   10, message="I/O threads of %s pinned" % instance.name)
    return instances


def log(instance):
    with open(instance.path("log")) as f:
        return f.read()


@pytest.mark.parametrize("round", range(10))
def test_parallel_start_disjoint_cpus(tmp_path, processes, round):
    """Instances started at the same time select different CPUs for all
    their threads, including the main thread, while enough CPUs are free.
    Without coordination, the instances select the same CPUs only by
    chance, so the test is repeated."""
    count = available_cpus() // 3
    if count < 2:
        pytest.skip("at least 6 CPUs required")
    instances = start_parallel(tmp_path, processes, range(1, count + 1))

    used = []
    locks = lock_files()
    for instance in instances:
        pinned = pinned_cpus(instance)
        assert "bngblaster" in pinned, "main thread of %s not pinned" % instance.name
        assert locks[instance.proc.pid] == set(pinned.values())
        assert "sharing CPU" not in log(instance)
        used += pinned.values()
    assert len(used) == 3 * count
    assert len(set(used)) == len(used), "CPU selected twice: %s" % used

    for instance in instances:
        assert instance.terminate(EXIT_TIMEOUT) == 0
    locks = lock_files()
    assert not any(instance.proc.pid in locks for instance in instances)


def test_parallel_start_shared_cpus(tmp_path, processes):
    """With more threads than CPUs, the instances share the CPUs evenly."""
    cpus = available_cpus()
    if cpus < 2:
        pytest.skip("at least 2 CPUs required")
    # Two I/O threads per instance for twice as many threads as CPUs.
    instances = start_parallel(tmp_path, processes, range(1, cpus + 1))

    locks = lock_files()
    users = Counter()
    for instance in instances:
        pinned = pinned_cpus(instance)
        assert locks[instance.proc.pid] == set(pinned.values())
        users.update(locks[instance.proc.pid])
    allowed = os.sched_getaffinity(0)
    counts = [users.get(cpu, 0) for cpu in allowed]
    assert max(counts) - min(counts) <= 1, "uneven CPU sharing: %s" % dict(users)
    assert any("sharing CPU" in log(instance) for instance in instances)

    for instance in instances:
        assert instance.terminate(EXIT_TIMEOUT) == 0


def test_killed_instance(tmp_path, processes):
    """CPUs and interfaces of a killed instance are free again, and its
    CPU lock files, which are not locked anymore, are removed by the
    next instance. The next instance uses the same interfaces, whose
    lock files it removes on exit."""
    if available_cpus() < 3:
        pytest.skip("at least 3 CPUs required")
    killed = start_parallel(tmp_path, processes, [1])[0]
    killed_cpus = set(pinned_cpus(killed).values())
    killed.proc.send_signal(signal.SIGKILL)
    killed.proc.wait()
    assert lock_files()[killed.proc.pid] == killed_cpus

    instance = start_parallel(tmp_path, processes, [1], name="next")[0]
    assert set(pinned_cpus(instance).values()) == killed_cpus
    assert "sharing CPU" not in log(instance)
    assert killed.proc.pid not in lock_files()
    assert instance.terminate(EXIT_TIMEOUT) == 0
    assert not {"bngblaster_lo1a.lock", "bngblaster_lo1b.lock"} & set(os.listdir(LOCK_DIR))
