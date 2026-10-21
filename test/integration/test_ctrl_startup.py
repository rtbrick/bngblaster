"""
BNG Blaster control socket during the startup

The control socket is opened before the startup, so that a controller
can follow the startup with test-info (status and current task), while
other commands are rejected until the startup is completed. The test
holds the startup lock itself to keep the instance in its startup.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import fcntl
import os
import signal
from contextlib import contextmanager

import pytest

from helpers import BngBlaster, wait_until

STARTUP_LOCK = "/run/lock/bngblaster_startup.lock"
EXIT_TIMEOUT = 30


class Host:
    """Run the BNG Blaster on the host instead of a network namespace."""
    name = "host"

    def cmd(self, cmd):
        return cmd


def loopback_config():
    return {
        "interfaces": {
            "io-mode": "loopback",
            "links": [
                {"interface": "loc1a", "loopback-peer": "loc1b",
                 "tx-threads": 1, "tx-auto-cpuset": True},
                {"interface": "loc1b",
                 "rx-threads": 1, "rx-auto-cpuset": True}
            ],
            "network": [
                {"interface": "loc1a", "address": "10.1.0.1/24", "gateway": "10.1.0.2"},
                {"interface": "loc1b", "address": "10.1.0.2/24", "gateway": "10.1.0.1"}
            ]
        }
    }


def proc_threads(pid):
    """Map thread ID to the CPU it is pinned to (None if not pinned)."""
    threads = {}
    for tid in os.listdir("/proc/%d/task" % pid):
        with open("/proc/%d/task/%s/status" % (pid, tid)) as f:
            allowed = [l.split()[1] for l in f if l.startswith("Cpus_allowed_list:")][0]
        threads[int(tid)] = int(allowed) if allowed.isdigit() else None
    return threads


@contextmanager
def startup_lock():
    """Hold the startup lock, which keeps instances in their startup."""
    lock = open(STARTUP_LOCK, "a+")
    fcntl.flock(lock, fcntl.LOCK_EX)
    # The process holding the lock writes its PID into the file.
    lock.seek(0)
    lock.truncate()
    lock.write("%d\n" % os.getpid())
    lock.flush()
    try:
        yield
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def test_startup_status(tmp_path, processes):
    with startup_lock():
        instance = BngBlaster(Host(), tmp_path, "bbl")
        processes.append(instance)
        instance.start(loopback_config(), wait_started=False)
        info = wait_until(lambda: instance.ctrl("test-info")["test-info"], 10,
                          message="test-info while starting")
        assert info["status"] == "starting"
        assert info["task"] == "wait-startup-lock"
        assert info["startup-lock-pid"] == os.getpid()
        assert info["pid"] == instance.proc.pid
        assert info["duration"] == 0
        for command in ("session-counters", "threads"):
            response = instance.ctrl(command)
            assert (response["code"], response["message"]) == (503, "not available while starting")

    wait_until(lambda: instance.ctrl("test-info")["test-info"]["status"] == "running", 10,
               message="instance running")
    info = instance.ctrl("test-info")["test-info"]
    assert info["task"] in ("running", "resolve-gateways")
    assert "startup-lock-pid" not in info

    threads = instance.ctrl("threads")["threads"]
    assert sorted(t["name"] for t in threads) == ["main", "rx0-loc1b", "tx0-loc1a"]
    pinned = proc_threads(instance.proc.pid)
    for thread in threads:
        assert thread["cpu-auto"], thread
        assert thread["cpu"] is not None, thread
        assert pinned[thread["tid"]] == thread["cpu"], thread
    assert len({t["cpu"] for t in threads}) == len(threads)

    assert instance.terminate(EXIT_TIMEOUT) == 0


@pytest.mark.parametrize("stop", ["terminate", "test-stop", "SIGTERM", "SIGINT"])
def test_abort_startup(tmp_path, processes, stop):
    """A teardown requested while waiting for the startup lock aborts the
    startup with a clean exit, without waiting for the lock."""
    with startup_lock():
        instance = BngBlaster(Host(), tmp_path, "bbl")
        processes.append(instance)
        instance.start(loopback_config(), wait_started=False)
        wait_until(lambda: instance.ctrl("test-info")["test-info"]["task"] == "wait-startup-lock",
                   10, message="waiting for startup lock")
        if stop.startswith("SIG"):
            instance.proc.send_signal(getattr(signal, stop))
        else:
            response = instance.ctrl(stop)
            assert (response["code"], response["message"]) == (200, "teardown requested")
        # Exit status 3 for an aborted startup.
        assert instance.proc.wait(timeout=10) == 3
    with open(instance.path("log")) as f:
        assert "Startup aborted by teardown request" in f.read()
