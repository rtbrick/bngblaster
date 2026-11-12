"""
BNG Blaster PCAP capture to a FIFO

A listener which goes away (EPIPE) is replaced by the next listener,
which gets a new section header before the packets.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import time

import pytest

from helpers import BngBlaster

EXIT_TIMEOUT = 30
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


def read_fifo(path, duration):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    data = b""
    deadline = time.time() + duration
    while time.time() < deadline:
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            chunk = b""
        data += chunk
        time.sleep(0.05)
    os.close(fd)
    return data


@pytest.mark.full
def test_fifo_listener_restart(topology, processes, tmp_path):
    fifo = str(tmp_path / "capture.fifo")
    os.mkfifo(fifo)
    os.chmod(fifo, 0o666)
    instance = BngBlaster(topology.a, tmp_path, "bbl").start(
        {"interfaces": {"network": [{"interface": topology.if_a, "address": "192.0.2.10/24",
                                     "gateway": "192.0.2.1", "gateway-resolve-wait": False}]}},
        args=("-P", fifo))
    processes.append(instance)
    first = read_fifo(fifo, 3)
    assert first.startswith(PCAPNG_SHB), first[:16]
    # The BNG Blaster gets EPIPE with the next packet (ARP every second).
    time.sleep(3)
    second = read_fifo(fifo, 4)
    assert second.startswith(PCAPNG_SHB), second[:16]
    assert instance.terminate(EXIT_TIMEOUT) == 0
