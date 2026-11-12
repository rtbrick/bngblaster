"""
lspgen command line

Invalid option values are rejected, and lspgen exits with failure if
the output is incomplete or was not written. An explicit sequence
number takes precedence over the sequence cache and the config file.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import subprocess

import pytest

from helpers import LSPGEN_BIN, lspgen


def lspgen_rc(args, cwd):
    result = subprocess.run([str(LSPGEN_BIN)] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=120, cwd=str(cwd))
    return result.returncode, result.stdout


@pytest.mark.parametrize("args", [
    ["-P", "ospf2", "-a", "1.2.3.999"],
    ["-a", "49.0001/24", "-a", "49.0002/24", "-a", "49.0003/24", "-a", "49.0004/24"],
    ["-n", "garbage"],
    ["-n", "1.2.3.4/40"],
    ["-N", "fc00::1/129"],
    ["-l", "x"],
    ["-L", "x"],
    ["-x", "1.2.3.4/33"],
    ["-X", "zz::"],
    ["-K", "key", "-T", "bogus"],
    ["-q", "zzz"],
    ["-q", "0"],
    ["-q", "0x100000000"],
    ["-P", "ospf2", "-q", "0x80000000"],
    ["-s", "abc"],
    ["-V", "2x"],
    ["-r", "in.json", "-w", "out.json"],
    ["-w", "out.json", "-r", "in.json"],
    ["-P", "ospf3", "-P", "isis"],
    ["-C", "0000.0000.0000.0000.0001"],
    ["-P", "ospf2", "-C", "10.0.0.1"],
], ids=["ospf-area", "isis-areas", "node-prefix", "node-prefix-len", "node-prefix6", "link-prefix",
        "link-prefix6", "ext-prefix", "ext-prefix6", "auth-type", "sequence", "sequence-zero",
        "sequence-range", "sequence-ospf", "seed", "level", "read-write", "write-read",
        "protocol-twice", "isis-connector", "ospf-connector"])
def test_lspgen_invalid_option(tmp_path, args):
    rc, output = lspgen_rc(args + ["-c", "5", "-m", "out.mrt"], tmp_path)
    assert rc != 0, output
    assert not (tmp_path / "out.mrt").exists()
    assert not (tmp_path / "out.json").exists()


@pytest.mark.parametrize("args", [
    ["-m", "/nonexistent/x.mrt"],
    ["-m", "/dev/full"],
    ["-p", "/nonexistent/x.pcap"],
    ["-f", "/dev/full"],
    ["-w", "/nonexistent/x.json"],
    ["-g", "/nonexistent/x"],
], ids=["mrt-open", "mrt-write", "pcap-open", "stream-write", "config-open", "graphviz-open"])
def test_lspgen_file_error(tmp_path, args):
    rc, output = lspgen_rc(["-c", "5"] + args, tmp_path)
    assert rc != 0, output


@pytest.mark.parametrize("args", [
    ["-c", "5", "-e", "50000", "-b", "512"],
    ["-P", "ospf2", "-c", "20", "-u", "150"],
], ids=["isis-fragments", "ospf2-router-lsa"])
def test_lspgen_truncated(tmp_path, args):
    rc, output = lspgen_rc(args + ["-m", "out.mrt"], tmp_path)
    assert rc != 0, output


def sequences(path):
    config = json.loads(path.read_text())
    nodes = [n for v in config.values() if isinstance(v, list) for n in v]
    return {int(n["sequence"], 16) for n in nodes}


@pytest.mark.parametrize("protocol,initial", [("isis", 1), ("ospf2", 0x80000001)])
def test_lspgen_sequence_option(tmp_path, protocol, initial):
    args = ["-P", protocol, "-c", "5", "-w", "out.json"]
    lspgen(args, cwd=str(tmp_path))
    assert sequences(tmp_path / "out.json") == {initial}
    lspgen(args, cwd=str(tmp_path))
    assert sequences(tmp_path / "out.json") == {initial + 1}

    # An explicit sequence wins over the cache.
    lspgen(args + ["-q", "100"], cwd=str(tmp_path))
    assert sequences(tmp_path / "out.json") == {100}
    lspgen(args, cwd=str(tmp_path))
    assert sequences(tmp_path / "out.json") == {101}

    # An exhausted sequence is not cached.
    maximum = 0xffffffff if protocol == "isis" else 0x7fffffff
    lspgen(args + ["-q", str(maximum)], cwd=str(tmp_path))
    assert sequences(tmp_path / "out.json") == {maximum}
    lspgen(args, cwd=str(tmp_path))
    assert sequences(tmp_path / "out.json") == {initial}


@pytest.mark.parametrize("protocol", ["isis", "ospf2", "ospf3"])
def test_lspgen_sequence_config_file(tmp_path, protocol):
    lspgen(["-P", protocol, "-c", "5", "-w", "topo.json"], cwd=str(tmp_path))
    for cache in tmp_path.glob("*-sequence-cache.json"):
        cache.unlink()
    # The cache holds the sequence of the emitted link state packets.
    args = ["-P", protocol, "-r", "topo.json", "-m", "out.mrt"]

    # An explicit sequence wins over the config file.
    lspgen(args + ["-q", "5"], cwd=str(tmp_path))
    cache, = tmp_path.glob("*-sequence-cache.json")
    assert sequences(cache) == {5}
    lspgen(args, cwd=str(tmp_path))
    assert sequences(cache) == {6}

    # A higher sequence in the config file wins over the cache.
    config = json.loads((tmp_path / "topo.json").read_text())
    for nodes in config.values():
        if isinstance(nodes, list):
            for node in nodes:
                node["sequence"] = "0x00000064"
    (tmp_path / "topo.json").write_text(json.dumps(config))
    lspgen(args, cwd=str(tmp_path))
    assert sequences(cache) == {100}
    lspgen(args, cwd=str(tmp_path))
    assert sequences(cache) == {101}
