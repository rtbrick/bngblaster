"""
BGP RAW update generator (bgpupdate) output

Decodes the generated update files without a BGP peer.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import struct
import subprocess
import sys

import pytest

import helpers
from helpers import bgpupdate

ATTR_ORIGIN, ATTR_AS_PATH, ATTR_NEXT_HOP, ATTR_MED, ATTR_LOCAL_PREF = 1, 2, 3, 4, 5
ATTR_MP_REACH, ATTR_MP_UNREACH, ATTR_EXT_COMMUNITIES = 14, 15, 16


def decode_labeled(data):
    """Return (label field, prefix length) of labeled NLRI."""
    routes = []
    while data:
        plen = data[0] - 24
        routes.append((int.from_bytes(data[1:4], "big"), plen))
        data = data[4 + (plen + 7) // 8:]
    return routes


def decode(path):
    """Return a list of updates, each a dict with the path attributes
    in order as (type, value) and the withdrawn and NLRI bytes."""
    with open(path, "rb") as f:
        data = f.read()
    updates = []
    while data:
        assert data[:16] == b"\xff" * 16
        length, msg_type = struct.unpack("!HB", data[16:19])
        assert msg_type == 2 and length <= 4096
        body, data = data[19:length], data[length:]
        withdrawn_len = struct.unpack("!H", body[:2])[0]
        withdrawn, body = body[2:2 + withdrawn_len], body[2 + withdrawn_len:]
        attr_len = struct.unpack("!H", body[:2])[0]
        attrs, nlri = body[2:2 + attr_len], body[2 + attr_len:]
        update = {"attrs": [], "withdrawn": withdrawn, "nlri": nlri}
        while attrs:
            flags, code = attrs[0], attrs[1]
            if flags & 0x10:
                value_len, hdr = struct.unpack("!H", attrs[2:4])[0], 4
            else:
                value_len, hdr = attrs[2], 3
            update["attrs"].append((code, attrs[hdr:hdr + value_len]))
            attrs = attrs[hdr + value_len:]
        updates.append(update)
    return updates


def codes(update):
    return [code for code, _ in update["attrs"]]


def attr(update, code):
    return next(value for c, value in update["attrs"] if c == code)


def end_of_rib(update, afi=None, safi=None):
    """IPv4 unicast End-of-RIB is an empty update, other families use
    an empty MP_UNREACH_NLRI (RFC 4724 section 2)."""
    if afi is None:
        return update == {"attrs": [], "withdrawn": b"", "nlri": b""}
    return update["attrs"] == [(ATTR_MP_UNREACH, struct.pack("!HB", afi, safi))] and not update["nlri"]


@pytest.mark.parametrize("args, order", [
    (["-n", "10.0.0.1", "-p", "10.0.0.0/24"],
     [ATTR_ORIGIN, ATTR_AS_PATH, ATTR_NEXT_HOP, ATTR_MED, ATTR_LOCAL_PREF]),
    (["-n", "10.0.0.1", "-p", "10.0.0.0/24", "-m", "100"],
     [ATTR_MP_REACH, ATTR_ORIGIN, ATTR_AS_PATH, ATTR_MED, ATTR_LOCAL_PREF]),
    (["-n", "fc00::1", "-p", "fc00:1::/64"],
     [ATTR_MP_REACH, ATTR_ORIGIN, ATTR_AS_PATH, ATTR_MED, ATTR_LOCAL_PREF]),
    (["-n", "10.0.0.1", "--l2vpn", "--rd", "1:1", "--rt", "1:1", "--label-base", "100"],
     [ATTR_MP_REACH, ATTR_ORIGIN, ATTR_AS_PATH, ATTR_MED, ATTR_LOCAL_PREF, ATTR_EXT_COMMUNITIES]),
], ids=["ipv4", "ipv4-labeled", "ipv6", "l2vpn"])
def test_attribute_order(tmp_path, args, order):
    """MP_REACH_NLRI first (RFC 7606 section 5.1), the others ordered
    by type code (RFC 4271 section 5)."""
    path = str(tmp_path / "update.bgp")
    bgpupdate(["-f", path, "-a", "65001", "-l", "100", "--med", "10"] + args)
    updates = decode(path)
    assert len(updates) == 1
    assert codes(updates[0]) == order


def test_as_path_empty(tmp_path):
    """Without -a the AS_PATH is empty instead of an empty segment."""
    path = str(tmp_path / "update.bgp")
    bgpupdate(["-f", path, "-n", "10.0.0.1", "-p", "10.0.0.0/24", "-P", "2"])
    assert attr(decode(path)[0], ATTR_AS_PATH) == b""
    bgpupdate(["-f", path, "-a", "65001", "-a", "65002", "-n", "10.0.0.1", "-p", "10.0.0.0/24"])
    assert attr(decode(path)[0], ATTR_AS_PATH) == struct.pack("!BBII", 2, 2, 65001, 65002)


@pytest.mark.parametrize("args, family", [
    (["-n", "10.0.0.1", "-p", "10.0.0.0/24"], (None, None)),
    (["-n", "10.0.0.1", "-p", "10.0.0.0/24", "-m", "100"], (1, 4)),
    (["-n", "fc00::1", "-p", "fc00:1::/64"], (2, 1)),
    (["-n", "fc00::1", "-p", "fc00:1::/64", "-m", "100"], (2, 4)),
], ids=["ipv4", "ipv4-labeled", "ipv6", "ipv6-labeled"])
def test_end_of_rib(tmp_path, args, family):
    path = str(tmp_path / "update.bgp")
    bgpupdate(["-f", path, "-a", "65001", "-P", "10", "--end-of-rib"] + args)
    updates = decode(path)
    assert len(updates) == 2
    assert not end_of_rib(updates[0], *family)
    assert end_of_rib(updates[1], *family)


@pytest.mark.parametrize("args, afi, plen, count", [
    (["-n", "10.0.0.1", "-p", "10.0.0.0/32"], 1, 32, 3000),
    (["-n", "fc00::1", "-p", "fc00:1::/128"], 2, 128, 3000),
], ids=["ipv4", "ipv6"])
def test_labeled_withdraw(tmp_path, args, afi, plen, count):
    """Labeled withdrawn routes carry the compatibility label 0x800000
    (RFC 8277 section 2.4) and are packed into as few updates as fit."""
    path = str(tmp_path / "withdraw.bgp")
    bgpupdate(["-f", path, "-a", "65001", "-P", str(count), "-m", "100", "-M", "10", "-w"] + args)
    updates = decode(path)
    routes = []
    for update in updates:
        assert codes(update) == [ATTR_MP_UNREACH]
        value = attr(update, ATTR_MP_UNREACH)
        assert struct.unpack("!HB", value[:3]) == (afi, 4)
        routes += decode_labeled(value[3:])
    assert routes == [(0x800000, plen)] * count
    nlri_len = 4 + plen // 8
    assert len(updates) <= -(-count * nlri_len // 3900)


def test_l2vpn_route_too_large(tmp_path):
    """A label block whose circuit status vector does not fit into one
    update is rejected without writing any file (it hung before)."""
    path, streams = tmp_path / "update.bgp", tmp_path / "streams.json"
    cmd = ["-f", str(path), "-s", str(streams), "-a", "65001", "-n", "10.0.0.1",
           "--l2vpn", "--rd", "1:1", "--rt", "1:1", "--label-base", "100",
           "--stream-l2vpn-ce-id", "2", "--stream-ce-interface", "eth1"]
    result = subprocess.run([sys.executable, helpers.BGPUPDATE_BIN] + cmd + ["--label-block-size", "40000"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
    assert result.returncode == 1
    assert "does not fit into a BGP update message" in result.stdout
    assert not path.exists() and not streams.exists()

    bgpupdate(cmd + ["--label-block-size", "30000"], timeout=20)
    updates = decode(str(path))
    assert codes(updates[0])[0] == ATTR_MP_REACH
    assert streams.exists()
