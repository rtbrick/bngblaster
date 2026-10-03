"""
BNG Blaster BGP TCP-AO (RFC 5925) against GoBGP (Linux kernel TCP-AO)

The KeyIDs are asymmetric to verify the SendID/RecvID mapping: the
BNG Blaster sends KeyID 1 and expects RNextKeyID/RecvID 2 from GoBGP.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import pytest

from bgp_common import BgpSetup

KEY = "BNGBlasterTCPAOKey0123456789abcd"
ALGORITHMS = ["hmac-sha-1-96", "aes-128-cmac-96", "hmac-sha-256-128"]

pytestmark = pytest.mark.usefixtures("gobgp_bin", "tcp_ao_kernel")


@pytest.fixture
def bgp(topology, processes, tmp_path):
    return BgpSetup(topology, processes, tmp_path)


def gobgp_ao(algorithm, key=KEY, send_id=2, receive_id=1):
    return {"algorithm": algorithm, "key": key, "send_id": send_id, "receive_id": receive_id}


def bbl_ao(algorithm, key=KEY, key_id=1, rnext_key_id=2):
    return {
        "tcp-ao-algorithm": algorithm,
        "tcp-ao-key": key,
        "tcp-ao-key-id": key_id,
        "tcp-ao-rnext-key-id": rnext_key_id,
    }


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_tcp_ao(bgp, algorithm):
    bgp.start(gobgp={"ao": gobgp_ao(algorithm)}, bbl={"bgp": bbl_ao(algorithm)})
    bgp.wait_established()
    assert bgp.bbl_session()["tcp-auth"] == algorithm
    bgp.teardown()


@pytest.mark.parametrize("gobgp,bbl", [
    ({"ao": gobgp_ao("hmac-sha-1-96", key="WrongKey0123456789ab")}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("hmac-sha-1-96", receive_id=3)}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("hmac-sha-1-96", send_id=3)}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("aes-128-cmac-96")}, {"bgp": bbl_ao("hmac-sha-1-96")}),
    ({"ao": gobgp_ao("hmac-sha-1-96")}, {}),
    ({}, {"bgp": bbl_ao("hmac-sha-1-96")}),
], ids=["wrong-key", "wrong-recv-id", "wrong-send-id", "wrong-algorithm", "gobgp-only", "bbl-only"])
def test_tcp_ao_mismatch(bgp, gobgp, bbl):
    bgp.start(gobgp=gobgp, bbl=bbl)
    bgp.assert_not_established()
    bgp.teardown()

