"""
BNG Blaster Integration Test Fixtures

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import itertools
import os

import pytest

import helpers
from helpers import BngBlaster, GoBgp, Netns

_ids = itertools.count(1)


def pytest_configure(config):
    """Keep artifacts in the (git ignored) repository tmp directory
    instead of the root-only /tmp/pytest-of-root."""
    if not config.option.basetemp:
        config.option.basetemp = str(helpers.REPO / "tmp/integration")


def pytest_unconfigure(config):
    """Hand artifacts to the invoking user after sudo runs."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    basetemp = config.option.basetemp
    if os.geteuid() == 0 and uid and gid and basetemp and os.path.isdir(basetemp):
        for root, _, files in os.walk(basetemp):
            for name in [root] + [os.path.join(root, f) for f in files]:
                os.lchown(name, int(uid), int(gid))


def pytest_collection_modifyitems(config, items):
    reason = None
    if os.geteuid() != 0:
        reason = "integration tests require root (network namespaces)"
    elif not helpers.BNGBLASTER_BIN:
        reason = "bngblaster binary not found (set BNGBLASTER_BIN)"
    if reason:
        for item in items:
            item.add_marker(pytest.mark.skip(reason=reason))


@pytest.fixture(scope="session", autouse=True)
def netns_cleanup():
    if os.geteuid() == 0:
        helpers.cleanup_netns()
    yield
    if os.geteuid() == 0:
        helpers.cleanup_netns()


def require_kernel(option, env):
    """Skip if the kernel lacks option, or fail if env is set (CI) so that
    a runner image change can't silently disable coverage."""
    if helpers.kernel_config(option) is not False:
        return
    if os.environ.get(env):
        pytest.fail("kernel option %s required (%s is set)" % (option, env))
    pytest.skip("kernel option %s not enabled" % option)


@pytest.fixture
def md5_kernel():
    require_kernel("CONFIG_TCP_MD5SIG", "BBL_REQUIRE_TCP_MD5")


@pytest.fixture
def tcp_ao_kernel():
    require_kernel("CONFIG_TCP_AO", "BBL_REQUIRE_TCP_AO")


@pytest.fixture
def topology(request):
    """Two namespaces A and B connected by veth pair (bbl<n>a <-> bbl<n>b).
    Test artifacts (configs, logs, pcaps, reports) are kept in tmp_path."""
    n = next(_ids)
    ns_a = Netns("%d-a" % n)
    ns_b = Netns("%d-b" % n)
    topo = type("Topology", (), {})()
    topo.a, topo.b = ns_a, ns_b
    topo.if_a, topo.if_b = "bbl%da" % n, "bbl%db" % n
    helpers.veth_pair(ns_a, topo.if_a, ns_b, topo.if_b)
    yield topo
    ns_a.delete()
    ns_b.delete()


@pytest.fixture
def local_veth():
    """One namespace with both ends of a veth pair, as used by a single
    BNG Blaster instance in the quickstart guide."""
    n = next(_ids)
    ns = Netns("%d" % n)
    topo = type("Topology", (), {})()
    topo.ns = ns
    topo.if1, topo.if2 = "bbl%da" % n, "bbl%db" % n
    helpers.veth_pair(ns, topo.if1, ns, topo.if2)
    yield topo
    ns.delete()


@pytest.fixture
def processes():
    """Track started processes and kill leftovers after the test."""
    started = []
    yield started
    for proc in started:
        if isinstance(proc, BngBlaster):
            proc.kill()
        elif isinstance(proc, GoBgp):
            proc.stop()


@pytest.fixture
def gobgp_bin():
    if not (helpers.GOBGPD_BIN and helpers.GOBGP_BIN):
        pytest.skip("gobgpd/gobgp not found (set GOBGPD_BIN and GOBGP_BIN)")
    version = helpers.gobgp_version(helpers.GOBGPD_BIN)
    if not version or version < helpers.GOBGP_MIN_VERSION:
        pytest.fail("%s version %s too old, GoBGP >= %s with TCP-AO required" % (
            helpers.GOBGPD_BIN, version, ".".join(map(str, helpers.GOBGP_MIN_VERSION))))
