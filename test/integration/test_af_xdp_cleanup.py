"""AF_XDP shutdown must leave reusable interfaces, including on repeated runs."""
import json
import re
import subprocess

import pytest

from helpers import BNGBLASTER_BIN, BngBlaster, run, wait_until


@pytest.fixture(autouse=True)
def require_af_xdp():
    if "af_xdp" not in run([BNGBLASTER_BIN, "-v"]):
        pytest.skip("requires AF_XDP-enabled build")


def config_for(interface):
    return {
        "interfaces": {
            "io-mode": "af_xdp",
            "rx-threads": 1,
            "tx-threads": 1,
            "links": [{"interface": interface, "io-slots-rx": 8192}],
            "network": [{
                "interface": interface,
                "address": "192.0.2.1/24",
                "gateway": "192.0.2.2",
            }],
        }
    }


def link_info(ns, interface):
    return json.loads(run(ns.cmd(["ip", "-j", "-d", "link", "show", "dev", interface])))[0]


def test_af_xdp_repeated_cleanup(local_veth, processes, tmp_path):
    config = config_for(local_veth.if1)
    before = link_info(local_veth.ns, local_veth.if1)
    features = run(local_veth.ns.cmd(["ethtool", "-k", local_veth.if1]))
    channels = run(local_veth.ns.cmd(["ethtool", "-l", local_veth.if1]))
    for iteration in range(2):
        instance = BngBlaster(local_veth.ns, tmp_path, name=f"xdp-{iteration}")
        processes.append(instance)
        instance.start(config)
        wait_until(lambda: link_info(local_veth.ns, local_veth.if1).get("xdp", {}).get("prog"),
                   10, message="XDP program attached")
        assert instance.terminate() == 0
        after = link_info(local_veth.ns, local_veth.if1)
        assert not after.get("xdp", {}).get("prog")
        assert after["mtu"] == before["mtu"]
        assert after["promiscuity"] == before["promiscuity"]
        assert run(local_veth.ns.cmd(["ethtool", "-k", local_veth.if1])) == features
        assert run(local_veth.ns.cmd(["ethtool", "-l", local_veth.if1])) == channels


def run_failed_config(ns, tmp_path, config):
    path = tmp_path / "failed.json"
    path.write_text(json.dumps(config))
    result = subprocess.run(ns.cmd([BNGBLASTER_BIN, "-C", str(path), "-b", "-f"]),
                            capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    return result.stdout + result.stderr


def test_af_xdp_preserves_existing_program(local_veth, processes, tmp_path):
    config = config_for(local_veth.if1)
    owner = BngBlaster(local_veth.ns, tmp_path, name="owner")
    processes.append(owner)
    owner.start(config)
    program = link_info(local_veth.ns, local_veth.if1)["xdp"]["prog"]["id"]
    output = run_failed_config(local_veth.ns, tmp_path, config)
    assert "refusing to replace" in output
    assert owner.alive()
    assert link_info(local_veth.ns, local_veth.if1)["xdp"]["prog"]["id"] == program
    assert owner.terminate() == 0
    assert not link_info(local_veth.ns, local_veth.if1).get("xdp", {}).get("prog")


def test_af_xdp_partial_init_cleanup(local_veth, tmp_path):
    channels = run(local_veth.ns.cmd(["ethtool", "-l", local_veth.if2]))
    maximum = int(re.search(r"(?:Combined|RX):\s+(\d+)", channels)[1])
    if maximum >= 254:
        pytest.skip("cannot exceed queue limit with supported thread count")
    config = config_for(local_veth.if1)
    config["interfaces"]["links"].append({
        "interface": local_veth.if2, "io-slots-rx": 8192, "rx-threads": maximum,
        "tx-threads": 1,
    })
    config["interfaces"]["network"].append({
        "interface": local_veth.if2, "address": "198.51.100.1/24",
        "gateway": "198.51.100.2",
    })
    features = run(local_veth.ns.cmd(["ethtool", "-k", local_veth.if1]))
    output = run_failed_config(local_veth.ns, tmp_path, config)
    assert "only supports up to" in output
    assert not link_info(local_veth.ns, local_veth.if1).get("xdp", {}).get("prog")
    assert run(local_veth.ns.cmd(["ethtool", "-k", local_veth.if1])) == features
