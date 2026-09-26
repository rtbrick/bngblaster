"""
BNG Blaster Integration Test Helpers

Network namespaces, veth pairs, process handling and control
socket client used by the integration tests.

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NETNS_PREFIX = "bbl-it-"


def env_path(name, default):
    """Return binary path from environment, repository build dir or PATH."""
    value = os.environ.get(name)
    if value:
        return value
    if default and Path(default).is_file():
        return str(default)
    return None


def go_bin(name):
    """Prefer go install location of the invoking user, because sudo
    resets PATH and may find an older distribution package instead."""
    home = Path("~%s" % os.environ.get("SUDO_USER", "")).expanduser()
    path = home / "go/bin" / name
    return path if path.is_file() else shutil.which(name)


BNGBLASTER_BIN = env_path("BNGBLASTER_BIN", REPO / "build/code/bngblaster/bngblaster")
BGPUPDATE_BIN = env_path("BGPUPDATE_BIN", REPO / "code/bgpupdate")
LDPUPDATE_BIN = env_path("LDPUPDATE_BIN", REPO / "code/ldpupdate")
LSPGEN_BIN = env_path("LSPGEN_BIN", REPO / "build/code/lspgen/lspgen")
GOBGPD_BIN = env_path("GOBGPD_BIN", go_bin("gobgpd"))
GOBGP_BIN = env_path("GOBGP_BIN", go_bin("gobgp"))
GOBGP_MIN_VERSION = (4, 9)


def run(cmd, check=True, timeout=30):
    """Run command and return stdout."""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError("command %s failed (%d): %s" % (
            " ".join(cmd), result.returncode, result.stderr.strip()))
    return result.stdout


def wait_until(predicate, timeout, interval=0.5, message="condition"):
    """Poll predicate until it returns a truthy value or raise on timeout."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (OSError, RuntimeError, ValueError, KeyError) as e:
            last = e
        time.sleep(interval)
    raise TimeoutError("timeout after %ss waiting for %s (last: %r)" % (timeout, message, last))


def gobgp_version(binary):
    """Return version tuple from 'gobgpd version 4.9.0'."""
    out = run([binary, "--version"], check=False).split()
    try:
        return tuple(int(x) for x in out[-1].split(".")[:2])
    except (IndexError, ValueError):
        return None


def kernel_config(option):
    """Return True if kernel option is enabled (y or m), None if unknown."""
    path = Path("/boot/config-%s" % os.uname().release)
    if not path.is_file():
        return None
    for line in path.read_text().splitlines():
        if line.startswith(option + "="):
            return line.split("=", 1)[1] in ("y", "m")
    return False


def cleanup_netns():
    """Delete all namespaces left over from previous runs."""
    for line in run(["ip", "netns", "list"], check=False).splitlines():
        name = line.split()[0] if line else ""
        if name.startswith(NETNS_PREFIX):
            run(["ip", "netns", "delete", name], check=False)


class Netns:
    """Network namespace with loopback up."""

    def __init__(self, name):
        self.name = NETNS_PREFIX + name
        run(["ip", "netns", "add", self.name])
        self.exec(["ip", "link", "set", "lo", "up"])

    def cmd(self, cmd):
        return ["ip", "netns", "exec", self.name] + cmd

    def exec(self, cmd, check=True, timeout=30):
        return run(self.cmd(cmd), check=check, timeout=timeout)

    def delete(self):
        run(["ip", "netns", "delete", self.name], check=False)


def veth_pair(ns_a, if_a, ns_b, if_b):
    """Create veth pair with one end in each namespace. Interfaces used by
    the BNG Blaster must not answer ARP/ND, so IPv6 is disabled on both
    ends and addresses are added by the caller only where needed."""
    run(["ip", "link", "add", if_a, "type", "veth", "peer", "name", if_b])
    for ns, ifname in ((ns_a, if_a), (ns_b, if_b)):
        run(["ip", "link", "set", ifname, "netns", ns.name])
        ns.exec(["sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % ifname])
        ns.exec(["ip", "link", "set", ifname, "up"])


def kernel_address(ns, ifname, ipv4=None, ipv6=None):
    """Add kernel addresses to an interface (peer side only). TX checksum
    offload is disabled, because veth leaves partial checksums which are
    dropped by the BNG Blaster (raw socket)."""
    ns.exec(["ethtool", "-K", ifname, "tx", "off"])
    if ipv6:
        ns.exec(["sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=0" % ifname])
        ns.exec(["ip", "-6", "addr", "add", ipv6, "dev", ifname, "nodad"])
    if ipv4:
        ns.exec(["ip", "addr", "add", ipv4, "dev", ifname])


class BngBlaster:
    """BNG Blaster instance running in a network namespace."""

    def __init__(self, ns, workdir, name="bngblaster"):
        self.ns = ns
        self.name = name
        self.workdir = Path(workdir)
        self.socket = str(self.workdir / ("%s.sock" % name))
        self.proc = None

    def path(self, suffix):
        return str(self.workdir / ("%s.%s" % (self.name, suffix)))

    def start(self, config, logging=("info",), args=()):
        config_file = self.path("json")
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
        cmd = [BNGBLASTER_BIN, "-C", config_file, "-S", self.socket,
               "-L", self.path("log"), "-P", self.path("pcap"),
               "-J", self.path("report.json"), "-b", "-f"]
        for log in logging:
            cmd += ["-l", log]
        cmd += list(args)
        with open(self.path("stdout"), "w") as out:
            self.proc = subprocess.Popen(self.ns.cmd(cmd), stdout=out,
                                         stderr=subprocess.STDOUT)
        wait_until(lambda: os.path.exists(self.socket) or self.proc.poll() is not None,
                   10, 0.1, "%s control socket" % self.name)
        if self.proc.poll() is not None:
            raise RuntimeError("%s exited on start (%d), see %s" % (
                self.name, self.proc.returncode, self.path("log")))
        return self

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def ctrl(self, command, **arguments):
        """Send control socket command and return the JSON response."""
        request = {"command": command}
        if arguments:
            request["arguments"] = arguments
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect(self.socket)
            client.sendall(json.dumps(request).encode())
            data = b""
            while True:
                chunk = client.recv(65536)
                if not chunk:
                    break
                data += chunk
        finally:
            client.close()
        return json.loads(data.decode())

    def report(self):
        with open(self.path("report.json")) as f:
            return json.load(f)

    def terminate(self, timeout=30):
        """Request teardown and return exit code. A process which does not
        exit within timeout is killed and reported as hanging."""
        if not self.alive():
            return self.proc.returncode if self.proc else None
        try:
            self.ctrl("terminate")
        except OSError:
            self.proc.send_signal(signal.SIGINT)
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise TimeoutError("%s did not exit within %ss after terminate" % (self.name, timeout))

    def kill(self):
        if self.alive():
            self.proc.kill()
            self.proc.wait(5)


class GoBgp:
    """GoBGP daemon running in a network namespace."""

    def __init__(self, ns, workdir):
        self.ns = ns
        self.workdir = Path(workdir)
        self.proc = None

    def start(self, config):
        config_file = str(self.workdir / "gobgpd.toml")
        with open(config_file, "w") as f:
            f.write(config)
        cmd = [GOBGPD_BIN, "-f", config_file, "-p", "-l", "debug",
               "--pprof-disable", "--api-hosts", "127.0.0.1:50051"]
        with open(str(self.workdir / "gobgpd.log"), "w") as out:
            self.proc = subprocess.Popen(self.ns.cmd(cmd), stdout=out,
                                         stderr=subprocess.STDOUT)
        wait_until(lambda: self.cli(["global"], json_output=False) is not None,
                   10, 0.2, "gobgpd API")
        return self

    def cli(self, args, json_output=True):
        cmd = [GOBGP_BIN, "-u", "127.0.0.1", "-p", "50051"]
        if json_output:
            cmd.append("-j")
        out = self.ns.exec(cmd + args)
        return json.loads(out) if json_output else out

    def neighbor(self, address):
        return self.cli(["neighbor", address])

    def session_established(self, address):
        state = self.neighbor(address).get("state", {})
        return state.get("session_state") == 6

    def received(self, address, afi, safi):
        """Return received prefix count of a family (omitted if zero)."""
        for afi_safi in self.neighbor(address).get("afi_safis", []):
            family = afi_safi.get("state", {}).get("family", {})
            if family.get("afi", 0) == afi and family.get("safi", 0) == safi:
                return afi_safi["state"].get("received", 0)
        return 0

    def adj_in(self, address, family):
        return self.cli(["neighbor", address, "adj-in", "-a", family])

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


AFI_IP, AFI_IP6, AFI_L2VPN = 1, 2, 25
SAFI_UNICAST, SAFI_EVPN = 1, 70


def gobgp_mpls_label(label):
    """GoBGP writes the 3-byte label field raw, without label shift and
    bottom of stack bit, so MPLS labels must be encoded by the caller."""
    return (label << 4) | 1


def bgpupdate(args, timeout=60):
    """Run the BGP RAW update generator."""
    return run([sys.executable, BGPUPDATE_BIN] + args, timeout=timeout)


def ldpupdate(args, timeout=60):
    """Run the LDP RAW update generator."""
    return run([sys.executable, LDPUPDATE_BIN] + args, timeout=timeout)


def lspgen(args, timeout=60):
    """Run the IS-IS/OSPF topology generator."""
    return run([LSPGEN_BIN] + args, timeout=timeout)
