"""
Scripted IS-IS neighbor for protocol tests

Sends and receives raw IS-IS PDUs on an interface of a network namespace,
so that the BNG Blaster can be tested with PDUs a real router would not
send (wrong order, wrong areas, own LSPs, bad checksums, ...).

Copyright (C) 2020-2026, RtBrick, Inc.
SPDX-License-Identifier: BSD-3-Clause
"""
import hashlib
import hmac
import os
import select
import socket
import struct
import time

MAC_P2P = bytes.fromhex("09002b000005")
MAC_L1 = bytes.fromhex("0180c2000014")
MAC_L2 = bytes.fromhex("0180c2000015")

L1_HELLO, L2_HELLO, P2P_HELLO = 15, 16, 17
L1_LSP, L2_LSP = 18, 20
L1_CSNP, L2_CSNP = 24, 25
L1_PSNP, L2_PSNP = 26, 27

TLV_AREA, TLV_IS_NEIGHBOR, TLV_LSP_ENTRIES, TLV_AUTH = 1, 6, 9, 10
TLV_EXT_IS_REACH, TLV_PROTOCOLS, TLV_IPV4_ADDR, TLV_P2P_ADJ = 22, 129, 132, 240

P2P_UP, P2P_INIT, P2P_DOWN = 0, 1, 2

HDR_LEN = {L1_HELLO: 27, L2_HELLO: 27, P2P_HELLO: 20, L1_LSP: 27, L2_LSP: 27,
           L1_CSNP: 33, L2_CSNP: 33, L1_PSNP: 17, L2_PSNP: 17}


def system_id(text):
    return bytes.fromhex(text.replace(".", ""))


def lsp_id(sysid, pseudo=0, fragment=0):
    if isinstance(sysid, str):
        sysid = system_id(sysid)
    return sysid + bytes([pseudo, fragment])


def lsp_id_str(raw):
    return "%s.%s.%s.%02x-%02x" % (raw[0:2].hex(), raw[2:4].hex(), raw[4:6].hex(), raw[6], raw[7])


def tlv(t, value):
    out = b""
    while True:
        out += bytes([t, min(len(value), 255)]) + value[:255]
        value = value[255:]
        if not value:
            return out


def fletcher(data, offset):
    """ISO 8473 checksum of data with the checksum field at offset."""
    data = bytearray(data)
    data[offset:offset + 2] = b"\x00\x00"
    c0 = c1 = 0
    for b in data:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    k = offset + 1
    x = ((len(data) - k) * c0 - c1) % 255
    y = (c1 - (len(data) - k + 1) * c0) % 255
    return bytes([x or 255, y or 255])


def fletcher_ok(data):
    c0 = c1 = 0
    for b in data:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    return c0 == 0 and c1 == 0


def pdu(pdu_type, header, tlvs=b"", pad=b""):
    """Build a PDU, the length field (first two bytes of header) is set."""
    common = bytes([0x83, HDR_LEN[pdu_type], 1, 0, pdu_type, 1, 0, 0])
    if pdu_type in (P2P_HELLO, L1_HELLO, L2_HELLO):
        # circuit type, system-id, hold time precede the length
        body = header[:9] + struct.pack("!H", 8 + len(header) + len(tlvs)) + header[11:]
    else:
        body = struct.pack("!H", 8 + len(header) + len(tlvs)) + header[2:]
    return common + body + tlvs + pad


def lsp(pdu_type, lspid, seq, lifetime, tlvs=b"", checksum=None, flags=0x03):
    header = struct.pack("!HH", 0, lifetime) + lspid + struct.pack("!IHB", seq, 0, flags)
    data = bytearray(pdu(pdu_type, header, tlvs))
    if checksum is None:
        data[24:26] = fletcher(data[12:], 12) if lifetime else b"\x00\x00"
    else:
        data[24:26] = struct.pack("!H", checksum)
    return bytes(data)


def area_tlv(*areas):
    value = b""
    for a in areas:
        raw = bytes.fromhex(a.replace(".", "").split("/")[0])
        value += bytes([len(raw)]) + raw
    return tlv(TLV_AREA, value)


def hmac_ok(data, key, auth_offset):
    """Verify the HMAC-MD5 of a PDU (RFC 5304), lifetime and checksum of
    LSPs are set to zero for the calculation."""
    data = bytearray(data)
    digest = bytes(data[auth_offset:auth_offset + 16])
    data[auth_offset:auth_offset + 16] = bytes(16)
    if data[4] in (L1_LSP, L2_LSP):
        data[10:12] = b"\x00\x00"
        data[24:26] = b"\x00\x00"
    return hmac.new(key.encode(), bytes(data), hashlib.md5).digest() == digest


class Pdu:
    """Decoded PDU received from the BNG Blaster."""

    def __init__(self, raw, timestamp):
        self.raw = raw
        self.time = timestamp
        self.type = raw[4] & 0x1f
        self.hdr_len = raw[1]
        self.tlvs = []
        off = self.hdr_len
        length = struct.unpack("!H", raw[17:19] if self.type in (L1_HELLO, L2_HELLO, P2P_HELLO)
                               else raw[8:10])[0]
        self.length = length
        while off + 2 <= length:
            t, l = raw[off], raw[off + 1]
            self.tlvs.append((t, raw[off + 2:off + 2 + l], off + 2))
            off += 2 + l

    def tlv(self, t):
        return [v for tt, v, _ in self.tlvs if tt == t]

    @property
    def lsp_id(self):
        return self.raw[12:20]

    @property
    def seq(self):
        return struct.unpack("!I", self.raw[20:24])[0]

    @property
    def lifetime(self):
        return struct.unpack("!H", self.raw[10:12])[0]

    def entries(self):
        """(lifetime, lsp-id, seq, checksum) of SNP entries."""
        out = []
        for v in self.tlv(TLV_LSP_ENTRIES):
            for o in range(0, len(v) - 15, 16):
                lt, lid, seq, ck = struct.unpack("!H8sIH", v[o:o + 16])
                out.append((lt, lid, seq, ck))
        return out


class IsisPeer:
    """IS-IS neighbor on interface ifname of namespace ns."""

    def __init__(self, ns, ifname, mac="02:00:00:00:00:fe", sysid="1921.6800.2002"):
        self.ifname = ifname
        self.mac = bytes.fromhex(mac.replace(":", ""))
        self.sysid = system_id(sysid)
        own = os.open("/proc/self/ns/net", os.O_RDONLY)
        target = os.open("/run/netns/%s" % ns.name, os.O_RDONLY)
        try:
            os.setns(target, os.CLONE_NEWNET)
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self.sock.bind((ifname, 0))
        finally:
            os.setns(own, os.CLONE_NEWNET)
            os.close(own)
            os.close(target)
        self.sock.setblocking(False)
        self.last_src = None

    def close(self):
        self.sock.close()

    def send(self, data, dst=MAC_P2P, src=None, pad=b""):
        llc = b"\xfe\xfe\x03" + data
        frame = dst + (src or self.mac) + struct.pack("!H", len(llc)) + llc + pad
        self.sock.send(frame)

    def recv(self, timeout, match=lambda p: True):
        """Return received PDUs matching until timeout (seconds)."""
        out = []
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return out
            r, _, _ = select.select([self.sock], [], [], left)
            if not r:
                continue
            try:
                frame = self.sock.recv(65535)
            except BlockingIOError:
                continue
            if frame[6:12] == self.mac:
                continue  # own frame
            self.last_src = frame[6:12]
            ethertype = struct.unpack("!H", frame[12:14])[0]
            if ethertype > 1500 and ethertype != 0x8870:
                continue
            if frame[14:17] != b"\xfe\xfe\x03":
                continue
            try:
                p = Pdu(frame[17:], time.monotonic())
            except (struct.error, IndexError):
                continue
            if match(p):
                out.append(p)

    def wait(self, timeout, match):
        """Return the first received PDU matching or None."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self.recv(min(0.2, deadline - time.monotonic()), match)
            if found:
                return found[0]
        return None

    # PDU builders of this neighbor

    def p2p_hello(self, state=None, circuit_type=2, areas=("49.0001",), neighbor=None,
                  neighbor_circuit=None, hold=30, sysid=None):
        header = bytes([circuit_type]) + (sysid or self.sysid) + struct.pack("!HHB", hold, 0, 1)
        tlvs = area_tlv(*areas) + tlv(TLV_PROTOCOLS, b"\xcc")
        if state is not None:
            value = bytes([state]) + struct.pack("!I", 1)
            if neighbor:
                value += neighbor
                if neighbor_circuit is not None:
                    value += struct.pack("!I", neighbor_circuit)
            tlvs += tlv(TLV_P2P_ADJ, value)
        return pdu(P2P_HELLO, header, tlvs)

    def lan_hello(self, level=2, neighbors=(), priority=64, dis=None, circuit_type=None,
                  areas=("49.0001",), hold=30, sysid=None):
        header = bytes([circuit_type or level]) + (sysid or self.sysid) + \
            struct.pack("!HHB", hold, 0, priority) + (dis or (sysid or self.sysid) + b"\x01")
        tlvs = area_tlv(*areas) + tlv(TLV_PROTOCOLS, b"\xcc")
        if neighbors:
            tlvs += tlv(TLV_IS_NEIGHBOR, b"".join(neighbors))
        return pdu(L1_HELLO if level == 1 else L2_HELLO, header, tlvs)

    def snp(self, pdu_type, entries, start=bytes(8), end=b"\xff" * 8):
        """CSNP or PSNP with entries (lifetime, lsp-id, seq, checksum)."""
        tlvs = b""
        for i in range(0, len(entries), 15):
            tlvs += tlv(TLV_LSP_ENTRIES, b"".join(struct.pack("!H8sIH", *e) for e in entries[i:i + 15]))
        header = struct.pack("!H", 0) + self.sysid + b"\x00"
        if pdu_type in (L1_CSNP, L2_CSNP):
            header += start + end
        return pdu(pdu_type, header, tlvs)
