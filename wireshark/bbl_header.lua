-- BNG Blaster Header Dissector
bbl_proto = Proto("BNG-BLASTER", "BNG Blaster Header")

local mn_f = ProtoField.uint64("bbl_proto.mn", "Magic Sequence", base.DEC, none, none)
local ht_f = ProtoField.uint8("bbl_proto.ht", "Type", base.DEC,
  {[0]="reserved", [1]="Unicast Session Traffic", [2]="Multicast"}, none)
local st_f = ProtoField.uint8("bbl_proto.st", "Sub-Type", base.DEC,
  {[0]="reserved", [1]="IPv4", [2]="IPv6", [3]="IPv6PD"}, none)
local hd_f = ProtoField.uint8("bbl_proto.hd", "Direction", base.DEC,
  {[0]="reserved", [1]="upstream", [2]="downstream"}, none)
local tt_f = ProtoField.uint8("bbl_proto.tt", "TX TOS", base.DEC, none)

local si_f = ProtoField.uint32("bbl_proto.si", "Session Identifier", base.DEC, none, none)
local ii_f = ProtoField.uint32("bbl_proto.ii", "Session Access Interface Index", base.DEC, none, none)
local ov_f = ProtoField.uint16("bbl_proto.ov", "Session Outer VLAN", base.DEC, none, none)
local iv_f = ProtoField.uint16("bbl_proto.iv", "Session Inner VLAN", base.DEC, none, none)

local ms_f = ProtoField.ipv4("bbl_proto.ms", "Multicast Source", base.DEC, none, none)
local mg_f = ProtoField.ipv4("bbl_proto.mg", "Multicast Group", base.DEC, none, none)

local fi_f = ProtoField.uint64("bbl_proto.fi", "Flow Identifier", base.DEC, none, none)
local sn_f = ProtoField.uint64("bbl_proto.sn", "Flow Sequence Number", base.DEC, none, none)
local ts_f = ProtoField.uint32("bbl_proto.ts", "Send Timestamp Seconds", base.DEC, none, none)
local tn_f = ProtoField.uint32("bbl_proto.tn", "Send Timestamp Nanoseconds", base.DEC, none, none)

bbl_proto.fields = {mn_f, ht_f, st_f, hd_f, tt_f, si_f, ii_f, ov_f, iv_f, ms_f, mg_f, fi_f, sn_f, ts_f, tn_f}

local data_dissector = Dissector.get("data")
local ethernet_dissector = DissectorTable.get("wtap_encap"):get_dissector(1)

function bbl_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "BNG-BLASTER"
    local subtree = tree:add(bbl_proto, buffer(0,48), "BNG-BLASTER")
    subtree:add_le(mn_f, buffer(0, 8))
    subtree:add(ht_f, buffer(8, 1))
    subtree:add(st_f, buffer(9, 1))
    subtree:add(hd_f, buffer(10, 1))
    subtree:add(tt_f, buffer(11, 1))
    -- reserved ---
    local header_type = buffer(8,1):uint()
    if header_type == 1 then
        -- unicast session traffic
        subtree:add_le(si_f, buffer(12, 4))
        subtree:add_le(ii_f, buffer(16, 4))
        subtree:add_le(ov_f, buffer(20, 2))
        subtree:add_le(iv_f, buffer(22, 2))
    end
    if header_type == 2 then
        -- mulicast traffic
        subtree:add(ms_f, buffer(16, 4))
        subtree:add(mg_f, buffer(20, 4))
    end
    subtree:add_le(fi_f, buffer(24, 8))
    subtree:add_le(sn_f, buffer(32, 8))
    subtree:add_le(ts_f, buffer(40, 4))
    subtree:add_le(tn_f, buffer(44, 4))
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(65056,bbl_proto)
