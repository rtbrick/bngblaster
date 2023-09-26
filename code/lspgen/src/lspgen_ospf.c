/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * OSPF protocol helper functions.
 *
 * Hannes Gredler, July 2023
 *
 * Copyright (C) 2015-2023, RtBrick, Inc.
 */

#include "lspgen.h"
#include "lspgen_ospf.h"

/*
 * Link State Attributes / name mappings
 */
struct keyval_ ospf_attr_names[] = {
    { OSPF_MSG_LSUPDATE,		"LS-Update" },
    { OSPF_LSA_ROUTER,			"Router-LSA" },
    { OSPF_LSA_EXTERNAL,		"External-LSA" },
    { OSPF_LSA_EXTERNAL6,		"External-LSA" },
    { OSPF_LSA_INTRA_AREA_PREFIX,	"Intra-Area-Prefix-LSA" },
    { OSPF_LSA_E_INTRA_AREA_PREFIX,	"Extd-Intra-Area-Prefix-LSA" },
    { OSPF_LSA_OPAQUE_AREA_RI,		"Opaque-LSA-RI" },
    { OSPF_LSA_OPAQUE_AREA_EP,		"Opaque-LSA-EP" },
    { OSPF_ROUTER_LSA_LINK_PTP,		"ptp-link" },
    { OSPF_ROUTER_LSA_LINK_STUB,	"ptp-stub" },
    { OSPF_TLV_HOSTNAME,		"Hostname" },
    { OSPF_TLV_SID_LABEL_RANGE,		"SID/Label-Range" },
    { OSPF_TLV_EXTENDED_PREFIX,		"Extended-Prefix" },
    { OSPF_TLV_EXTENDED_PREFIX_RANGE,	"Extended-Prefix-Range" },
    { OSPF_TLV_INTRA_AREA_PREFIX,	"Intra-Area-Prefix" },
    { OSPF_SUBTLV_PREFIX_SID,		"Prefix-SID" },
    { OSPF_IA_PREFIX_LSA_PREFIX,	"Prefix" },
    { 0, NULL}
};
