/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * OSPF protocol definitions.
 *
 * Hannes Gredler, July 2023
 *
 * Copyright (C) 2015-2024, RtBrick, Inc.
 */

/*
 * Those codepoints are purely used for lspgen internal handling.
 * They do not (!) represent the IANA allocated codepoints on the wire.
 */
enum {
    OSPF_UNKNOWN = 0,

    /* Message Type */
    OSPF_MSG_LSUPDATE,

    /* LSA Type */
    OSPF_LSA_ROUTER,
    OSPF_LSA_EXTERNAL,
    OSPF_LSA_EXTERNAL6, /* ospf3*/
    OSPF_LSA_INTRA_AREA_PREFIX, /* ospf3 */
    OSPF_LSA_E_INTRA_AREA_PREFIX, /* ospf3, rfc8362 */
    OSPF_LSA_OPAQUE_AREA_RI,
    OSPF_LSA_OPAQUE_AREA_EP, /* rfc 7684 */

    /* Router LSA subtypes */
    OSPF_ROUTER_LSA_LINK_PTP,
    OSPF_ROUTER_LSA_LINK_STUB,

    /* Opaque LSA RI TLVs*/
    OSPF_TLV_HOSTNAME,
    OSPF_TLV_SID_LABEL_RANGE,

    /* Opaque LSA Extended Prefix TLVs */
    OSPF_TLV_EXTENDED_PREFIX,
    OSPF_TLV_EXTENDED_PREFIX_RANGE,

    /* rfc 8362 */
    OSPF_TLV_INTRA_AREA_PREFIX,

    /* rfc 8666 */
    OSPF_SUBTLV_PREFIX_SID,

    /* Inter Area Prefix LSA */
    OSPF_IA_PREFIX_LSA_PREFIX,
};

extern struct keyval_ ospf_attr_names[];
