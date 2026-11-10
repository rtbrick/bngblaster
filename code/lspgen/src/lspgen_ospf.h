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

    /* Opaque LSA RI SR-Algorithm TLV (rfc 8665), appended to keep the attribute order */
    OSPF_TLV_SR_ALGO,
};

/* Largest OSPFv3 LSA generated, such that an LS update with one LSA fits into
 * the IPv6 minimum MTU with authentication. OSPFv3 is not fragmented, while
 * OSPFv2 LSAs are limited by the packet buffer only (IP fragmentation). */
#define OSPF3_MAX_LSA_LEN           1200
/* IP and OSPF header plus #LSAs of an LS update */
#define OSPF2_LSUPDATE_HDR_LEN      (20+24+4)
#define OSPF3_LSUPDATE_HDR_LEN      (40+16+4)
#define OSPF_MAX_AGE                3600

/* Node flag of the OSPFv2 Extended Prefix TLV (RFC 7684) */
#define OSPF_EXT_PREFIX_FLAG_N      0x40
/* Node bit of the OSPFv3 prefix options (RFC 8362) */
#define OSPF3_PREFIX_OPTION_N       0x20

extern struct keyval_ ospf_attr_names[];
