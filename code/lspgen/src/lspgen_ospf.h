/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * OSPF protocol definitions.
 *
 * Hannes Gredler, July 2023
 *
 * Copyright (C) 2015-2023, RtBrick, Inc.
 */

#define OSPF_MSG_LSUPDATE          4

#define OSPF_LSA_ROUTER            1
#define OSPF_LSA_NETWORK           2
#define OSPF_LSA_SUMMARY           3
#define OSPF_LSA_ASBR_SUMMARY      4
#define OSPF_LSA_EXTERNAL          5
#define OSPF_LSA_OPAQUE_LINK       9
#define OSPF_LSA_INTRA_AREA_PREFIX 39 /* OSPFv3 LSA Type 9*/
#define OSPF_LSA_OPAQUE_AREA_RI  104
#define OSPF_LSA_OPAQUE_AREA_EP  107 /* rfc 7684 */
#define OSPF_LSA_OPAQUE_DOMAIN    11

/* Router LSA */
#define OSPF_ROUTER_LSA_LINK_PTP   1
#define OSPF_ROUTER_LSA_LINK_STUB  3

/* Opaque LSA RI TLVs*/
#define OSPF_TLV_HOSTNAME          7
#define OSPF_TLV_SID_LABEL_RANGE   9

/* Opaque LSA Extended Prefix TLVs */
#define OSPF_TLV_EXTENDED_PREFIX_RANGE 2

/* Inter Area Prefix LSA */
#define OSPF_IA_PREFIX_LSA_PREFIX  31
