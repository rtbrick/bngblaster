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
#define OSPF_LSA_OPAQUE_AREA_RI  104
#define OSPF_LSA_OPAQUE_DOMAIN    11

#define OSPF_TLV_HOSTNAME          7

enum {
    /* Router LSA */
    OSPF_ROUTER_LSA_LINK_PTP,
    OSPF_ROUTER_LSA_LINK_STUB,
};
