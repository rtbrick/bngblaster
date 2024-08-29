/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * IS-IS protocol definitions.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */

enum {
    ISIS_AUTH_NONE = 0,
    ISIS_AUTH_SIMPLE = 1,
    ISIS_AUTH_MD5 = 54
};

#define ISIS_PDU_L1_LSP           18
#define ISIS_PDU_L2_LSP           20

#define NLPID_IPV4              0xcc
#define NLPID_IPV6              0x8e

#define TLV_OVERHEAD               2

#define ISIS_TLV_AREA              1
#define ISIS_TLV_IS_REACH          2
#define ISIS_TLV_AUTH             10
#define ISIS_TLV_LSP_BUFFER_SIZE  14
#define ISIS_TLV_EXTD_IS_REACH    22
#define ISIS_TLV_INT_IPV4_REACH  128
#define ISIS_TLV_PROTOCOLS       129
#define ISIS_TLV_EXT_IPV4_REACH  130
#define ISIS_TLV_IPV4_ADDR       132
#define ISIS_TLV_EXTD_IPV4_REACH 135
#define ISIS_TLV_HOSTNAME        137
#define ISIS_TLV_BINDING         149
#define ISIS_TLV_IPV6_ADDR       232
#define ISIS_TLV_EXTD_IPV6_REACH 236
#define ISIS_TLV_CAP             242

#define ISIS_SUBTLV_CAP_SR         2
#define ISIS_SUBTLV_CAP_SR_ALGO   19

#define ISIS_SUBTLV_IS_EXT_ADJ_SID	31

#define ISIS_SUBTLV_PREFIX_TAG     1
#define ISIS_SUBTLV_PREFIX_SID     3
#define ISIS_SUBTLV_PREFIX_FLAG    4

#define ISIS_DEFAULT_LSP_BUFFER_SIZE    1492
