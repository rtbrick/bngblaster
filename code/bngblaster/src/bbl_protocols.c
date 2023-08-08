/*
 * Protocol Encode/Decode Functions
 *
 * Christian Giese, July 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl_def.h"
#include "bbl_protocols.h"
#include "bbl_access_line.h"
#include "isis/isis_def.h"
#include "ospf/ospf_def.h"
#include "ldp/ldp_def.h"

static protocol_error_t decode_l2tp(uint8_t *buf, uint16_t len, uint8_t *sp, uint16_t sp_len, bbl_ethernet_header_s *eth, bbl_l2tp_s **_l2tp);
static protocol_error_t encode_l2tp(uint8_t *buf, uint16_t *len, bbl_l2tp_s *l2tp);

/** 
 * This function searches for the BNG Blaster data
 * traffic signature and returns true if found.
 * 
 * @param buf start of packet
 * @param len length of packet
 * @return true for BNG Blaster stream traffic
 */
bool
packet_is_bbl(uint8_t *buf, uint16_t len)
{
    if(len < BBL_MIN_LEN) {
        return false;
    }
    buf += len - BBL_HEADER_LEN;
    if(*(uint64_t*)buf == BBL_MAGIC_NUMBER) {
        return true;
    }
    return false;
}

/*
 * CHECKSUM
 * ------------------------------------------------------------------------*/

static uint32_t
_checksum(void *buf, ssize_t len)
{
    uint32_t result = 0;
    uint16_t *cur = buf;
    while (len > 1) {
        result += *cur++;
        len -= 2;
    }
    /*  Add left-over byte, if any */
    if(len) {
        result += *(uint8_t*)cur;
    }
    return result;
}

static uint32_t
_fold(uint32_t sum)
{
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum;
}

uint16_t
bbl_checksum(uint8_t *buf, uint16_t len)
{
    return ~_fold(_checksum(buf, len));
}

static uint16_t
bbl_ipv4_udp_checksum(uint32_t src, uint32_t dst, uint8_t *udp, uint16_t udp_len)
{
    uint32_t result;
    result  = htobe16(PROTOCOL_IPV4_UDP);
    result += htobe16(udp_len);
    result += _checksum(&src, sizeof(src));
    result += _checksum(&dst, sizeof(dst));
    result += _checksum(udp, 6);
    result += _checksum(udp+8, udp_len-8);
    return ~_fold(result);
}

static uint16_t
bbl_ipv6_udp_checksum(ipv6addr_t src, ipv6addr_t dst, uint8_t *udp, uint16_t udp_len)
{
    uint32_t result;
    result  = htobe16(IPV6_NEXT_HEADER_UDP);
    result += htobe16(udp_len);
    result += _checksum(src, sizeof(ipv6addr_t));
    result += _checksum(dst, sizeof(ipv6addr_t));
    result += _checksum(udp, 6);
    result += _checksum(udp+8, udp_len-8);
    return ~_fold(result);
}

static uint16_t
bbl_ipv6_icmpv6_checksum(ipv6addr_t src, ipv6addr_t dst, uint8_t *icmp, uint16_t icmp_len)
{
    uint32_t result;
    result  = htobe16(IPV6_NEXT_HEADER_ICMPV6);
    result += htobe16(icmp_len);
    result += _checksum(src, sizeof(ipv6addr_t));
    result += _checksum(dst, sizeof(ipv6addr_t));
    result += _checksum(icmp, 2);
    result += _checksum(icmp+4, icmp_len-4);
    return ~_fold(result);
}

uint16_t
bbl_ipv6_ospf_checksum(ipv6addr_t src, ipv6addr_t dst, uint8_t *ospf, uint16_t ospf_len)
{
    uint32_t result;
    result  = htobe16(IPV6_NEXT_HEADER_OSPF);
    result += htobe16(ospf_len);
    result += _checksum(src, sizeof(ipv6addr_t));
    result += _checksum(dst, sizeof(ipv6addr_t));
    result += _checksum(ospf, ospf_len);
    return ~_fold(result);
}

/*
 * ENCODE
 * ------------------------------------------------------------------------*/

/*
 * encode_lacp
 */
static protocol_error_t
encode_lacp(uint8_t *buf, uint16_t *len,
           bbl_lacp_s *lacp)
{
    *buf = SLOW_PROTOCOLS_LACP;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* LACP Version */
    *buf = 0x01;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Encode Actor TLV */
    *buf = LACP_TLV_ACTOR_INFORMATION;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 20;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(lacp->actor_system_priority);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    memcpy(buf, lacp->actor_system_id, ETH_ADDR_LEN);
    BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
    *(uint16_t*)buf = htobe16(lacp->actor_key);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(lacp->actor_port_priority);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(lacp->actor_port_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint32_t*)buf = 0;
    *buf = lacp->actor_state;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    /* Encode Partner TLV */
    *buf = LACP_TLV_PARTNER_INFORMATION;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 20;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(lacp->partner_system_priority);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    memcpy(buf, lacp->partner_system_id, ETH_ADDR_LEN);
    BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
    *(uint16_t*)buf = htobe16(lacp->partner_key);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(lacp->partner_port_priority);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(lacp->partner_port_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint32_t*)buf = 0;
    *buf = lacp->partner_state;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    /* Encode Collector TLV */
    *buf = LACP_TLV_COLLECTOR_INFORMATION;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 16;
    /* Fill with Zero */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    memset(buf, 0x0, 66);
    BUMP_WRITE_BUFFER(buf, len, 66);
    return PROTOCOL_SUCCESS;
}

static uint16_t
encode_dhcpv6_access_line(uint8_t *buf, access_line_s *access_line)
{
    uint16_t len = 0;
    uint16_t *option_len;

    /* DHCPv6 Vendor Option (17) */
    *(uint16_t*)buf = htobe16(DHCPV6_OPTION_VENDOR_OPTS);
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
    option_len = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
    *(uint32_t*)buf = htobe32(BROADBAND_FORUM);
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));

    if(access_line->up) {
        *(uint16_t*)buf = htobe16(ACCESS_LINE_ACT_UP);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(uint32_t));
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
        *(uint32_t*)buf = htobe32(access_line->up);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    }
    if(access_line->down) {
        *(uint16_t*)buf = htobe16(ACCESS_LINE_ACT_DOWN);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(uint32_t));
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
        *(uint32_t*)buf = htobe32(access_line->down);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    }
    if(access_line->dsl_type) {
        *(uint16_t*)buf = htobe16(ACCESS_LINE_DSL_TYPE);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(uint32_t));
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
        *(uint32_t*)buf = htobe32(access_line->dsl_type);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    }

    if(len > 8) {
        *option_len = htobe16(len-4);
        return len;
    }
    return 0;
}

/*
 * encode_dhcpv6
 */
static protocol_error_t
encode_dhcpv6(uint8_t *buf, uint16_t *len,
              bbl_dhcpv6_s *dhcpv6)
{
    uint16_t value_len;

    if(dhcpv6->type == DHCPV6_MESSAGE_RELAY_FORW || 
       dhcpv6->type == DHCPV6_MESSAGE_RELAY_REPL) {
        /* Type */
        *buf = dhcpv6->type;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        /* Hops */
        *buf = dhcpv6->hops;
        /* Link Address */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        if(dhcpv6->link_address) {
            memcpy(buf, dhcpv6->link_address, sizeof(ipv6addr_t));
        } else {
            memset(buf, 0x0, sizeof(ipv6addr_t));
        }
        BUMP_WRITE_BUFFER(buf, len, sizeof(ipv6addr_t));
        /* Peer Address */
        if(dhcpv6->peer_address) {
            memcpy(buf, dhcpv6->peer_address, sizeof(ipv6addr_t));
        } else {
            memset(buf, 0x0, sizeof(ipv6addr_t));
        }
        BUMP_WRITE_BUFFER(buf, len, sizeof(ipv6addr_t));
    } else {
        /* Type/Transaction ID */
        *(uint32_t*)buf = htobe32(dhcpv6->xid);
        *buf = dhcpv6->type;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        /* Elapsed Time */
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_ELAPSED_TIME);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(uint16_t));
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }

    /* Relay Message */
    if(dhcpv6->relay_message) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_RELAY_MSG);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        value_len = 0;
        if(encode_dhcpv6(buf+2, &value_len, dhcpv6->relay_message) != PROTOCOL_SUCCESS) {
            return ENCODE_ERROR;
        }
        *(uint16_t*)buf = htobe16(value_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t)+value_len);
    }
    /* Client Identifier */
    if(dhcpv6->client_duid_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_CLIENTID);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->client_duid_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->client_duid, dhcpv6->client_duid_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->client_duid_len);
    }
    /* Server Identifier */
    if(dhcpv6->server_duid_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_SERVERID);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->server_duid_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->server_duid, dhcpv6->server_duid_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->server_duid_len);
    }
    /* Rapid Commit */
    if(dhcpv6->rapid) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_RAPID_COMMIT);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
    /* IA_NA */
    if(dhcpv6->ia_na_option_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IA_NA);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->ia_na_option_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->ia_na_option, dhcpv6->ia_na_option_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->ia_na_option_len);
    } else if(dhcpv6->ia_na_iaid) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IA_NA);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        if(dhcpv6->ia_na_address) {
            *(uint16_t*)buf = htobe16(40); /* length */
        } else {
            *(uint16_t*)buf = htobe16(12); /* length */
        }
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = dhcpv6->ia_na_iaid;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = dhcpv6->ia_na_t1; /* T1 */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = dhcpv6->ia_na_t2; /* T2 */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        if(dhcpv6->ia_na_address) {
            *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IAADDR);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            *(uint16_t*)buf = htobe16(24); /* length */
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            memcpy(buf, dhcpv6->ia_na_address, sizeof(ipv6addr_t));
            BUMP_WRITE_BUFFER(buf, len, sizeof(ipv6addr_t));
            *(uint32_t*)buf = dhcpv6->ia_na_preferred_lifetime;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            *(uint32_t*)buf = dhcpv6->ia_na_valid_lifetime;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        }

    }
    /* IA_PD */
    if(dhcpv6->ia_pd_option_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IA_PD);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->ia_pd_option_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->ia_pd_option, dhcpv6->ia_pd_option_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->ia_pd_option_len);
    } else if(dhcpv6->ia_pd_iaid) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IA_PD);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(41); /* length */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = dhcpv6->ia_pd_iaid;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = dhcpv6->ia_pd_t1; /* T1 */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = dhcpv6->ia_pd_t2; /* T2 */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IAPREFIX);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(25); /* length */
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = dhcpv6->ia_pd_preferred_lifetime;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = dhcpv6->ia_pd_valid_lifetime;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        if(dhcpv6->ia_pd_prefix) {
            memcpy(buf, dhcpv6->ia_pd_prefix, sizeof(ipv6_prefix));
        } else {
            memset(buf, 0x0, sizeof(ipv6_prefix));
        }
        BUMP_WRITE_BUFFER(buf, len, sizeof(ipv6_prefix));
    }
    /* Option Request Option */
    if(dhcpv6->oro) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_ORO);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(2);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_DNS_SERVERS);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
    /* Vendor Class Option */
    //*(uint16_t*)buf = htobe16(DHCPV6_OPTION_VENDOR_CLASS);
    //BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    //*(uint16_t*)buf = htobe16(sizeof(uint32_t));
    //BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    //*(uint32_t*)buf = htobe32(RTBRICK);
    //BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    if(dhcpv6->access_line) {
        if(dhcpv6->access_line->aci) {
            /* DHCPv6 Interface-Id Option (18) */
            *(uint16_t*)buf = htobe16(DHCPV6_OPTION_INTERFACE_ID);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            value_len = strnlen(dhcpv6->access_line->aci, UINT8_MAX);
            *(uint16_t*)buf = htobe16(value_len);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            memcpy(buf, dhcpv6->access_line->aci, value_len);
            BUMP_WRITE_BUFFER(buf, len, value_len);
        }
        if(dhcpv6->access_line->ari) {
            /* DHCPv6 Remote-ID Option (37) */
            *(uint16_t*)buf = htobe16(DHCPV6_OPTION_REMOTE_ID);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            value_len = strnlen(dhcpv6->access_line->ari, UINT16_MAX);
             *(uint16_t*)buf = htobe16(value_len+4);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            /* See TR-177 chapter 5.6.1, R-11! */
            *(uint32_t*)buf = htobe32(BROADBAND_FORUM);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            memcpy(buf, dhcpv6->access_line->ari, value_len);
            BUMP_WRITE_BUFFER(buf, len, value_len);
        }
        /* DHCPv6 Vendor Option (17)
         * See TR-177 chapter 5.6.1 and TR-101 Appendix B */
        value_len = encode_dhcpv6_access_line(buf, dhcpv6->access_line);
        BUMP_WRITE_BUFFER(buf, len, value_len);
    }
    return PROTOCOL_SUCCESS;
}

static uint8_t
encode_dhcp_access_line(uint8_t *buf, access_line_s *access_line)
{
    uint16_t len = 0;
    uint8_t *option_len;
    uint8_t *data_len;

    *buf = DHCP_RELAY_AGENT_VENDOR_SUBOPT;
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    option_len = buf;
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *(uint32_t*)buf = htobe32(BROADBAND_FORUM);
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    data_len = buf;
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));

    if(access_line->up) {
        *buf = ACCESS_LINE_ACT_UP;
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
        *buf = sizeof(uint32_t);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
        *(uint32_t*)buf = htobe32(access_line->up);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    }
    if(access_line->down) {
        *buf = ACCESS_LINE_ACT_DOWN;
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
        *buf = sizeof(uint32_t);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
        *(uint32_t*)buf = htobe32(access_line->down);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    }
    if(access_line->dsl_type) {
        *buf = ACCESS_LINE_DSL_TYPE;
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
        *buf = sizeof(uint32_t);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
        *(uint32_t*)buf = htobe32(access_line->dsl_type);
        BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));
    }
    if(len > 7) {
        *option_len = len-2;
        *data_len = len-7;
        return len;
    }
    return 0;
}

/*
 * encode_dhcp
 */
static protocol_error_t
encode_dhcp(uint8_t *buf, uint16_t *len,
            bbl_dhcp_s *dhcp)
{
    if(!dhcp->header) return ENCODE_ERROR;

    uint8_t  value_len;
    uint8_t  option_len;
    uint8_t *option_len_ptr;

    memcpy(buf, dhcp->header, sizeof(struct dhcp_header));
    BUMP_WRITE_BUFFER(buf, len, sizeof(struct dhcp_header));

    /* Magic Cookie */
    *(uint32_t*)buf = DHCP_MAGIC_COOKIE;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    *buf = DHCP_OPTION_DHCP_MESSAGE_TYPE;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 1;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = dhcp->type;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    if(dhcp->parameter_request_list) {
        *buf = DHCP_OPTION_PARAM_REQUEST_LIST;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        option_len_ptr = buf;
        option_len = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        if(dhcp->option_netmask) {
            option_len++;
            *buf = DHCP_OPTION_SUBNET_MASK;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        if(dhcp->option_router) {
            option_len++;
            *buf = DHCP_OPTION_ROUTER;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        if(dhcp->option_dns1 || dhcp->option_dns2) {
            option_len++;
            *buf = DHCP_OPTION_DNS_SERVER;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        if(dhcp->option_domain_name) {
            option_len++;
            *buf = DHCP_OPTION_DOMAIN_NAME;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        *option_len_ptr = option_len;
    }
    if(dhcp->client_identifier) {
        *buf = DHCP_OPTION_CLIENT_IDENTIFIER;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = dhcp->client_identifier_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, dhcp->client_identifier, dhcp->client_identifier_len);
        BUMP_WRITE_BUFFER(buf, len, dhcp->client_identifier_len);
    }
    if(dhcp->option_server_identifier) {
        *buf = DHCP_OPTION_SERVER_IDENTIFIER;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 4;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint32_t*)buf = dhcp->server_identifier;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }
    if(dhcp->option_address && dhcp->address) {
        *buf = DHCP_OPTION_REQUESTED_IP_ADDRESS;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 4;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint32_t*)buf = dhcp->address;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }
    if(dhcp->option_router && dhcp->router) {
        *buf = DHCP_OPTION_ROUTER;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 4;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint32_t*)buf = dhcp->router;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }
    if(dhcp->option_lease_time && dhcp->lease_time) {
        *buf = DHCP_OPTION_IP_ADDRESS_LEASE_TIME;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 4;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint32_t*)buf = htobe32(dhcp->lease_time);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }
    if(dhcp->access_line) {
        /* RFC3046 Relay Agent Information Option (82) */
        *buf = DHCP_OPTION_RELAY_AGENT_INFORMATION;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        option_len_ptr = buf;
        option_len = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        if(dhcp->access_line->aci) {
            *buf = ACCESS_LINE_ACI;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            value_len = strnlen(dhcp->access_line->aci, UINT8_MAX);
            *buf = value_len;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            memcpy(buf, dhcp->access_line->aci, value_len);
            BUMP_WRITE_BUFFER(buf, len, value_len);
            option_len += value_len + 2;
        }
        if(dhcp->access_line->ari) {
            *buf = ACCESS_LINE_ARI;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            value_len = strnlen(dhcp->access_line->ari, UINT8_MAX);
            *buf = value_len;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            memcpy(buf, dhcp->access_line->ari, value_len);
            BUMP_WRITE_BUFFER(buf, len, value_len);
            option_len += value_len + 2;
        }
        /* See TR-101 Appendix B */
        value_len = encode_dhcp_access_line(buf, dhcp->access_line);
        option_len += value_len;
        BUMP_WRITE_BUFFER(buf, len, value_len);
        *option_len_ptr = option_len;
    }

    *buf = DHCP_OPTION_END;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* This is optional ... */
    while(*len % 8) {
        *buf = DHCP_OPTION_PAD;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    }
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ldp_hello
 */
static protocol_error_t
encode_ldp_hello(uint8_t *buf, uint16_t *len, bbl_ldp_hello_s *ldp)
{
    uint8_t *start = buf;
    uint16_t pdu_len;
    uint16_t msg_len;

    /* PDU version and length */
    *(uint16_t*)buf = htobe16(1); 
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = 0; 
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    pdu_len = *len;

    /* LDP identifier (LSR ID + label space) */
    *(uint32_t*)buf = ldp->lsr_id;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    *(uint16_t*)buf = htobe16(ldp->label_space_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    /* LDP message type and length */
    *(uint16_t*)buf = htobe16(LDP_MESSAGE_TYPE_HELLO);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    msg_len = *len;

    /* LDP message ID */
    *(uint32_t*)buf = htobe32(ldp->msg_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    /* Common hello parameters TLV */
    *(uint16_t*)buf = htobe16(LDP_TLV_TYPE_COMMON_HELLO_PARAMETERS);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(4);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(ldp->hold_time);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    /* IPv4 transport address TLV */
    if(ldp->ipv4_transport_address) {
        *(uint16_t*)buf = htobe16(LDP_TLV_TYPE_IPV4_TRANSPORT_ADDRESS);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(uint32_t));
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = ldp->ipv4_transport_address;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }

    /* IPv6 transport address TLV */
    if(ldp->ipv6_transport_address) {
        *(uint16_t*)buf = htobe16(LDP_TLV_TYPE_IPV6_TRANSPORT_ADDRESS);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(ipv6addr_t));
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, ldp->ipv6_transport_address, sizeof(ipv6addr_t));
        BUMP_WRITE_BUFFER(buf, len, sizeof(ipv6addr_t));
    }

    /* Dual-Stack capability TLV */
    if(ldp->dual_stack_capability) {
        *(uint16_t*)buf = htobe16(LDP_TLV_TYPE_DUAL_STACK_CAPABILITY);
        *buf |= 0x80;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(sizeof(uint32_t));
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = 0;
        *buf = (ldp->dual_stack_capability << 4) & 0xF0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }

    /* Update total length */
    pdu_len = *len - pdu_len;
    msg_len = *len - msg_len;
    *(uint16_t*)(start + 2) = htobe16(pdu_len);
    *(uint16_t*)(start + 12) = htobe16(msg_len);

    return PROTOCOL_SUCCESS;
}

/*
 * encode_bbl
 */
static protocol_error_t
encode_bbl(uint8_t *buf, uint16_t *len,
           bbl_bbl_s *bbl)
{
    if(bbl->padding) {
        memset(buf, 0x0, bbl->padding);
        BUMP_WRITE_BUFFER(buf, len, bbl->padding);
    }
    *(uint64_t*)buf = BBL_MAGIC_NUMBER;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint64_t));
    *buf = bbl->type;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = bbl->sub_type;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = bbl->direction;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = bbl->tos;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint32_t*)buf = bbl->session_id;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    if(bbl->type == BBL_TYPE_UNICAST) {
        *(uint32_t*)buf = bbl->ifindex;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint16_t*)buf = bbl->outer_vlan_id;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = bbl->inner_vlan_id;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    } else if(bbl->type == BBL_TYPE_MULTICAST) {
        *(uint32_t*)buf = bbl->mc_source;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = bbl->mc_group;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }
    *(uint64_t*)buf = bbl->flow_id;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint64_t));
    *(uint64_t*)buf = bbl->flow_seq;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint64_t));
    *(uint32_t*)buf = bbl->timestamp.tv_sec;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    *(uint32_t*)buf = bbl->timestamp.tv_nsec;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    return PROTOCOL_SUCCESS;
}

/*
 * encode_udp
 */
static protocol_error_t
encode_udp(uint8_t *buf, uint16_t *len,
           bbl_udp_s *udp)
{
    protocol_error_t result;

    *(uint16_t*)buf = htobe16(udp->src);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(udp->dst);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint32_t*)buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    /* Add protocol */
    switch(udp->protocol) {
        case UDP_PROTOCOL_DHCPV6:
            result = encode_dhcpv6(buf, len, (bbl_dhcpv6_s*)udp->next);
            break;
        case UDP_PROTOCOL_BBL:
            result = encode_bbl(buf, len, (bbl_bbl_s*)udp->next);
            break;
        case UDP_PROTOCOL_L2TP:
            result = encode_l2tp(buf, len, (bbl_l2tp_s*)udp->next);
            break;
        case UDP_PROTOCOL_DHCP:
            result = encode_dhcp(buf, len, (bbl_dhcp_s*)udp->next);
            break;
        case UDP_PROTOCOL_LDP:
            result = encode_ldp_hello(buf, len, (bbl_ldp_hello_s*)udp->next);
            break;
        default:
            result = PROTOCOL_SUCCESS;
            break;
    }
    return result;
}

/*
 * encode_icmpv6
 */
static protocol_error_t
encode_icmpv6(uint8_t *buf, uint16_t *len,
              bbl_icmpv6_s *icmp)
{
    uint8_t *start = buf;
    uint16_t icmp_len = *len;

    *(uint32_t*)buf = 0;
    *buf = icmp->type;
    *(buf+1) = icmp->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    if(icmp->data_len) {
        /* Copy data */
        memcpy(buf, icmp->data, icmp->data_len);
        BUMP_WRITE_BUFFER(buf, len, icmp->data_len);
    } else {
        switch(icmp->type) {
            case IPV6_ICMPV6_ROUTER_SOLICITATION:
                *(uint32_t*)buf = 0;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                break;
            case IPV6_ICMPV6_ROUTER_ADVERTISEMENT:
                *buf = 64; /* Hop Limit */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 0; /* Flags */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint16_t*)buf = htobe16(30); /* Router lifetime */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
                *(uint32_t*)buf = 0; /* Reachable time */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                *(uint32_t*)buf = 0; /* Retrans time */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                *buf = 1; /* Source link-layer address */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 1; /* Length (1 = 8 byte) */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                memcpy(buf, icmp->mac, ETH_ADDR_LEN);
                BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
                break;
            case IPV6_ICMPV6_NEIGHBOR_SOLICITATION:
                *(uint32_t*)buf = 0; /* Reserved */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                /* Target address */
                memcpy(buf, icmp->prefix.address, IPV6_ADDR_LEN);
                BUMP_WRITE_BUFFER(buf, len, IPV6_ADDR_LEN);
                *buf = 1; /* Source link-layer address */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 1; /* Length (1 = 8 byte) */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                memcpy(buf, icmp->mac, ETH_ADDR_LEN);
                BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
                break;
            case IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT:
                *buf = 0x60; /* Flags */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                /* Target address */
                memcpy(buf, icmp->prefix.address, IPV6_ADDR_LEN);
                BUMP_WRITE_BUFFER(buf, len, IPV6_ADDR_LEN);
                *buf = 2; /* Target link-layer address */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 1; /* Length (1 = 8 byte) */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                memcpy(buf, icmp->mac, ETH_ADDR_LEN);
                BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
                break;
            default:
                break;
        }
    }

    /* Calculate length */
    icmp_len = *len - icmp_len;

    /* Update checksum */
    *(uint16_t*)(start + 2) = bbl_checksum(start, icmp_len);

    return PROTOCOL_SUCCESS;
}

/*
 * encode_arp
 */
static protocol_error_t
encode_arp(uint8_t *buf, uint16_t *len,
           bbl_arp_s *arp)
{
    *(uint16_t*)buf = 0x0100;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = 0x0008;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *buf = 6;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 4;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(arp->code);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    if(arp->sender) {
        memcpy(buf, arp->sender, ETH_ADDR_LEN);
    } else {
        memset(buf, 0x0, ETH_ADDR_LEN);
    }
    BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
    *(uint32_t*)buf = arp->sender_ip;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    if(arp->target) {
        memcpy(buf, arp->target, ETH_ADDR_LEN);
    } else {
        memset(buf, 0x0, ETH_ADDR_LEN);
    }
    BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);
    *(uint32_t*)buf = arp->target_ip;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    return PROTOCOL_SUCCESS;
}

/*
 * encode_icmp
 */
static protocol_error_t
encode_icmp(uint8_t *buf, uint16_t *len,
            bbl_icmp_s *icmp)
{
    uint8_t *start = buf;
    uint16_t icmp_len = *len;

    *(uint64_t*)buf = 0;
    *buf = icmp->type;
    *(buf+1) = icmp->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    if(icmp->data_len) {
        /* Copy data */
        memcpy(buf, icmp->data, icmp->data_len);
        BUMP_WRITE_BUFFER(buf, len, icmp->data_len);
    }

    /* Calculate length */
    icmp_len = *len - icmp_len;

    /* Update checksum */
    *(uint16_t*)(start + 2) = bbl_checksum(start, icmp_len);

    return PROTOCOL_SUCCESS;
}

/*
 * encode_igmp
 */
static protocol_error_t
encode_igmp(uint8_t *buf, uint16_t *len,
            bbl_igmp_s *igmp)
{
    uint8_t *start = buf;
    uint16_t igmp_len = *len;

    int i, i2;

    /* The first 4 bytes are equal for all IGMP messages ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Type = 0x11  | Max Resp Code |           Checksum            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
    *(uint64_t*)buf = 0;
    *buf = igmp->type;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    /* Following bytes will differ */
    switch(igmp->type) {
        case IGMP_TYPE_QUERY:
        case IGMP_TYPE_REPORT_V1:
        case IGMP_TYPE_REPORT_V2:
        case IGMP_TYPE_LEAVE:
            *(uint32_t*)buf = igmp->group;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            break;
        case IGMP_TYPE_REPORT_V3:
            *(uint16_t*)buf = 0;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            /* Group record count */
            *(uint16_t*)buf = htobe16(igmp->group_records);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            /* Group records */
            if(igmp->group_records) {
                for(i=0; i < igmp->group_records && i < IGMP_MAX_GROUPS; i++) {
                    /* Start Record */
                    *buf = igmp->group_record[i].type;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    /* Aux data len */
                    *buf = 0;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    /* Number of sources */
                    *(uint16_t*)buf = htobe16(igmp->group_record[i].sources);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
                    /* Group address */
                    *(uint32_t*)buf = igmp->group_record[i].group;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    for(i2=0; i2 < igmp->group_record[i].sources && i2 < IGMP_MAX_SOURCES; i2++) {
                        /* Source address */
                        *(uint32_t*)buf = igmp->group_record[i].source[i2];
                        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    }
                }
            } else {
                /* No records */
                *(uint16_t*)buf = 0;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            }
            break;
    }

    /* Calculate length */
    igmp_len = *len - igmp_len;

    /* Update checksum */
    *(uint16_t*)(start + 2) = bbl_checksum(start, igmp_len);

    return PROTOCOL_SUCCESS;
}

/*
 * encode_ospf
 */
static protocol_error_t
encode_ospf(uint8_t *buf, uint16_t *len, bbl_ospf_s *ospf)
{
    /* OSPF PDU */
    memcpy(buf, ospf->pdu, ospf->pdu_len);
    BUMP_WRITE_BUFFER(buf, len, ospf->pdu_len);
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ipv6
 */
static protocol_error_t
encode_ipv6(uint8_t *buf, uint16_t *len,
            bbl_ipv6_s *ipv6)
{
    protocol_error_t result;

    uint8_t *start = buf;
    uint16_t ipv6_len;

    *(uint64_t*)buf = 0;
    *(uint16_t*)buf |= be16toh(ipv6->tos << 4);
    *buf |= 6 <<4;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    /* Skip payload length field */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    *buf = ipv6->protocol;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    *buf = ipv6->ttl;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    memcpy(buf, ipv6->src, IPV6_ADDR_LEN);
    BUMP_WRITE_BUFFER(buf, len, IPV6_ADDR_LEN);
    memcpy(buf, ipv6->dst, IPV6_ADDR_LEN);
    BUMP_WRITE_BUFFER(buf, len, IPV6_ADDR_LEN);

    ipv6_len = *len;
    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_ICMPV6:
            result = encode_icmpv6(buf, len, (bbl_icmpv6_s*)ipv6->next);
            ipv6_len = *len - ipv6_len;
            /* Update icmpv6 checksum */
            *(uint16_t*)(buf + 2) = bbl_ipv6_icmpv6_checksum(ipv6->src, ipv6->dst, buf, ipv6_len);
            break;
        case IPV6_NEXT_HEADER_UDP:
            result = encode_udp(buf, len, (bbl_udp_s*)ipv6->next);
            ipv6_len = *len - ipv6_len;
            /* Update UDP length */
            *(uint16_t*)(buf + 4) = htobe16(ipv6_len);
            if(((bbl_udp_s*)ipv6->next)->protocol != UDP_PROTOCOL_BBL) {
                /* Update UDP checksum */
                *(uint16_t*)(buf + 6) = bbl_ipv6_udp_checksum(ipv6->src, ipv6->dst, buf, ipv6_len);
            }
            break;
        case IPV6_NEXT_HEADER_OSPF:
            result = encode_ospf(buf, len, (bbl_ospf_s*)ipv6->next);
            ipv6_len = *len - ipv6_len;
            break;
        default:
            ipv6_len = 0;
            result = UNKNOWN_PROTOCOL;
            break;
    }

    /* Update payload length */
    *(uint16_t*)(start + 4) = htobe16(ipv6_len);

    return result;
}

/*
 * encode_ipv4
 */
static protocol_error_t
encode_ipv4(uint8_t *buf, uint16_t *len,
            bbl_ipv4_s *ipv4)
{
    protocol_error_t result;

    uint8_t *start = buf;
    uint16_t ipv4_len = *len;
    uint16_t udp_len;
    uint8_t header_len = 5; /* header length 20 (4 * 5) */

    if(ipv4->router_alert_option) {
        header_len++;
    }

    /* Set version 4 and header length to 20 */
    *buf = 64;
    *buf |= header_len;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    *buf = ipv4->tos;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Skip total length field */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    /* Fragmentation fields
     * (Identification, Flags, Fragment Offset) */
    *(uint16_t*)buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(ipv4->offset);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    *buf = ipv4->ttl;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    *buf = ipv4->protocol;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Set header checksum to zero */
    *(uint16_t*)buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    *(uint32_t*)buf = ipv4->src;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    *(uint32_t*)buf = ipv4->dst;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    if(ipv4->router_alert_option) {
        *buf = 0x94;
        *(buf+1) = 0x04;
        *(buf+2) = 0x00;
        *(buf+3) = 0x00;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }

    /* Add protocol */
    switch(ipv4->protocol) {
        case PROTOCOL_IPV4_IGMP:
            result = encode_igmp(buf, len, (bbl_igmp_s*)ipv4->next);
            break;
        case PROTOCOL_IPV4_ICMP:
            result = encode_icmp(buf, len, (bbl_icmp_s*)ipv4->next);
            break;
        case PROTOCOL_IPV4_UDP:
            udp_len = *len;
            result = encode_udp(buf, len, (bbl_udp_s*)ipv4->next);
            udp_len = *len - udp_len;
            /* Update UDP length */
            *(uint16_t*)(buf + 4) = htobe16(udp_len);
            if(((bbl_udp_s*)ipv4->next)->protocol != UDP_PROTOCOL_BBL &&
               ((bbl_udp_s*)ipv4->next)->protocol != UDP_PROTOCOL_L2TP) {
                /* Update UDP checksum */
                *(uint16_t*)(buf + 6) = bbl_ipv4_udp_checksum(ipv4->src, ipv4->dst, buf, udp_len);
            }
            break;
        case PROTOCOL_IPV4_OSPF:
            result = encode_ospf(buf, len, (bbl_ospf_s*)ipv4->next);
            break;
        default:
            result = PROTOCOL_SUCCESS;
            break;
    }

    /* Update total length */
    ipv4_len = *len - ipv4_len;
    *(uint16_t*)(start + 2) = htobe16(ipv4_len);

    /* Update checksum */
    *(uint16_t*)(start + 10) = bbl_checksum(start, header_len * 4);

    return result;
}

/*
 * encode_ppp_pap
 */
static protocol_error_t
encode_ppp_pap(uint8_t *buf, uint16_t *len,
               bbl_pap_s *pap)
{
    uint16_t *pap_len_field = NULL;
    uint16_t  pap_len = *len;

    *buf = pap->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = pap->identifier;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    pap_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    if(pap->username) {
        *buf = pap->username_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, pap->username, pap->username_len);
        BUMP_WRITE_BUFFER(buf, len, pap->username_len);
    }
    if(pap->password) {
        *buf = pap->password_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, pap->password, pap->password_len);
        BUMP_WRITE_BUFFER(buf, len, pap->password_len);
    }
    if(pap->reply_message) {
        *buf = pap->reply_message_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, pap->reply_message, pap->reply_message_len);
        BUMP_WRITE_BUFFER(buf, len, pap->reply_message_len);
    }
    pap_len = *len - pap_len;
    *pap_len_field = htobe16(pap_len);
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ppp_chap
 */
static protocol_error_t
encode_ppp_chap(uint8_t *buf, uint16_t *len,
                bbl_chap_s *chap)
{
    uint16_t *chap_len_field = NULL;
    uint16_t  chap_len = *len;

    *buf = chap->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = chap->identifier;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    chap_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    if(chap->challenge) {
        *buf = chap->challenge_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, chap->challenge, chap->challenge_len);
        BUMP_WRITE_BUFFER(buf, len, chap->challenge_len);
    }
    if(chap->name) {
        memcpy(buf, chap->name, chap->name_len);
        BUMP_WRITE_BUFFER(buf, len, chap->name_len);
    }
    if(chap->reply_message) {
        memcpy(buf, chap->reply_message, chap->reply_message_len);
        BUMP_WRITE_BUFFER(buf, len, chap->reply_message_len);
    }
    chap_len = *len - chap_len;
    *chap_len_field = htobe16(chap_len);
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ppp_ip6cp
 */
static protocol_error_t
encode_ppp_ip6cp(uint8_t *buf, uint16_t *len,
                 bbl_ip6cp_s *ip6cp)
{
    uint16_t *ip6cp_len_field;
    uint16_t  ip6cp_len = 0;

    *buf = ip6cp->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = ip6cp->identifier;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    /* Remember LCP length field position */
    ip6cp_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    if(ip6cp->options && ip6cp->options_len) {
        /* Copy options from here ... */
        memcpy(buf, ip6cp->options, ip6cp->options_len);
        BUMP_WRITE_BUFFER(buf, len, ip6cp->options_len);
        ip6cp_len = ip6cp->options_len + 4;
        *ip6cp_len_field = htobe16(ip6cp_len);
    } else {
        /* Constuct options ... */
        ip6cp_len = 4;
        *buf = PPP_IP6CP_OPTION_IDENTIFIER;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 10;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint64_t*)buf = ip6cp->ipv6_identifier;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint64_t));
        ip6cp_len += 10;
        *ip6cp_len_field = htobe16(ip6cp_len);
    }
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ppp_ipcp
 */
static protocol_error_t
encode_ppp_ipcp(uint8_t *buf, uint16_t *len,
                bbl_ipcp_s *ipcp)
{
    uint16_t *ipcp_len_field;
    uint16_t  ipcp_len = 0;

    *buf = ipcp->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = ipcp->identifier;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    /* Remember LCP length field position */
    ipcp_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    if(ipcp->options && ipcp->options_len) {
        /* Copy options from here ... */
        memcpy(buf, ipcp->options, ipcp->options_len);
        BUMP_WRITE_BUFFER(buf, len, ipcp->options_len);
        ipcp_len = ipcp->options_len + 4;
        *ipcp_len_field = htobe16(ipcp_len);
    } else {
        /* Construct options ... */
        ipcp_len = 4;
        if(ipcp->option_address) {
            *buf = PPP_IPCP_OPTION_ADDRESS;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            *buf = 6;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            *(uint32_t*)buf = ipcp->address;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            ipcp_len += 6;
        }
        if(ipcp->option_dns1) {
            *buf = PPP_IPCP_OPTION_DNS1;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            *buf = 6;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            *(uint32_t*)buf = ipcp->dns1;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            ipcp_len += 6;
        }
        if(ipcp->option_dns2) {
            *buf = PPP_IPCP_OPTION_DNS2;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            *buf = 6;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            *(uint32_t*)buf = ipcp->dns2;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            ipcp_len += 6;
        }
        *ipcp_len_field = htobe16(ipcp_len);
    }
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ppp_lcp
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Data ...
 *  +-+-+-+-+
 */
static protocol_error_t
encode_ppp_lcp(uint8_t *buf, uint16_t *len,
               bbl_lcp_s *lcp)
{
    uint16_t *lcp_len_field;
    uint16_t  lcp_len = 0;

    *buf = lcp->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = lcp->identifier;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    /* Remember LCP length field position */
    lcp_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    if(lcp->code == PPP_CODE_ECHO_REQUEST || lcp->code == PPP_CODE_ECHO_REPLY) {
        *(uint32_t*)buf = lcp->magic;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        lcp_len = 8;
        *lcp_len_field = htobe16(lcp_len);
    } else {
        if(lcp->options && lcp->options_len) {
            /* Copy options from here ... */
            memcpy(buf, lcp->options, lcp->options_len);
            BUMP_WRITE_BUFFER(buf, len, lcp->options_len);
            lcp_len = lcp->options_len + 4;
            *lcp_len_field = htobe16(lcp_len);
        } else {
            /* Options ... */
            lcp_len = 4;
            if(lcp->mru) {
                *buf = PPP_LCP_OPTION_MRU;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 4;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint16_t*)buf = htobe16(lcp->mru);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
                lcp_len += 4;
            }
            if(lcp->auth) {
                *buf = PPP_LCP_OPTION_AUTH;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 4;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint16_t*)buf = htobe16(lcp->auth);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
                lcp_len += 4;
            }
            if(lcp->magic) {
                *buf = PPP_LCP_OPTION_MAGIC;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 6;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint32_t*)buf = lcp->magic;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                lcp_len += 6;
            }
            *lcp_len_field = htobe16(lcp_len);
        }
    }
    if(lcp->padding) {
        BUMP_WRITE_BUFFER(buf, len, lcp->padding);
    }
    return PROTOCOL_SUCCESS;
}

/*
 * encode_l2tp
 */
static protocol_error_t
encode_l2tp(uint8_t *buf, uint16_t *len, bbl_l2tp_s *l2tp)
{
    protocol_error_t result;
    uint16_t *l2tp_len_field = NULL;
    uint16_t  l2tp_len = *len;
    *(uint64_t*)buf = 0;
    /* Set flags */
    if(l2tp->type) {
        /* L2TP control packet */
        *buf |= L2TP_HDR_CTRL_BIT_MASK;
        *buf |= L2TP_HDR_LEN_BIT_MASK;
        *buf |= L2TP_HDR_SEQ_BIT_MASK;
        l2tp->with_length = true;
        l2tp->with_sequence = true;
    } else {
        if(l2tp->with_length) *buf |= L2TP_HDR_LEN_BIT_MASK;
    }
    if(l2tp->with_offset) *buf |= L2TP_HDR_OFFSET_BIT_MASK;
    if(l2tp->with_priority) *buf |= L2TP_HDR_PRIORITY_BIT_MASK;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 2; /* Set L2TP version */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    if(l2tp->with_length) {
        /* Remember L2TP length field position */
        l2tp_len_field = (uint16_t*)buf;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
    *(uint16_t*)buf = htobe16(l2tp->tunnel_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *(uint16_t*)buf = htobe16(l2tp->session_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    if(l2tp->with_sequence) {
        *(uint16_t*)buf = htobe16(l2tp->ns);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(l2tp->nr);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
    if(l2tp->with_offset) {
        *(uint16_t*)buf = htobe16(l2tp->offset);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        if(l2tp->offset) {
            BUMP_WRITE_BUFFER(buf, len, l2tp->offset);
        }
    }
    if(l2tp->type) {
        /* L2TP control packet */
        if(l2tp->payload && l2tp->payload_len) {
            memcpy(buf, l2tp->payload, l2tp->payload_len);
            BUMP_WRITE_BUFFER(buf, len, l2tp->payload_len);
        }
        result = PROTOCOL_SUCCESS;
    } else {
        /* L2TP data packet */
        *buf = 0xff;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 0x03;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint16_t*)buf = htobe16(l2tp->protocol);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        /* Add protocol */
        switch(l2tp->protocol) {
            case PROTOCOL_LCP:
                result = encode_ppp_lcp(buf, len, (bbl_lcp_s*)l2tp->next);
                break;
            case PROTOCOL_IPCP:
                result = encode_ppp_ipcp(buf, len, (bbl_ipcp_s*)l2tp->next);
                break;
            case PROTOCOL_IP6CP:
                result = encode_ppp_ip6cp(buf, len, (bbl_ip6cp_s*)l2tp->next);
                break;
            case PROTOCOL_PAP:
                result = encode_ppp_pap(buf, len, (bbl_pap_s*)l2tp->next);
                break;
            case PROTOCOL_CHAP:
                result = encode_ppp_chap(buf, len, (bbl_chap_s*)l2tp->next);
                break;
            case PROTOCOL_IPV4:
                result = encode_ipv4(buf, len, (bbl_ipv4_s*)l2tp->next);
                break;
            case PROTOCOL_IPV6:
                result = encode_ipv6(buf, len, (bbl_ipv6_s*)l2tp->next);
                break;
            default:
                result = UNKNOWN_PROTOCOL;
                break;
        }
    }
    if(l2tp->with_length && l2tp_len_field) {
        l2tp_len = *len - l2tp_len;
        *l2tp_len_field = htobe16(l2tp_len);
    }
    return result;
}

/*
 * encode_pppoe_discovery
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  VER  | TYPE  |      CODE     |          SESSION_ID           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            LENGTH             |           payload             ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static protocol_error_t
encode_pppoe_discovery(uint8_t *buf, uint16_t *len,
                       bbl_pppoe_discovery_s *pppoe)
{
    uint16_t *pppoe_len_field;
    uint16_t *vendor_len_field;
    uint16_t  pppoe_len = 0;
    uint16_t  vendor_len;
    uint8_t   str_len;

    bbl_access_line_profile_s *access_line_profile;

    /* Set version and type to 1 */
    *buf = 17;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = pppoe->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(pppoe->session_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    /* Remember PPPoE length field position */
    pppoe_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    if(pppoe->code != PPPOE_PADT) {
        *(uint16_t*)buf = htobe16(PPPOE_TAG_SERVICE_NAME);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(pppoe->service_name_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        pppoe_len += 4;
        /* When the tag length is zero this tag is used to indicate that
         * any service is acceptable. */
        if(pppoe->service_name_len) {
            memcpy(buf, pppoe->service_name, pppoe->service_name_len);
            BUMP_WRITE_BUFFER(buf, len, pppoe->service_name_len);
            pppoe_len += pppoe->service_name_len;
        }
        if(pppoe->host_uniq_len) {
            *(uint16_t*)buf = htobe16(PPPOE_TAG_HOST_UNIQ);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            *(uint16_t*)buf = htobe16(pppoe->host_uniq_len);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            pppoe_len += 4;
            memcpy(buf, pppoe->host_uniq, pppoe->host_uniq_len);
            BUMP_WRITE_BUFFER(buf, len, pppoe->host_uniq_len);
            pppoe_len += pppoe->host_uniq_len;
        }
        if(pppoe->max_payload) {
            *(uint16_t*)buf = htobe16(PPPOE_TAG_MAX_PAYLOAD);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            *(uint16_t*)buf = htobe16(sizeof(uint16_t));
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            *(uint16_t*)buf = htobe16(pppoe->max_payload);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            pppoe_len += 6;
        }
        if(pppoe->ac_cookie) {
            *(uint16_t*)buf = htobe16(PPPOE_TAG_AC_COOKIE);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            *(uint16_t*)buf = htobe16(pppoe->ac_cookie_len);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            pppoe_len += 4;
            memcpy(buf, pppoe->ac_cookie, pppoe->ac_cookie_len);
            BUMP_WRITE_BUFFER(buf, len, pppoe->ac_cookie_len);
            pppoe_len += pppoe->ac_cookie_len;
        }
        if(pppoe->access_line) {
            *(uint16_t*)buf = htobe16(PPPOE_TAG_VENDOR);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            vendor_len_field = (uint16_t*)buf;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            *(uint32_t*)buf = htobe32(BROADBAND_FORUM_VENDOR_ID);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
            vendor_len = 4;
            if(pppoe->access_line->aci) {
                *buf = ACCESS_LINE_ACI;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                str_len = strnlen(pppoe->access_line->aci, 128);
                *buf = str_len;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                memcpy(buf, pppoe->access_line->aci, str_len);
                BUMP_WRITE_BUFFER(buf, len, str_len);
                vendor_len += 2 + str_len;
            }
            if(pppoe->access_line->ari) {
                *buf = ACCESS_LINE_ARI;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                str_len = strnlen(pppoe->access_line->ari, 128);
                *buf = str_len;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                memcpy(buf, pppoe->access_line->ari, str_len);
                BUMP_WRITE_BUFFER(buf, len, str_len);
                vendor_len += 2 + str_len;
            }
            if(pppoe->access_line->aaci) {
                *buf = ACCESS_LINE_AGG_ACC_CIRCUIT_ID_ASCII;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                str_len = strnlen(pppoe->access_line->aaci, 128);
                *buf = str_len;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                memcpy(buf, pppoe->access_line->aaci, str_len);
                BUMP_WRITE_BUFFER(buf, len, str_len);
                vendor_len += 2 + str_len;
            }
            if(pppoe->access_line->up) {
                *buf = ACCESS_LINE_ACT_UP;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 4;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint32_t*)buf = htobe32(pppoe->access_line->up);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                vendor_len += 6;
            }
            if(pppoe->access_line->down) {
                *buf = ACCESS_LINE_ACT_DOWN;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 4;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint32_t*)buf = htobe32(pppoe->access_line->down);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                vendor_len += 6;
            }
            if(pppoe->access_line->dsl_type) {
                *buf = ACCESS_LINE_DSL_TYPE;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 4;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint32_t*)buf = htobe32(pppoe->access_line->dsl_type);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                vendor_len += 6;
            }
            access_line_profile = pppoe->access_line->profile;
            if(access_line_profile) {
                if(access_line_profile->min_up) {
                    *buf = ACCESS_LINE_MIN_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->min_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->min_down) {
                    *buf = ACCESS_LINE_MIN_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->min_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->att_up) {
                    *buf = ACCESS_LINE_ATT_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->att_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->att_down) {
                    *buf = ACCESS_LINE_ATT_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->att_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->max_up) {
                    *buf = ACCESS_LINE_MAX_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->max_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->max_down) {
                    *buf = ACCESS_LINE_MAX_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->max_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->min_up_low) {
                    *buf = ACCESS_LINE_MIN_UP_LOW;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->min_up_low);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->min_down_low) {
                    *buf = ACCESS_LINE_MIN_DOWN_LOW;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->min_down_low);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->max_interl_delay_up) {
                    *buf = ACCESS_LINE_MAX_INTERL_DELAY_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->max_interl_delay_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->act_interl_delay_up) {
                    *buf = ACCESS_LINE_ACT_INTERL_DELAY_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->act_interl_delay_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->max_interl_delay_down) {
                    *buf = ACCESS_LINE_MAX_INTERL_DELAY_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->max_interl_delay_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->act_interl_delay_down) {
                    *buf = ACCESS_LINE_ACT_INTERL_DELAY_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->act_interl_delay_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->data_link_encaps) {
                    *buf = ACCESS_LINE_DATA_LINK_ENCAPS;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    /* (1)byte   + (1)byte  + (1)byte
                    * data link   encaps 1   encaps 2 */
                    *(uint32_t*)buf = htobe32(access_line_profile->data_link_encaps);
                    *buf = 3;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 5;
                }
                if(access_line_profile->dsl_type) {
                    *buf = ACCESS_LINE_DSL_TYPE;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->dsl_type);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->pon_type) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_PON_TYPE_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_PON_TYPE;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->pon_type);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->etr_up) {
                    *buf = ACCESS_LINE_ETR_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->etr_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->etr_down) {
                    *buf = ACCESS_LINE_ETR_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->etr_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->attetr_up) {
                    *buf = ACCESS_LINE_ATTETR_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->attetr_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->attetr_down) {
                    *buf = ACCESS_LINE_ATTETR_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->attetr_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->gdr_up) {
                    *buf = ACCESS_LINE_GDR_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->gdr_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->gdr_down) {
                    *buf = ACCESS_LINE_GDR_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->gdr_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->attgdr_up) {
                    *buf = ACCESS_LINE_ATTGDR_UP;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->attgdr_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->attgdr_down) {
                    *buf = ACCESS_LINE_ATTGDR_DOWN;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->attgdr_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->ont_onu_avg_down) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_ONT_ONU_AVG_DOWN_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_ONT_ONU_AVG_DOWN;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->ont_onu_avg_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->ont_onu_peak_down) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_ONT_ONU_PEAK_DOWN_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_ONT_ONU_PEAK_DOWN;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->ont_onu_peak_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->ont_onu_max_up) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_ONT_ONU_MAX_UP_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_ONT_ONU_MAX_UP;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->ont_onu_max_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->ont_onu_ass_up) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_ONT_ONU_ASS_UP_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_ONT_ONU_ASS_UP;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->ont_onu_ass_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->pon_max_up) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_PON_MAX_UP_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_PON_MAX_UP;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->pon_max_up);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
                if(access_line_profile->pon_max_down) {
                    switch(access_line_profile->pon_access_line_version) {
                      case DRAFT_LIHAWI_00:
                          *buf = ACCESS_LINE_PON_MAX_DOWN_LIHAWI_00;
                           break;
                      default:
                          *buf = ACCESS_LINE_PON_MAX_DOWN;
                           break;
                    }
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *buf = 4;
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                    *(uint32_t*)buf = htobe32(access_line_profile->pon_max_down);
                    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                    vendor_len += 6;
                }
            }
            *vendor_len_field = htobe16(vendor_len);
            pppoe_len += 4 + vendor_len;
        }
    }
    *pppoe_len_field = htobe16(pppoe_len);
    return PROTOCOL_SUCCESS;
}

/*
 * encode_pppoe_session
 */
static protocol_error_t
encode_pppoe_session(uint8_t *buf, uint16_t *len,
                     bbl_pppoe_session_s *pppoe)
{
    protocol_error_t result = PROTOCOL_SUCCESS;
    uint16_t *pppoe_len_field;
    uint16_t  pppoe_len = 0;

    /* Set version and type to 1 */
    *buf = 17;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(pppoe->session_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    /* Remember PPPoE length field position */
    pppoe_len_field = (uint16_t*)buf;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    /* Add PPP header */
    *(uint16_t*)buf = htobe16(pppoe->protocol);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    pppoe_len = *len;

#ifdef BNGBLASTER_LWIP
    if(pppoe->lwip) {
        struct pbuf *p = pppoe->next; 
        while(p) {
            memcpy(buf, p->payload, p->len);
            BUMP_WRITE_BUFFER(buf, len, p->len);
            p = p->next;
        }
    } else {
#endif
        /* Add protocol */
        switch(pppoe->protocol) {
            case PROTOCOL_LCP:
                result = encode_ppp_lcp(buf, len, (bbl_lcp_s*)pppoe->next);
                break;
            case PROTOCOL_IPCP:
                result = encode_ppp_ipcp(buf, len, (bbl_ipcp_s*)pppoe->next);
                break;
            case PROTOCOL_IP6CP:
                result = encode_ppp_ip6cp(buf, len, (bbl_ip6cp_s*)pppoe->next);
                break;
            case PROTOCOL_PAP:
                result = encode_ppp_pap(buf, len, (bbl_pap_s*)pppoe->next);
                break;
            case PROTOCOL_CHAP:
                result = encode_ppp_chap(buf, len, (bbl_chap_s*)pppoe->next);
                break;
            case PROTOCOL_IPV4:
                result = encode_ipv4(buf, len, (bbl_ipv4_s*)pppoe->next);
                break;
            case PROTOCOL_IPV6:
                result = encode_ipv6(buf, len, (bbl_ipv6_s*)pppoe->next);
                break;
            default:
                result = UNKNOWN_PROTOCOL;
                break;
        }
#ifdef BNGBLASTER_LWIP
    }
#endif

    pppoe_len = *len - pppoe_len;
    pppoe_len += 2; /* PPP header */
    *pppoe_len_field = htobe16(pppoe_len);
    return result;
}

/*
 * encode_cfm
 */
static protocol_error_t
encode_cfm(uint8_t *buf, uint16_t *len, bbl_cfm_s *cfm)
{
    uint8_t max_ma_str_len = 45;

    if(cfm->type != CFM_TYPE_CCM) {
        /* Currently only CFM CC is supported */
        return ENCODE_ERROR;
    }

    *buf = cfm->md_level << 5; /* CFM MD level and version */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = cfm->type; /* CFM OpCode */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Set CFM CC interval fixed to 1s (4) */
    *buf = 4;
    if(cfm->rdi) {
        /* Set RDI bit */
        *buf |= 128;
    }
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Remember first TLV offset position */
    *buf = 70;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    memset(buf, 0x0, 70);

    /* Sequence Number */
    *(uint32_t*)buf = htobe32(cfm->seq);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    /* MA Identifier */
    *(uint16_t*)buf = htobe16(cfm->ma_id);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    /* MD Name */
    *buf = cfm->md_name_format;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    if(cfm->md_name_format != CMF_MD_NAME_FORMAT_NONE) {
        if(cfm->md_name_len > 32) cfm->md_name_len = 32;
        *buf = cfm->md_name_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, cfm->md_name, cfm->md_name_len);
        BUMP_WRITE_BUFFER(buf, len, cfm->md_name_len);
        max_ma_str_len -= cfm->md_name_len + 1;
    }
    /* MA Name */
    *buf = cfm->ma_name_format;
    if(cfm->ma_name_len > max_ma_str_len) cfm->ma_name_len = max_ma_str_len;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = cfm->ma_name_len;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    memcpy(buf, cfm->ma_name, cfm->ma_name_len);
    BUMP_WRITE_BUFFER(buf, len, max_ma_str_len);

    /* Y.1731 */
    BUMP_WRITE_BUFFER(buf, len, 16);

    /* CFM TLVs */

    /* Sender ID TLV */
    *buf = 1;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(1);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Port Status TLV */
    *buf = 2;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(1);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *buf = 2; /* UP */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* Interface Status TLV */
    *buf = 4;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(1);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *buf = 1; /* UP */
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* End TLV */
    *buf = 0;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    return PROTOCOL_SUCCESS;
}

/*
 * encode_isis
 */
static protocol_error_t
encode_isis(uint8_t *buf, uint16_t *len, bbl_isis_s *isis)
{
    /* LLC header ... */
    *(uint16_t*)buf = 0xfefe;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    *buf = 0x03;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* ISIS PDU */
    memcpy(buf, isis->pdu, isis->pdu_len);
    BUMP_WRITE_BUFFER(buf, len, isis->pdu_len);
    return PROTOCOL_SUCCESS;
}

/*
 * encode_ethernet
 */
protocol_error_t
encode_ethernet(uint8_t *buf, uint16_t *len,
                bbl_ethernet_header_s *eth)
{
    bbl_mpls_s *mpls;
    uint16_t  eth_len; /* 802.3 ethernet header length */
    uint16_t *eth_len_ptr; /* 802.3 ethernet header length ptr */

    if(eth->dst) {
        memcpy(buf, eth->dst, ETH_ADDR_LEN);
    } else {
        /* Default broadcast */
        memset(buf, 0xff, ETH_ADDR_LEN);
    }
    BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);

    memcpy(buf, eth->src, ETH_ADDR_LEN);
    BUMP_WRITE_BUFFER(buf, len, ETH_ADDR_LEN);

    /* Add VLAN header */
    if(eth->vlan_outer) {
        if(eth->qinq) {
            *(uint16_t*)buf = htobe16(ETH_TYPE_QINQ);
        } else {
            *(uint16_t*)buf = htobe16(ETH_TYPE_VLAN);
        }
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        eth->vlan_outer |= eth->vlan_outer_priority << 13;
        *(uint16_t*)buf = htobe16(eth->vlan_outer);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        if(eth->vlan_inner) {
            *(uint16_t*)buf = htobe16(ETH_TYPE_VLAN);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            eth->vlan_inner |= eth->vlan_inner_priority << 13;
            *(uint16_t*)buf = htobe16(eth->vlan_inner);
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            if(eth->vlan_three) {
                *(uint16_t*)buf = htobe16(ETH_TYPE_VLAN);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
                *(uint16_t*)buf = htobe16(eth->vlan_three);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
            }
        }
    }

    if(eth->mpls) {
        /* Add ethertype MPLS */
        *(uint16_t*)buf = htobe16(ETH_TYPE_MPLS);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        /* Add labels ... */
        mpls = eth->mpls;
        while(mpls) {
            *(buf+2) = mpls->exp << 1;
            *(buf+3) = mpls->ttl;
            *(uint32_t*)buf |= htobe32(mpls->label << 12);
            mpls = mpls->next;
            if(!mpls) {
                *(buf+2) |= 0x1; /* set BOS bit*/
            }
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        }
    } else if(eth->type == ISIS_PROTOCOL_IDENTIFIER) {
        /* Remember ethernet length field position */
        eth_len_ptr = (uint16_t*)buf;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        eth_len = *len;
        if(encode_isis(buf, len, (bbl_isis_s*)eth->next) == PROTOCOL_SUCCESS)  {
            /* Update ethernet length field */
            *eth_len_ptr = htobe16(*len - eth_len);
            return PROTOCOL_SUCCESS;
        } else {
            return ENCODE_ERROR;
        }
    } else {
        /* Add ethertype */
        *(uint16_t*)buf = htobe16(eth->type);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
#ifdef BNGBLASTER_LWIP
    if(eth->lwip) {
        struct pbuf *p = eth->next; 
        while(p) {
            memcpy(buf, p->payload, p->len);
            BUMP_WRITE_BUFFER(buf, len, p->len);
            p = p->next;
        }
        return PROTOCOL_SUCCESS;
    }
#endif

    /* Add protocol header */
    switch(eth->type) {
        case ETH_TYPE_PPPOE_DISCOVERY:
            return encode_pppoe_discovery(buf, len, (bbl_pppoe_discovery_s*)eth->next);
        case ETH_TYPE_PPPOE_SESSION:
            return encode_pppoe_session(buf, len, (bbl_pppoe_session_s*)eth->next);
        case ETH_TYPE_ARP:
            return encode_arp(buf, len, (bbl_arp_s*)eth->next);
        case ETH_TYPE_IPV4:
            return encode_ipv4(buf, len, (bbl_ipv4_s*)eth->next);
        case ETH_TYPE_IPV6:
            return encode_ipv6(buf, len, (bbl_ipv6_s*)eth->next);
        case ETH_TYPE_CFM:
            return encode_cfm(buf, len, (bbl_cfm_s*)eth->next);
        case ETH_TYPE_LACP:
            return encode_lacp(buf, len, (bbl_lacp_s*)eth->next);
        default:
            return UNKNOWN_PROTOCOL;
    }
}

/*
 * DECODE
 * ------------------------------------------------------------------------*/

/*
 * decode_lacp
 */
static protocol_error_t
decode_lacp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_lacp_s **_lacp) 
{
    bbl_lacp_s *lacp;
    uint8_t tlv_type;
    uint8_t tlv_len;

    if(len && *buf != SLOW_PROTOCOLS_LACP) {
        return UNKNOWN_PROTOCOL;
    }
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    if(len < 109 || sp_len < sizeof(bbl_lacp_s)) {
        return DECODE_ERROR;
    }

    /* Init LACP header */
    lacp = (bbl_lacp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_lacp_s));
    memset(lacp, 0x0, sizeof(bbl_lacp_s));

    /* Check LACP Version */
    if(*buf != 1) {
        return DECODE_ERROR;
    }
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    /* Decode TLV's */
    while(len >= 2) {
        tlv_type = *buf;
        tlv_len = *(buf+1);
        if(tlv_len > len) {
            return DECODE_ERROR;
        }
        switch(tlv_type) {
            case LACP_TLV_TERMINATOR:
                len = 0;
                break;
            case LACP_TLV_ACTOR_INFORMATION:
                if(tlv_len != 20) {
                    return DECODE_ERROR;
                }
                lacp->actor_system_priority = be16toh(*(uint16_t*)(buf+2));
                lacp->actor_system_id = buf+4;
                lacp->actor_key = be16toh(*(uint16_t*)(buf+10));
                lacp->actor_port_priority = be16toh(*(uint16_t*)(buf+12));
                lacp->actor_port_id = be16toh(*(uint16_t*)(buf+14));
                lacp->actor_state = *(buf+16);
                break;
            case LACP_TLV_PARTNER_INFORMATION:
                if(tlv_len != 20) {
                    return DECODE_ERROR;
                }
                lacp->partner_system_priority = be16toh(*(uint16_t*)(buf+2));
                lacp->partner_system_id = buf+4;
                lacp->partner_key = be16toh(*(uint16_t*)(buf+10));
                lacp->partner_port_priority = be16toh(*(uint16_t*)(buf+12));
                lacp->partner_port_id = be16toh(*(uint16_t*)(buf+14));
                lacp->partner_state = *(buf+16);
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, tlv_len);
    }

    *_lacp = lacp;
    return PROTOCOL_SUCCESS;

}

/*
 * decode_icmp
 */
static protocol_error_t
decode_icmp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_icmp_s **_icmp)
{

    bbl_icmp_s *icmp;

    if(len < 4 || sp_len < sizeof(bbl_icmp_s)) {
        return DECODE_ERROR;
    }

    /* Init ICMP header */
    icmp = (bbl_icmp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_icmp_s));

    icmp->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    icmp->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    BUMP_BUFFER(buf, len, sizeof(uint16_t)); /* checksum */

    if(len) {
        icmp->data = buf;
        icmp->data_len = len;
    }
    *_icmp = icmp;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_icmpv6
 */
static protocol_error_t
decode_icmpv6(uint8_t *buf, uint16_t len,
              uint8_t *sp, uint16_t sp_len,
              bbl_icmpv6_s **_icmpv6)
{
    bbl_icmpv6_s *icmpv6;

    uint8_t  option;
    uint16_t option_len;

    if(len < 4 || sp_len < sizeof(bbl_icmpv6_s)) {
        return DECODE_ERROR;
    }

    /* Init ICMP header */
    icmpv6 = (bbl_icmpv6_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_icmpv6_s));
    memset(icmpv6, 0x0, sizeof(bbl_icmpv6_s));

    icmpv6->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    icmpv6->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    BUMP_BUFFER(buf, len, sizeof(uint16_t)); /* checksum */

    if(len) {
        icmpv6->data = buf;
        icmpv6->data_len = len;
    }

    switch(icmpv6->type) {
        case IPV6_ICMPV6_ROUTER_ADVERTISEMENT:
            if(len < 12) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint8_t)); /* hop limit */
            icmpv6->flags = *buf;
            BUMP_BUFFER(buf, len, 11);
            while(len >= 8) {
                option = *buf;
                BUMP_BUFFER(buf, len, sizeof(uint8_t));
                option_len = *buf;
                option_len = option_len * 8;
                BUMP_BUFFER(buf, len, sizeof(uint8_t));
                if(option_len < 2 || len < option_len-2) {
                    return DECODE_ERROR;
                }
                if(option == ICMPV6_OPTION_PREFIX) {
                    if(option_len < 32) {
                        return DECODE_ERROR;
                    }
                    icmpv6->prefix.len = *buf;
                    memcpy(&icmpv6->prefix.address, buf+14, IPV6_ADDR_LEN);
                } else if(option == ICMPV6_OPTION_DNS) {
                    if(option_len >= 24) {
                        icmpv6->dns1 = (ipv6addr_t*)(buf+6);
                        if(option_len >= 40) {
                            icmpv6->dns2 = (ipv6addr_t*)(buf+22);
                        }
                    }
                }
                BUMP_BUFFER(buf, len, option_len-2);
            }
            break;
        case IPV6_ICMPV6_NEIGHBOR_SOLICITATION:
            if(len < 20) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint32_t)); /* flags / reserved */
            memcpy(&icmpv6->prefix.address, buf, IPV6_ADDR_LEN);
            break;
        case IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT:
            if(len < 20) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint32_t)); /* flags / reserved */
            memcpy(&icmpv6->prefix.address, buf, IPV6_ADDR_LEN);
            BUMP_BUFFER(buf, len, IPV6_ADDR_LEN);
            while(len >= 8) {
                option = *buf;
                BUMP_BUFFER(buf, len, sizeof(uint8_t));
                option_len = (*buf) * 8;
                BUMP_BUFFER(buf, len, sizeof(uint8_t));
                if(option_len < 2 || len < option_len - 2) {
                    return DECODE_ERROR;
                }
                if(option == ICMPV6_OPTION_DEST_LINK_LAYER) {
                    if(option_len != 8) {
                        // Maleformed ICMPv6 packet
                        return DECODE_ERROR;
                    }
                    icmpv6->dst_mac = buf;
                    break;
                }
                BUMP_BUFFER(buf, len, option_len-2);
            }
            break;
        default:
            break;
    }

    *_icmpv6 = icmpv6;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_igmp
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Type     | Max Resp Time |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Group Address                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static protocol_error_t
decode_igmp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_igmp_s **_igmp)
{
    bbl_igmp_s *igmp;

    uint16_t sources;

    if(len < 8 || sp_len < sizeof(bbl_igmp_s)) {
        return DECODE_ERROR;
    }

    /* Init IGMP header */
    igmp = (bbl_igmp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_igmp_s));
    memset(igmp, 0x0, sizeof(bbl_igmp_s));

    if(len < 12) {
        igmp->version = IGMP_VERSION_1;
    } else {
        igmp->version = IGMP_VERSION_3;
    }

    igmp->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    /* Skip max resp time */
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    /* Skip checksum */
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    switch(igmp->type) {
        case IGMP_TYPE_QUERY:
            igmp->group = *(uint32_t*)buf;
            BUMP_BUFFER(buf, len, sizeof(uint32_t));
            if(igmp->version == IGMP_VERSION_3) {
                /* For IGMPv3 the is more to do ... */
                igmp->robustness = *buf & 0x7;
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
                sources = be16toh(*(uint16_t*)buf);
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
                if(sources) {
                    igmp->source = *(uint32_t*)buf;
                }
            }
            break;
        case IGMP_TYPE_REPORT_V1:
            igmp->group = *(uint32_t*)buf;
            BUMP_BUFFER(buf, len, sizeof(uint32_t));
            break;
        case IGMP_TYPE_REPORT_V2:
            igmp->version = IGMP_VERSION_2;
            igmp->group = *(uint32_t*)buf;
            BUMP_BUFFER(buf, len, sizeof(uint32_t));
            break;
        case IGMP_TYPE_REPORT_V3:
            igmp->version = IGMP_VERSION_3;
            /* TODO: needs to be implemented ... */
            break;
        case IGMP_TYPE_LEAVE:
            igmp->version = IGMP_VERSION_2;
            igmp->group = *(uint32_t*)buf;
            BUMP_BUFFER(buf, len, sizeof(uint32_t));
            break;
        default:
            break;
    }
    *_igmp = igmp;
    return PROTOCOL_SUCCESS;
}

static protocol_error_t
decode_dhcpv6_ia_na(uint8_t *buf, uint16_t len, bbl_dhcpv6_s *dhcpv6)
{
    uint16_t ia_option;
    uint16_t ia_option_len;

    if(len < 12) {
        return DECODE_ERROR;
    }
    dhcpv6->ia_na_option = buf;
    dhcpv6->ia_na_option_len = len;
    dhcpv6->ia_na_iaid = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    dhcpv6->ia_na_t1 = be32toh(*(uint32_t*)(buf));
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    dhcpv6->ia_na_t2 = be32toh(*(uint32_t*)(buf));
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    while(len >= 4) {
        ia_option = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        ia_option_len = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(ia_option_len > len) {
            return DECODE_ERROR;
        }
        switch(ia_option) {
            case DHCPV6_OPTION_IAADDR:
                if(ia_option_len < 24) {
                    return DECODE_ERROR;
                }
                dhcpv6->ia_na_address = (ipv6addr_t*)(buf);
                dhcpv6->ia_na_preferred_lifetime = be32toh(*(uint32_t*)(buf+16));
                dhcpv6->ia_na_valid_lifetime = be32toh(*(uint32_t*)(buf+20));
                break;
            case DHCPV6_OPTION_STATUS_CODE:
                if(ia_option_len < 2) {
                    return DECODE_ERROR;
                }
                dhcpv6->ia_na_status_code = be16toh(*(uint16_t*)buf);
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, ia_option_len);
    }
    return PROTOCOL_SUCCESS;
}

static protocol_error_t
decode_dhcpv6_ia_pd(uint8_t *buf, uint16_t len, bbl_dhcpv6_s *dhcpv6)
{

    uint16_t ia_option;
    uint16_t ia_option_len;

    if(len < 12) {
        return DECODE_ERROR;
    }
    dhcpv6->ia_pd_option = buf;
    dhcpv6->ia_pd_option_len = len;
    dhcpv6->ia_pd_iaid = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    dhcpv6->ia_pd_t1 = be32toh(*(uint32_t*)(buf));
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    dhcpv6->ia_pd_t2 = be32toh(*(uint32_t*)(buf));
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    while(len >= 4) {
        ia_option = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        ia_option_len = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(ia_option_len > len) {
            return DECODE_ERROR;
        }
        switch(ia_option) {
            case DHCPV6_OPTION_IAPREFIX:
                if(ia_option_len < 25) {
                    return DECODE_ERROR;
                }
                dhcpv6->ia_pd_preferred_lifetime = be32toh(*(uint32_t*)(buf));
                dhcpv6->ia_pd_valid_lifetime = be32toh(*(uint32_t*)(buf+4));
                dhcpv6->ia_pd_prefix = (ipv6_prefix*)(buf+8);
                break;
            case DHCPV6_OPTION_STATUS_CODE:
                if(ia_option_len < 2) {
                    return DECODE_ERROR;
                }
                dhcpv6->ia_pd_status_code = be16toh(*(uint16_t*)buf);
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, ia_option_len);
    }
    return PROTOCOL_SUCCESS;
}

/*
 * decode_dhcpv6
 */
static protocol_error_t
decode_dhcpv6(uint8_t *buf, uint16_t len,
              uint8_t *sp, uint16_t sp_len,
              bbl_dhcpv6_s **_dhcpv6,
              bool relay)
{
    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_dhcpv6_s *dhcpv6;
    uint16_t option;
    uint16_t option_len;

    if(len < 8 || sp_len < sizeof(bbl_dhcpv6_s)) {
        return DECODE_ERROR;
    }

    /* Init DHCPv6 structure */
    dhcpv6 = (bbl_dhcpv6_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_dhcpv6_s));
    memset(dhcpv6, 0x0, sizeof(bbl_dhcpv6_s));

    dhcpv6->type = *buf;
    if(dhcpv6->type == DHCPV6_MESSAGE_RELAY_FORW || 
       dhcpv6->type == DHCPV6_MESSAGE_RELAY_REPL) {
        if(relay || len < 34) {
            return DECODE_ERROR;
        }
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        dhcpv6->hops = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        dhcpv6->link_address = (ipv6addr_t*)(buf);
        BUMP_BUFFER(buf, len, sizeof(ipv6addr_t));
        dhcpv6->peer_address = (ipv6addr_t*)(buf);
        BUMP_BUFFER(buf, len, sizeof(ipv6addr_t));
    } else {
        dhcpv6->xid = be32toh(*(uint32_t*)buf) & DHCPV6_TYPE_MASK;
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
    }

    while(len >= 4) {
        option = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        option_len = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(option_len > len) {
            return DECODE_ERROR;
        }
        switch(option) {
            case DHCPV6_OPTION_RAPID_COMMIT:
                dhcpv6->rapid = true;
                break;
            case DHCPV6_OPTION_IA_NA:
                if(decode_dhcpv6_ia_na(buf, option_len, dhcpv6) != PROTOCOL_SUCCESS) {
                    return DECODE_ERROR;
                }
                break;
            case DHCPV6_OPTION_IA_PD:
                if(decode_dhcpv6_ia_pd(buf, option_len, dhcpv6) != PROTOCOL_SUCCESS) {
                    return DECODE_ERROR;
                }
                break;
            case DHCPV6_OPTION_SERVERID:
                if(option_len < 2) {
                    return DECODE_ERROR;
                }
                dhcpv6->server_duid = buf;
                dhcpv6->server_duid_len = option_len;
                break;
            case DHCPV6_OPTION_DNS_SERVERS:
                if(option_len >= 16) {
                    dhcpv6->dns1 = (ipv6addr_t*)(buf);
                    if(option_len >= 32) {
                        dhcpv6->dns2 = (ipv6addr_t*)(buf+16);
                    }
                }
                break;
            case DHCPV6_OPTION_INTERFACE_ID:
                dhcpv6->interface_id = buf;
                dhcpv6->interface_id_len = option_len;
                break;
            case DHCPV6_OPTION_RELAY_MSG:
                if(!(dhcpv6->type == DHCPV6_MESSAGE_RELAY_FORW || dhcpv6->type == DHCPV6_MESSAGE_RELAY_REPL)) {
                    return DECODE_ERROR;
                }
                if(decode_dhcpv6(buf, option_len, sp, sp_len, (bbl_dhcpv6_s**)&dhcpv6->relay_message, true) != PROTOCOL_SUCCESS) {
                    return DECODE_ERROR;
                }
            default:
                break;
        }
        BUMP_BUFFER(buf, len, option_len);
    }
    *_dhcpv6 = dhcpv6;
    return ret_val;
}

static protocol_error_t
decode_dhcp_agent(uint8_t *buf, uint16_t len,
                  uint8_t *sp, uint16_t sp_len,
                  bbl_dhcp_s *dhcp)
{
    access_line_s *access_line;
    
    uint8_t tlv_type;
    uint8_t tlv_length;

    if(dhcp->access_line) {
        access_line = dhcp->access_line;
    } else {
        access_line = (access_line_s*)sp; 
        BUMP_BUFFER(sp, sp_len, sizeof(access_line_s));
        memset(access_line, 0x0, sizeof(access_line_s));
        dhcp->access_line = access_line;
    }

    while(len > 2) {
        tlv_type = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        tlv_length = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        switch (tlv_type) {
            case ACCESS_LINE_ACI:
                if(sp_len > tlv_length) {
                    access_line->aci = (void*)sp;
                    memcpy(sp, buf, tlv_length);
                    /* zero terminate string */
                    sp += tlv_length; *sp = 0; sp++;
                } else {
                    return DECODE_ERROR;
                }
                break;
            case ACCESS_LINE_ARI:
                if(sp_len > tlv_length) {
                    access_line->ari = (void*)sp;
                    memcpy(sp, buf, tlv_length);
                    /* zero terminate string */
                    sp += tlv_length; *sp = 0; sp++;
                } else {
                    return DECODE_ERROR;
                }
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, tlv_length);
    }
    return PROTOCOL_SUCCESS;
}

/*
 * decode_dhcp
 */
static protocol_error_t
decode_dhcp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_dhcp_s **_dhcp)
{
    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_dhcp_s *dhcp;

    uint8_t option;
    uint8_t option_len;

    if(len < sizeof(struct dhcp_header) + 4 || sp_len < sizeof(bbl_dhcp_s)) {
        return DECODE_ERROR;
    }

    /* Init DHCP structure */
    dhcp = (bbl_dhcp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_dhcp_s));
    memset(dhcp, 0x0, sizeof(bbl_dhcp_s));

    dhcp->header = (struct dhcp_header*)buf;
    BUMP_BUFFER(buf, len, sizeof(struct dhcp_header));

    /* Magic Cookie */
    BUMP_BUFFER(buf, len, sizeof(uint32_t));

    while(len >= 2) {
        option = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(option == DHCP_OPTION_PAD) {
            continue;
        }
        option_len = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(option_len > len) {
            return DECODE_ERROR;
        }
        switch(option) {
            case DHCP_OPTION_END:
                option_len = len;
                break;
            case DHCP_OPTION_DHCP_MESSAGE_TYPE:
                if(option_len != 1) {
                    return DECODE_ERROR;
                }
                dhcp->type = *buf;
                break;
            case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
                if(option_len != 4) {
                    return DECODE_ERROR;
                }
                dhcp->lease_time = be32toh(*(uint32_t*)buf);
                dhcp->option_lease_time = true;
                break;
            case DHCP_OPTION_CLIENT_IDENTIFIER:
                dhcp->client_identifier = buf;
                dhcp->client_identifier_len = option_len;
                break;
            case DHCP_OPTION_SERVER_IDENTIFIER:
                if(option_len != 4) {
                    return DECODE_ERROR;
                }
                dhcp->server_identifier = *(uint32_t*)buf;
                dhcp->option_server_identifier = true;
                break;
            case DHCP_OPTION_SUBNET_MASK:
                if(option_len != 4) {
                    return DECODE_ERROR;
                }
                dhcp->netmask = *(uint32_t*)buf;
                dhcp->option_netmask = true;
                break;
            case DHCP_OPTION_ROUTER:
                if(option_len < 4) {
                    return DECODE_ERROR;
                }
                dhcp->router = *(uint32_t*)buf;
                dhcp->option_router = true;
                break;
            case DHCP_OPTION_DNS_SERVER:
                if(option_len < 4) {
                    return DECODE_ERROR;
                }
                dhcp->dns1 = *(uint32_t*)buf;
                dhcp->option_dns1 = true;
                if(option_len >=8) {
                    dhcp->dns2 = *(uint32_t*)(buf+4);
                    dhcp->option_dns2 = true;
                }
                break;
            case DHCP_OPTION_HOST_NAME:
                dhcp->host_name = (char*)buf;
                dhcp->host_name_len = option_len;
                break;
            case DHCP_OPTION_DOMAIN_NAME:
                dhcp->domain_name = (char*)buf;
                dhcp->domain_name_len = option_len;
                break;
            case DHCP_OPTION_INTERFACE_MTU:
                if(option_len != 2) {
                    return DECODE_ERROR;
                }
                dhcp->mtu = be16toh(*(uint16_t*)buf);
                dhcp->option_mtu = true;
                break;
            case DHCP_OPTION_RELAY_AGENT_INFORMATION:
                if(decode_dhcp_agent(buf, option_len, sp, sp_len, dhcp) != PROTOCOL_SUCCESS) {
                    return DECODE_ERROR;
                }
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, option_len);
    }
    *_dhcp = dhcp;
    return ret_val;
}

/*
 * decode_bbl
 */
static protocol_error_t
decode_bbl(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_bbl_s **_bbl)
{
    bbl_bbl_s *bbl;

    if(len < 48 || sp_len < sizeof(bbl_bbl_s)) {
        return DECODE_ERROR;
    }

    if(len > 48) {
        /* Bump padding... */
        BUMP_BUFFER(buf, len, (len - 48));
    }

    if(*(uint64_t*)buf != BBL_MAGIC_NUMBER) {
        return DECODE_ERROR;
    }

    /* Init BBL header */
    bbl = (bbl_bbl_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_bbl_s));

    BUMP_BUFFER(buf, len, sizeof(uint64_t));
    bbl->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    bbl->sub_type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    bbl->direction = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    bbl->tos = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    bbl->session_id = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    if(bbl->type == BBL_TYPE_UNICAST) {
        bbl->ifindex = *(uint32_t*)buf;
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
        bbl->outer_vlan_id = *(uint16_t*)buf;
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        bbl->inner_vlan_id = *(uint16_t*)buf;
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
    } else if(bbl->type == BBL_TYPE_MULTICAST) {
        bbl->mc_source = *(uint32_t*)buf;
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
        bbl->mc_group = *(uint32_t*)buf;
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
    }
    bbl->flow_id = *(uint64_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint64_t));
    bbl->flow_seq = *(uint64_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint64_t));
    bbl->timestamp.tv_sec = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    bbl->timestamp.tv_nsec = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));

    *_bbl = bbl;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_qmx_li
 */
static protocol_error_t
decode_qmx_li(uint8_t *buf, uint16_t len,
              uint8_t *sp, uint16_t sp_len,
              bbl_qmx_li_s **_qmx_li)
{
    bbl_qmx_li_s *qmx_li;

    if(len < 4 || sp_len < sizeof(bbl_qmx_li_s)) {
        return DECODE_ERROR;
    }
    /* Init QMX LI header */
    qmx_li = (bbl_qmx_li_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_qmx_li_s));
    qmx_li->header = *(uint32_t*)buf;
    qmx_li->liid = be32toh(*(uint32_t*)buf) & 0x003fffff;
    qmx_li->direction = (*buf >> 5) & 0x7;
    qmx_li->packet_type = (*buf >> 1) & 0xf;
    qmx_li->sub_packet_type =(be16toh(*(uint16_t*)buf) >> 6) & 0x07;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    qmx_li->payload = buf;
    qmx_li->payload_len = len;
    *_qmx_li = qmx_li;
    return decode_ethernet(buf, len, sp, sp_len, (bbl_ethernet_header_s**)&qmx_li->next);
}

/*
 * decode_ldp_hello
 */
static protocol_error_t
decode_ldp_hello(uint8_t *buf, uint16_t len,
                     uint8_t *sp, uint16_t sp_len,
                     bbl_ldp_hello_s **_ldp)
{
    bbl_ldp_hello_s *ldp;

    uint16_t pdu_version;
    uint16_t pdu_len;
    uint16_t msg_type;
    uint16_t msg_len;
    uint16_t tlv_type;
    uint16_t tlv_len;

    if(len < 10 || sp_len < sizeof(bbl_ldp_hello_s)) {
        return DECODE_ERROR;
    }

    /* Init LDP structure */
    ldp = (bbl_ldp_hello_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ldp_hello_s));
    memset(ldp, 0x0, sizeof(bbl_ldp_hello_s));

    /* PDU version and length */
    pdu_version = be16toh(*(uint16_t*)buf) & 0x7FFF;
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    pdu_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    if(pdu_version != 1) {
        return UNKNOWN_PROTOCOL;
    }

    /* The PDU length is defined as two octet integer specifying 
     * the total length of the PDU in octets, excluding the version 
     * and PDU length fields. */
    if(pdu_len > len) {
        return UNKNOWN_PROTOCOL;
    }
    len = pdu_len;

    /* LDP identifier (LSR ID + label space) */
    ldp->lsr_id = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    ldp->label_space_id = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    /* LDP message type and length */
    if(len < 4) {
        return DECODE_ERROR;
    }
    msg_type = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    msg_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    if(msg_len > len || msg_len < 4 || 
       msg_type != LDP_MESSAGE_TYPE_HELLO) {
        return DECODE_ERROR;
    }
    len = msg_len;

    /* LDP message ID */
    ldp->msg_id = be32toh(*(uint32_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint32_t));

    /* LDP TLV's */
    while(len >= LDP_TLV_LEN_MIN) {
        tlv_type = be16toh(*(uint16_t*)buf) & LDP_TLV_TYPE_MASK;
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        tlv_len = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(tlv_len > len) {
            return DECODE_ERROR;
        }
        switch(tlv_type) {
            case LDP_TLV_TYPE_COMMON_HELLO_PARAMETERS:
                if(tlv_len != 4) {
                    return DECODE_ERROR;
                }
                ldp->hold_time = be16toh(*(uint16_t*)buf);
                break;
            case LDP_TLV_TYPE_IPV4_TRANSPORT_ADDRESS:
                if(tlv_len != sizeof(uint32_t)) {
                    return DECODE_ERROR;
                }
                ldp->ipv4_transport_address = *(uint32_t*)buf;
                break;
            case LDP_TLV_TYPE_IPV6_TRANSPORT_ADDRESS:
                if(tlv_len != sizeof(ipv6addr_t)) {
                    return DECODE_ERROR;
                }
                ldp->ipv6_transport_address = (ipv6addr_t*)buf;
                break;
            case LDP_TLV_TYPE_DUAL_STACK_CAPABILITY:
                if(tlv_len != 4) {
                    return DECODE_ERROR;
                }
                ldp->dual_stack_capability = (*buf >> 4) & 0x0F;
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, tlv_len);
    }

    *_ldp = ldp;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_udp
 */
static protocol_error_t
decode_udp(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_ethernet_header_s *eth,
           bbl_udp_s **_udp)
{
    protocol_error_t ret_val = UNKNOWN_PROTOCOL;

    bbl_udp_s *udp;

    if(len < 8 || sp_len < sizeof(bbl_udp_s)) {
        return DECODE_ERROR;
    }

    /* Init UDP header */
    udp = (bbl_udp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_udp_s));

    udp->src = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    udp->dst = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    udp->payload_len = be16toh(*(uint16_t*)buf);
    udp->payload_len -= 8;
    BUMP_BUFFER(buf, len, sizeof(uint32_t)); /* len + checksum */

    if(udp->payload_len > len) {
        return DECODE_ERROR;
    }
    len = udp->payload_len;

    switch(udp->dst) {
        case DHCPV6_UDP_CLIENT:
        case DHCPV6_UDP_SERVER:
            udp->protocol = UDP_PROTOCOL_DHCPV6;
            ret_val = decode_dhcpv6(buf, len, sp, sp_len, (bbl_dhcpv6_s**)&udp->next, false);
            break;
        case BBL_UDP_PORT:
            udp->protocol = UDP_PROTOCOL_BBL;
            ret_val = decode_bbl(buf, len, sp, sp_len, (bbl_bbl_s**)&udp->next);
            eth->bbl = udp->next;
            break;
        case L2TP_UDP_PORT:
            if(udp->src == L2TP_UDP_PORT) {
                udp->protocol = UDP_PROTOCOL_L2TP;
                ret_val = decode_l2tp(buf, len, sp, sp_len, eth, (bbl_l2tp_s**)&udp->next);
            }
            break;
        case DHCP_UDP_CLIENT:
        case DHCP_UDP_SERVER:
            udp->protocol = UDP_PROTOCOL_DHCP;
            ret_val = decode_dhcp(buf, len, sp, sp_len, (bbl_dhcp_s**)&udp->next);
            break;
        case QMX_LI_UDP_PORT:
            udp->protocol = UDP_PROTOCOL_QMX_LI;
            ret_val = decode_qmx_li(buf, len, sp, sp_len, (bbl_qmx_li_s**)&udp->next);
            break;
        case LDP_PORT:
            if(udp->src == LDP_PORT) {
                udp->protocol = UDP_PROTOCOL_LDP;
                ret_val = decode_ldp_hello(buf, len, sp, sp_len, (bbl_ldp_hello_s**)&udp->next);
            }
            break;
        default:
            break;
    }

    if(ret_val == UNKNOWN_PROTOCOL) {
        if(udp->src == QMX_LI_UDP_PORT) {
            udp->protocol = UDP_PROTOCOL_QMX_LI;
            ret_val = decode_qmx_li(buf, len, sp, sp_len, (bbl_qmx_li_s**)&udp->next);
        } else {
            /* Try if payload could be decoded as BBL! 
             * This fails fast if the 64 bit magic number 
             * is not found on the expected position. */
            ret_val = decode_bbl(buf, len, sp, sp_len, (bbl_bbl_s**)&udp->next);
            if(ret_val == PROTOCOL_SUCCESS) {
                udp->protocol = UDP_PROTOCOL_BBL;
                eth->bbl = udp->next;
            } else {
                ret_val = PROTOCOL_SUCCESS;
                udp->protocol = 0;
                udp->next = NULL;
            }
        }
    }

    *_udp = udp;
    return ret_val;
}

/*
 * decode_tcp
 */
static protocol_error_t
decode_tcp(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_tcp_s **_tcp)
{
    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_tcp_s *tcp;

    if(len < 20 || sp_len < sizeof(bbl_tcp_s)) {
        return DECODE_ERROR;
    }

    /* Init TCP header */
    tcp = (bbl_tcp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_tcp_s));

    tcp->src = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    tcp->dst = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    *_tcp = tcp;
    return ret_val;
}

/*
 * decode_ospf
 */
static protocol_error_t
decode_ospf(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_ospf_s **_ospf)
{
    bbl_ospf_s *ospf;
    uint16_t hdr_len;

    if(len < OSPF_PDU_LEN_MIN || sp_len < sizeof(bbl_ospf_s)) {
        return DECODE_ERROR;
    }

    /* Init OSPF */
    ospf = (bbl_ospf_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_isis_s));
    ospf->pdu = buf;
    ospf->pdu_len = len;

    /* Get OSPF version and type */
    ospf->version = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ospf->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    /* Check length */
    hdr_len = be16toh(*(uint16_t*)buf);
    if(hdr_len > ospf->pdu_len) {
        return DECODE_ERROR;
    }

    *_ospf = ospf;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_ipv6
 */
static protocol_error_t
decode_ipv6(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_ethernet_header_s *eth,
            bbl_ipv6_s **_ipv6)
{
    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_ipv6_s *ipv6;

    if(len < IPV6_HDR_LEN || sp_len < sizeof(bbl_ipv6_s)) {
        return DECODE_ERROR;
    }

    /* Init IPv6 header */
    ipv6 = (bbl_ipv6_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ipv6_s));
    ipv6->hdr = buf;

    /* Check if version is 6 */
    if(((*buf >> 4) & 0xf) != 6) {
        return DECODE_ERROR;
    }

    ipv6->tos = (be16toh(*(uint16_t*)buf) >> 4);
    if(!eth->tos) eth->tos = ipv6->tos;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    ipv6->payload_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    ipv6->protocol = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ipv6->ttl = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ipv6->src = buf;
    BUMP_BUFFER(buf, len, IPV6_ADDR_LEN);
    ipv6->dst = buf;
    BUMP_BUFFER(buf, len, IPV6_ADDR_LEN);

    ipv6->payload = buf;
    if(ipv6->payload_len > len) {
        return DECODE_ERROR;
    }
    len = ipv6->payload_len;
    ipv6->len = IPV6_HDR_LEN + len;

     /* Decode protocol */
    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_ICMPV6:
            ret_val = decode_icmpv6(buf, len, sp, sp_len, (bbl_icmpv6_s**)&ipv6->next);
            break;
        case IPV6_NEXT_HEADER_UDP:
            ret_val = decode_udp(buf, len, sp, sp_len, eth, (bbl_udp_s**)&ipv6->next);
            break;
        case IPV6_NEXT_HEADER_TCP:
            ret_val = decode_tcp(buf, len, sp, sp_len, (bbl_tcp_s**)&ipv6->next);
            break;
        case IPV6_NEXT_HEADER_OSPF:
            ret_val = decode_ospf(buf, len, sp, sp_len, (bbl_ospf_s**)&ipv6->next);
            break;
        default:
            ipv6->next = NULL;
            break;
    }

    *_ipv6 = ipv6;
    return ret_val;
}

/*
 * decode_ipv4
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static protocol_error_t
decode_ipv4(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_ethernet_header_s *eth,
            bbl_ipv4_s **_ipv4)
{
    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_ipv4_s *ipv4;
    const struct ip* header;

    uint16_t ipv4_header_len;

    if(len < 20 || sp_len < sizeof(bbl_ipv4_s)) {
        return DECODE_ERROR;
    }

    /* Init IPv4 header */
    ipv4 = (bbl_ipv4_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ipv4_s));
    ipv4->router_alert_option = false;

    ipv4->hdr = buf;
    header = (struct ip*)buf;

    /* Check if version is 4 */
    if(header->ip_v != 4) {
        return DECODE_ERROR;
    }
    /* Internet Header Length (IHL) is the length of the internet header in 32
     * bit words, and thus points to the beginning of the data.  Note that
     * the minimum value for a correct header is 5. */
    ipv4_header_len = header->ip_hl * 4;
    if(ipv4_header_len < 20) {
        return DECODE_ERROR;
    }

    ipv4->tos = header->ip_tos;
    if(!eth->tos) eth->tos = ipv4->tos;
    ipv4->len = be16toh(header->ip_len);
    if(ipv4_header_len > ipv4->len ||
       ipv4->len > len)  {
        return DECODE_ERROR;
    }

    ipv4->offset = be16toh(header->ip_off);
    ipv4->ttl = header->ip_ttl;
    ipv4->protocol = header->ip_p;

    ipv4->src = header->ip_src.s_addr;
    ipv4->dst = header->ip_dst.s_addr;
    BUMP_BUFFER(buf, len, ipv4_header_len);

    ipv4->payload = buf;
    ipv4->payload_len = ipv4->len - ipv4_header_len;

    if(ipv4->payload_len > len) {
        return DECODE_ERROR;
    }
    len = ipv4->payload_len;

    if(ipv4->offset & ~IPV4_DF) {
        /* Reassembling of fragmented IPv4 packets is currently not supported. */
        ipv4->protocol = 0;
    }

    switch(ipv4->protocol) {
        case PROTOCOL_IPV4_IGMP:
            ret_val = decode_igmp(buf, len, sp, sp_len, (bbl_igmp_s**)&ipv4->next);
            break;
        case PROTOCOL_IPV4_ICMP:
            ret_val = decode_icmp(buf, len, sp, sp_len, (bbl_icmp_s**)&ipv4->next);
            break;
        case PROTOCOL_IPV4_UDP:
            ret_val = decode_udp(buf, len, sp, sp_len, eth, (bbl_udp_s**)&ipv4->next);
            break;
        case PROTOCOL_IPV4_TCP:
            ret_val = decode_tcp(buf, len, sp, sp_len, (bbl_tcp_s**)&ipv4->next);
            break;
        case PROTOCOL_IPV4_OSPF:
            ret_val = decode_ospf(buf, len, sp, sp_len, (bbl_ospf_s**)&ipv4->next);
            break;
        default:
            ipv4->next = NULL;
            break;
    }

    *_ipv4 = ipv4;
    return ret_val;
}

/*
 * decode_ppp_pap
 */
static protocol_error_t
decode_ppp_pap(uint8_t *buf, uint16_t len,
               uint8_t *sp, uint16_t sp_len,
               bbl_pap_s **ppp_pap)
{
    bbl_pap_s *pap;
    uint16_t   pap_len;

    if(len < 4 || sp_len < sizeof(bbl_pap_s)) {
        return DECODE_ERROR;
    }

    /* Init PAP header */
    pap = (bbl_pap_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_pap_s));
    memset(pap, 0x0, sizeof(bbl_pap_s));

    pap->code = *buf;
    pap->identifier = *(buf+1);
    pap_len = be16toh(*(uint16_t*)(buf+2));
    if(pap->code == PAP_CODE_REQUEST) {
        if(pap_len < 6 || pap_len > len) {
            return DECODE_ERROR;
        }
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
        pap->username_len = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(pap->username_len >= len) {
            return DECODE_ERROR;
        }
        pap->username = (char*)buf;
        BUMP_BUFFER(buf, len, pap->username_len);
        pap->password_len = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(pap->password_len > len) {
            return DECODE_ERROR;
        }
        pap->password = (char*)buf;
        BUMP_BUFFER(buf, len, pap->password_len);
    } else {
        if(pap_len < 5 || pap_len > len) {
            return DECODE_ERROR;
        }
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
        pap->reply_message_len = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(pap->reply_message_len) {
            if(pap->reply_message_len > len) {
                return DECODE_ERROR;
            }
            pap->reply_message = (char*)buf;
            BUMP_BUFFER(buf, len, pap->reply_message_len);
        }
    }
    *ppp_pap = pap;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_ppp_chap
 */
static protocol_error_t
decode_ppp_chap(uint8_t *buf, uint16_t len,
                uint8_t *sp, uint16_t sp_len,
                bbl_chap_s **ppp_chap)
{
    bbl_chap_s *chap;
    uint16_t chap_len;

    if(len < 4 || sp_len < sizeof(bbl_chap_s)) {
        return DECODE_ERROR;
    }

    /* Init CHAP header */
    chap = (bbl_chap_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_chap_s));
    memset(chap, 0x0, sizeof(bbl_chap_s));

    chap->code = *buf;
    chap->identifier = *(buf+1);
    chap_len = be16toh(*(uint16_t*)(buf+2));
    if(chap->code == CHAP_CODE_CHALLENGE) {
        if(chap_len < 5 || chap_len > len) {
            return DECODE_ERROR;
        }
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
        chap->challenge_len = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(chap->challenge_len > len) {
            return DECODE_ERROR;
        }
        chap->challenge = buf;
        BUMP_BUFFER(buf, len, chap->challenge_len);
    } else {
        if(chap_len < 4 || chap_len > len) {
            return DECODE_ERROR;
        }
        BUMP_BUFFER(buf, len, sizeof(uint32_t));
        chap->reply_message_len = chap_len - 4;
        if(chap->reply_message_len) {
            if(chap->reply_message_len > len) {
                return DECODE_ERROR;
            }
            chap->reply_message = (char*)buf;
            BUMP_BUFFER(buf, len, chap->reply_message_len);
        }
    }
    *ppp_chap = chap;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_ppp_ip6cp
 */
static protocol_error_t
decode_ppp_ip6cp(uint8_t *buf, uint16_t len,
                 uint8_t *sp, uint16_t sp_len,
                 bbl_ip6cp_s **ppp_ip6cp)
{
    bbl_ip6cp_s *ip6cp;

    uint16_t ip6cp_len = 0;
    uint8_t  ip6cp_option_type = 0;
    uint8_t  ip6cp_option_len = 0;
    uint8_t  ip6cp_option_index = 0;

    if(len < 4 || sp_len < sizeof(bbl_ip6cp_s)) {
        return DECODE_ERROR;
    }

    /* Init IP6CP header */
    ip6cp = (bbl_ip6cp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ip6cp_s));
    memset(ip6cp, 0x0, sizeof(bbl_ip6cp_s));

    ip6cp->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ip6cp->identifier = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ip6cp_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    if(ip6cp_len < 4) {
        return DECODE_ERROR;
    }
    ip6cp_len -= 4;

    if(ip6cp_len > len) {
        return DECODE_ERROR;
    }

    /* Decode options ...
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |     Type      |    Length     |      Data ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    ip6cp->options = buf;
    ip6cp->options_len = ip6cp_len;

    switch(ip6cp->code) {
        case PPP_CODE_CONF_REQUEST:
        case PPP_CODE_CONF_ACK:
        case PPP_CODE_CONF_NAK:
            while(ip6cp_len >= 2) {
                if(ip6cp_option_index < PPP_MAX_OPTIONS) {
                    ip6cp->option[ip6cp_option_index++] = buf;
                }
                ip6cp_option_type = *buf;
                BUMP_BUFFER(buf, ip6cp_len, sizeof(uint8_t));
                ip6cp_option_len = *buf;
                BUMP_BUFFER(buf, ip6cp_len, sizeof(uint8_t));
                if(ip6cp_option_len < 2) {
                    return DECODE_ERROR;
                }
                ip6cp_option_len -= 2;
                if(ip6cp_option_len > ip6cp_len) {
                    return DECODE_ERROR;
                }
                switch (ip6cp_option_type) {
                    case PPP_IP6CP_OPTION_IDENTIFIER:
                        if(ip6cp_option_len < sizeof(uint64_t)) {
                            return DECODE_ERROR;
                        }
                        ip6cp->ipv6_identifier = *(uint64_t*)buf;
                        break;
                    default:
                        ip6cp->unknown_options = true;
                        break;
                }
                BUMP_BUFFER(buf, ip6cp_len, ip6cp_option_len);
            }
            break;
        default:
            break;
    }

    *ppp_ip6cp = ip6cp;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_ppp_ipcp
 */
static protocol_error_t
decode_ppp_ipcp(uint8_t *buf, uint16_t len,
                uint8_t *sp, uint16_t sp_len,
                bbl_ipcp_s **ppp_ipcp)
{
    bbl_ipcp_s *ipcp;

    uint16_t ipcp_len = 0;
    uint8_t  ipcp_option_type = 0;
    uint8_t  ipcp_option_len = 0;
    uint8_t  ipcp_option_index = 0;

    if(len < 4 || sp_len < sizeof(bbl_ipcp_s)) {
        return DECODE_ERROR;
    }

    /* Init IPCP header */
    ipcp = (bbl_ipcp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ipcp_s));
    memset(ipcp, 0x0, sizeof(bbl_ipcp_s));

    ipcp->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ipcp->identifier = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    ipcp_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    if(ipcp_len < 4) {
        return DECODE_ERROR;
    }
    ipcp_len -= 4;

    if(ipcp_len > len) {
        return DECODE_ERROR;
    }

    /* Decode options ...
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |     Type      |    Length     |      Data ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    ipcp->options = buf;
    ipcp->options_len = ipcp_len;

    switch(ipcp->code) {
        case PPP_CODE_CONF_REQUEST:
        case PPP_CODE_CONF_ACK:
        case PPP_CODE_CONF_NAK:
            while(ipcp_len >= 2) {
                if(ipcp_option_index < PPP_MAX_OPTIONS) {
                    ipcp->option[ipcp_option_index++] = buf;
                }
                ipcp_option_type = *buf;
                BUMP_BUFFER(buf, ipcp_len, sizeof(uint8_t));
                ipcp_option_len = *buf;
                BUMP_BUFFER(buf, ipcp_len, sizeof(uint8_t));
                if(ipcp_option_len < 2) {
                    return DECODE_ERROR;
                }
                ipcp_option_len -= 2;
                if(ipcp_option_len > ipcp_len) {
                    return DECODE_ERROR;
                }
                switch (ipcp_option_type) {
                    case PPP_IPCP_OPTION_ADDRESS:
                        if(ipcp_option_len < sizeof(uint32_t)) {
                            return DECODE_ERROR;
                        }
                        ipcp->option_address = true;
                        ipcp->address = *(uint32_t*)buf;
                        break;
                    case PPP_IPCP_OPTION_DNS1:
                        if(ipcp_option_len < sizeof(uint32_t)) {
                            return DECODE_ERROR;
                        }
                        ipcp->option_dns1 = true;
                        ipcp->dns1 = *(uint32_t*)buf;
                        break;
                    case PPP_IPCP_OPTION_DNS2:
                        if(ipcp_option_len < sizeof(uint32_t)) {
                            return DECODE_ERROR;
                        }
                        ipcp->option_dns2 = true;
                        ipcp->dns2 = *(uint32_t*)buf;
                        break;
                    default:
                        ipcp->unknown_options = true;
                        break;
                }
                BUMP_BUFFER(buf, ipcp_len, ipcp_option_len);
            }
            break;
        default:
            break;
    }

    *ppp_ipcp = ipcp;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_ppp_lcp
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |    Data ...
 *  +-+-+-+-+
 */
static protocol_error_t
decode_ppp_lcp(uint8_t *buf, uint16_t len,
               uint8_t *sp, uint16_t sp_len,
               bbl_lcp_s **ppp_lcp)
{
    bbl_lcp_s *lcp;

    uint16_t lcp_len = 0;
    uint8_t  lcp_option_type = 0;
    uint8_t  lcp_option_len = 0;
    uint8_t  lcp_option_index = 0;

    if(len < 4 || sp_len < sizeof(bbl_lcp_s)) {
        return DECODE_ERROR;
    }

    /* Init LCP header */
    lcp = (bbl_lcp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_lcp_s));
    memset(lcp, 0x0, sizeof(bbl_lcp_s));

    lcp->start = buf;
    lcp->len = len;

    lcp->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    lcp->identifier = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    lcp_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    if(lcp_len < 4) {
        return DECODE_ERROR;
    }
    lcp_len -= 4;

    if(lcp_len > len) {
        return DECODE_ERROR;
    }

    /* Decode options ...
     *  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |     Type      |    Length     |      Data ...
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    lcp->options = buf;
    lcp->options_len = lcp_len;

    switch(lcp->code) {
        case PPP_CODE_VENDOR_SPECIFIC:
            /* RFC 2153 */
            if(lcp_len < 8) {
                return DECODE_ERROR;
            }
            lcp->magic = *(uint32_t*)buf;
            BUMP_BUFFER(buf, lcp_len, sizeof(uint32_t));
            memcpy(lcp->vendor_oui, buf, OUI_LEN);
            BUMP_BUFFER(buf, lcp_len, OUI_LEN);
            lcp->vendor_kind = *buf;
            BUMP_BUFFER(buf, lcp_len, sizeof(uint8_t));
            lcp->vendor_value = buf;
            lcp->vendor_value_len = lcp_len;
            break;
        case PPP_CODE_PROT_REJECT:
            if(lcp_len < 2) {
                return DECODE_ERROR;
            }
            lcp->protocol = be16toh(*(uint16_t*)buf);
            break;
        case PPP_CODE_ECHO_REQUEST:
        case PPP_CODE_ECHO_REPLY:
            if(lcp_len>=4) {
                lcp->magic = *(uint32_t*)buf;
            }
            break;
        case PPP_CODE_CONF_REQUEST:
        case PPP_CODE_CONF_ACK:
        case PPP_CODE_CONF_NAK:
            while(lcp_len >= 2) {
                if(lcp_option_index < PPP_MAX_OPTIONS) {
                    lcp->option[lcp_option_index++] = buf;
                }
                lcp_option_type = *buf;
                BUMP_BUFFER(buf, lcp_len, sizeof(uint8_t));
                lcp_option_len = *buf;
                BUMP_BUFFER(buf, lcp_len, sizeof(uint8_t));
                if(lcp_option_len < 2) {
                    return DECODE_ERROR;
                }
                lcp_option_len -= 2;
                if(lcp_option_len > lcp_len) {
                    return DECODE_ERROR;
                }
                switch (lcp_option_type) {
                    case PPP_LCP_OPTION_MRU:
                        if(lcp_len < sizeof(uint16_t)) {
                            return DECODE_ERROR;
                        }
                        lcp->mru = be16toh(*(uint16_t*)buf);
                        break;
                    case PPP_LCP_OPTION_AUTH:
                        if(lcp_len < sizeof(uint16_t)) {
                            return DECODE_ERROR;
                        }
                        lcp->auth = be16toh(*(uint16_t*)buf);
                        break;
                    case PPP_LCP_OPTION_MAGIC:
                        if(lcp_len < sizeof(uint32_t)) {
                            return DECODE_ERROR;
                        }
                        lcp->magic = *(uint32_t*)buf;
                        break;
                    default:
                        lcp->unknown_options = true;
                        break;
                }
                BUMP_BUFFER(buf, lcp_len, lcp_option_len);
            }
            break;
        default:
            break;
    }

    *ppp_lcp = lcp;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_l2tp
 */
static protocol_error_t
decode_l2tp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_ethernet_header_s *eth,
            bbl_l2tp_s **_l2tp)
{
    protocol_error_t ret_val = UNKNOWN_PROTOCOL;
    bbl_l2tp_s *l2tp;

    uint16_t l2tp_len = 0;

    if(len < 8 || sp_len < sizeof(bbl_l2tp_s)) {
        return DECODE_ERROR;
    }

    /* Init L2TP header */
    l2tp = (bbl_l2tp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_l2tp_s));
    memset(l2tp, 0x0, sizeof(bbl_l2tp_s));

    /*  0                   1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Tunnel ID           |           Session ID          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |             Ns (opt)          |             Nr (opt)          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |      Offset Size (opt)        |    Offset pad... (opt)
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

    if(*buf & L2TP_HDR_CTRL_BIT_MASK) {
        l2tp->type = L2TP_MESSAGE_ZLB;
    }

    l2tp->with_length = *buf & L2TP_HDR_LEN_BIT_MASK;
    l2tp->with_sequence = *buf & L2TP_HDR_SEQ_BIT_MASK;
    l2tp->with_offset = *buf & L2TP_HDR_OFFSET_BIT_MASK;
    l2tp->with_priority = *buf & L2TP_HDR_PRIORITY_BIT_MASK;

    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    if((*buf & L2TP_HDR_VERSION_MASK) != 2) { /* Check L2TP version */
        return DECODE_ERROR;
    }
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    /* L2TP length */
    if(l2tp->with_length) {
        l2tp->length = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        l2tp_len = l2tp->length - 4;
        if(l2tp_len > len) {
            return DECODE_ERROR;
        }
        len = l2tp_len;
    } else if(l2tp->type) {
        /* Length is mandatory for control packets */
        return DECODE_ERROR;
    }
    if(len < 4) {
        return DECODE_ERROR;
    }
    l2tp->tunnel_id = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    l2tp->session_id = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    if(l2tp->with_sequence) {
        if(len < 4) {
            return DECODE_ERROR;
        }
        l2tp->ns = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        l2tp->nr = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
    } else if(l2tp->type) {
        /* Sequence is mandatory for control packets */
        return DECODE_ERROR;
    }

    if(l2tp->with_offset) {
        if(len < 2) {
            return DECODE_ERROR;
        }
        l2tp->offset = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(l2tp->offset) {
            if(len < l2tp->offset) {
                return DECODE_ERROR;
            }
            /* Actually never seen a BNG sending offset
             * different than zero... */
            BUMP_BUFFER(buf, len, l2tp->offset);
        }
    }

    if(l2tp->type) {
        /* L2TP control packet */
        if(len) {
            if(len < 8) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            if(*(uint32_t*)buf != 0) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint32_t));
            l2tp->type = be16toh(*(uint16_t*)buf);
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            if(len) {
                l2tp->payload = buf;
                l2tp->payload_len = len;
            }
        }
        ret_val = PROTOCOL_SUCCESS;
    } else {
        /* L2TP data packet */
        if(len < 4) {
            return DECODE_ERROR;
        }
        l2tp->payload = buf;
        l2tp->payload_len = len;

        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        l2tp->protocol = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));

        /* Decode protocol */
        switch(l2tp->protocol) {
            case PROTOCOL_IPV4:
                ret_val = decode_ipv4(buf, len, sp, sp_len, eth, (bbl_ipv4_s**)&l2tp->next);
                break;
            case PROTOCOL_IPV6:
                ret_val = decode_ipv6(buf, len, sp, sp_len, eth, (bbl_ipv6_s**)&l2tp->next);
                break;
            case PROTOCOL_LCP:
                ret_val = decode_ppp_lcp(buf, len, sp, sp_len, (bbl_lcp_s**)&l2tp->next);
                break;
            case PROTOCOL_IPCP:
                ret_val = decode_ppp_ipcp(buf, len, sp, sp_len, (bbl_ipcp_s**)&l2tp->next);
                break;
            case PROTOCOL_IP6CP:
                ret_val = decode_ppp_ip6cp(buf, len, sp, sp_len, (bbl_ip6cp_s**)&l2tp->next);
                break;
            case PROTOCOL_PAP:
                ret_val = decode_ppp_pap(buf, len, sp, sp_len, (bbl_pap_s**)&l2tp->next);
                break;
            case PROTOCOL_CHAP:
                ret_val = decode_ppp_chap(buf, len, sp, sp_len, (bbl_chap_s**)&l2tp->next);
                break;
            default:
                break;
        }
    }
    *_l2tp = l2tp;
    return ret_val;
}

static protocol_error_t
decode_pppoe_vendor(uint8_t *buf, uint16_t len,
                    uint8_t *sp, uint16_t sp_len,
                    bbl_pppoe_discovery_s *pppoe)
{
    uint32_t vendor;
    uint8_t tlv_type;
    uint8_t tlv_length;

    access_line_s *access_line;

    if(len < sizeof(uint32_t)) {
        return DECODE_ERROR;
    }

    vendor = be32toh(*(uint32_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    if(vendor != BROADBAND_FORUM_VENDOR_ID) {
        return PROTOCOL_SUCCESS;
    }

    if(sp_len < sizeof(access_line_s)) {
        return DECODE_ERROR;
    }

    access_line = (access_line_s*)sp; 
    BUMP_BUFFER(sp, sp_len, sizeof(access_line_s));
    memset(access_line, 0x0, sizeof(access_line_s));
    pppoe->access_line = access_line;
    while(len > 2) {
        tlv_type = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        tlv_length = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        switch (tlv_type) {
            case ACCESS_LINE_ACI:
                if(sp_len > tlv_length) {
                    access_line->aci = (void*)sp;
                    memcpy(sp, buf, tlv_length);
                    /* zero terminate string */
                    sp += tlv_length; *sp = 0; sp++;
                } else {
                    return DECODE_ERROR;
                }
                break;
            case ACCESS_LINE_ARI:
                if(sp_len > tlv_length) {
                    access_line->ari = (void*)sp;
                    memcpy(sp, buf, tlv_length);
                    /* zero terminate string */
                    sp += tlv_length; *sp = 0; sp++;
                } else {
                    return DECODE_ERROR;
                }
                break;
            case ACCESS_LINE_ACT_UP:
                if(tlv_length == sizeof(uint32_t)) {
                    access_line->up = be32toh(*(uint32_t*)buf);
                } else {
                    return DECODE_ERROR;
                }
                break;
            case ACCESS_LINE_ACT_DOWN:
                if(tlv_length == sizeof(uint32_t)) {
                    access_line->down = be32toh(*(uint32_t*)buf);
                } else {
                    return DECODE_ERROR;
                }
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, len, tlv_length);
    }
    return PROTOCOL_SUCCESS;
}

/*
 * decode_pppoe_discovery
 *
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  VER  | TYPE  |      CODE     |          SESSION_ID           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            LENGTH             |           payload             ~
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static protocol_error_t
decode_pppoe_discovery(uint8_t *buf, uint16_t len,
                       uint8_t *sp, uint16_t sp_len,
                       bbl_pppoe_discovery_s **pppoe_discovery)
{
    bbl_pppoe_discovery_s *pppoe;
    uint16_t pppoe_len = 0;
    uint16_t pppoe_tag_type = 0;
    uint16_t pppoe_tag_len = 0;

    if(len < 6 || sp_len < sizeof(bbl_pppoe_discovery_s)) {
        return DECODE_ERROR;
    }

    /* Init PPPoE header */
    pppoe = (bbl_pppoe_discovery_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_pppoe_discovery_s));
    memset(pppoe, 0x0, sizeof(bbl_pppoe_discovery_s));

    /* Check if version and type are both set to 1 */
    if(*buf != 17) {
        return DECODE_ERROR;
    }
    BUMP_BUFFER(buf, len, sizeof(uint8_t));

    pppoe->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    pppoe->session_id = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    pppoe_len = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    if(pppoe_len > len) {
        return DECODE_ERROR;
    }

    /* Decode PPPoE tags ... */
    while(pppoe_len >= 4) {
        pppoe_tag_type = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, pppoe_len, sizeof(uint16_t));
        pppoe_tag_len = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, pppoe_len, sizeof(uint16_t));
        if(pppoe_tag_len > pppoe_len) {
            return DECODE_ERROR;
        }
        switch (pppoe_tag_type) {
            case PPPOE_TAG_SERVICE_NAME:
                pppoe->service_name = buf;
                pppoe->service_name_len = pppoe_tag_len;
                break;
            case PPPOE_TAG_HOST_UNIQ:
                pppoe->host_uniq = buf;
                pppoe->host_uniq_len = pppoe_tag_len;
                break;
            case PPPOE_TAG_AC_COOKIE:
                pppoe->ac_cookie = buf;
                pppoe->ac_cookie_len = pppoe_tag_len;
                break;
            case PPPOE_TAG_VENDOR:
                if(decode_pppoe_vendor(buf, pppoe_tag_len, sp, sp_len, pppoe) != PROTOCOL_SUCCESS) {
                    return DECODE_ERROR;
                }
                break;
            default:
                break;
        }
        BUMP_BUFFER(buf, pppoe_len, pppoe_tag_len);
    }

    *pppoe_discovery = pppoe;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_pppoe_session
 */
static protocol_error_t
decode_pppoe_session(uint8_t *buf, uint16_t len,
                     uint8_t *sp, uint16_t sp_len,
                     bbl_ethernet_header_s *eth,
                     bbl_pppoe_session_s **pppoe_session)
{
    protocol_error_t ret_val = UNKNOWN_PROTOCOL;
    bbl_pppoe_session_s *pppoe;
    const struct pppoe_ppp_session_header *header;

    uint16_t pppoe_len = 0;

    if(len < 8 || sp_len < sizeof(bbl_pppoe_session_s)) {
        return DECODE_ERROR;
    }

    /* Init PPPoE header */
    pppoe = (bbl_pppoe_session_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_pppoe_session_s));
    pppoe->lwip = false;

    header = (struct pppoe_ppp_session_header*)buf;
    BUMP_BUFFER(buf, len, sizeof(struct pppoe_ppp_session_header));

    /* Check if version and type are both set to 1 */
    if(header->version_type != 17) {
        return DECODE_ERROR;
    }
    pppoe->session_id = be16toh(header->session_id);
    pppoe_len = be16toh(header->len) - 2; /* - 2 byte PPP header */
    pppoe->protocol = be16toh(header->protocol);
    if(pppoe_len > len) {
        return DECODE_ERROR;
    }
    len = pppoe_len;

    /* Decode protocol */
    switch(pppoe->protocol) {
        case PROTOCOL_IPV4:
            ret_val = decode_ipv4(buf, len, sp, sp_len, eth, (bbl_ipv4_s**)&pppoe->next);
            break;
        case PROTOCOL_IPV6:
            ret_val = decode_ipv6(buf, len, sp, sp_len, eth, (bbl_ipv6_s**)&pppoe->next);
            break;
        case PROTOCOL_LCP:
            ret_val = decode_ppp_lcp(buf, len, sp, sp_len, (bbl_lcp_s**)&pppoe->next);
            break;
        case PROTOCOL_IPCP:
            ret_val = decode_ppp_ipcp(buf, len, sp, sp_len, (bbl_ipcp_s**)&pppoe->next);
            break;
        case PROTOCOL_IP6CP:
            ret_val = decode_ppp_ip6cp(buf, len, sp, sp_len, (bbl_ip6cp_s**)&pppoe->next);
            break;
        case PROTOCOL_PAP:
            ret_val = decode_ppp_pap(buf, len, sp, sp_len, (bbl_pap_s**)&pppoe->next);
            break;
        case PROTOCOL_CHAP:
            ret_val = decode_ppp_chap(buf, len, sp, sp_len, (bbl_chap_s**)&pppoe->next);
            break;
        default:
            pppoe->next = NULL;
            break;
    }

    *pppoe_session = pppoe;
    return ret_val;
}

/*
 * decode_arp
 */
static protocol_error_t
decode_arp(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_arp_s **_arp)
{
    bbl_arp_s *arp;

    if(len < 28 || sp_len < sizeof(bbl_arp_s)) {
        return DECODE_ERROR;
    }

    /* Init ARP header */
    arp = (bbl_arp_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_arp_s));

    BUMP_BUFFER(buf, len, 6);
    arp->code = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    arp->sender = buf;
    BUMP_BUFFER(buf, len, ETH_ADDR_LEN);
    arp->sender_ip = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    arp->target = buf;
    BUMP_BUFFER(buf, len, ETH_ADDR_LEN);
    arp->target_ip = *(uint32_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));

    *_arp = arp;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_isis
 */
static protocol_error_t
decode_isis(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_isis_s **_isis)
{
    bbl_isis_s *isis;
    uint8_t hdr_len;

    if(len < ISIS_HDR_LEN_COMMON || sp_len < sizeof(bbl_isis_s)) {
        return DECODE_ERROR;
    }

    /* Init IS-IS */
    isis = (bbl_isis_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_isis_s));
    isis->pdu = buf;
    isis->pdu_len = len;

    /* Check IS-IS common header (8 byte) */
    hdr_len = *(buf+1);
    if(hdr_len > len) {
        return DECODE_ERROR;
    }
    isis->type = *(buf+4) & 0x1f;

    *_isis = isis;
    return PROTOCOL_SUCCESS;
}

/*
 * decode_ethernet
 */
protocol_error_t
decode_ethernet(uint8_t *buf, uint16_t len,
                uint8_t *sp, uint16_t sp_len,
                bbl_ethernet_header_s **_eth)
{
    bbl_ethernet_header_s *eth;
    bbl_mpls_s *mpls;

    if(len < 14 || sp_len < sizeof(bbl_ethernet_header_s)) {
        return DECODE_ERROR;
    }

    /* Init ethernet header */
    eth = (bbl_ethernet_header_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ethernet_header_s));
    memset(eth, 0x0, sizeof(bbl_ethernet_header_s));
    *_eth = eth;

    eth->length = len;

    /* Decode ethernet header */
    eth->dst = buf;
    BUMP_BUFFER(buf, len, ETH_ADDR_LEN);
    eth->src = buf;
    BUMP_BUFFER(buf, len, ETH_ADDR_LEN);
    eth->type = *(uint16_t*)buf;
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    if(eth->type == NB_ETH_TYPE_VLAN || eth->type == NB_ETH_TYPE_QINQ) {
        if(len < 4) {
            return DECODE_ERROR;
        }
        if(eth->type == ETH_TYPE_QINQ) {
            eth->qinq = true;
        }
        eth->vlan_outer_priority = *buf >> 5;
        eth->vlan_outer = be16toh(*(uint16_t*)buf);
        eth->vlan_outer &= BBL_ETH_VLAN_ID_MAX;

        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        eth->type = *(uint16_t*)buf;
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(eth->type == NB_ETH_TYPE_VLAN || eth->type == NB_ETH_TYPE_QINQ) {
            if(len < 4) {
                return DECODE_ERROR;
            }
            eth->vlan_inner_priority = *buf >> 5;
            eth->vlan_inner = be16toh(*(uint16_t*)buf);
            eth->vlan_inner &= BBL_ETH_VLAN_ID_MAX;
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            eth->type = *(uint16_t*)buf;
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            if(eth->type == NB_ETH_TYPE_VLAN || eth->type == NB_ETH_TYPE_QINQ) {
                if(len < 4) {
                    return DECODE_ERROR;
                }
                eth->vlan_three = be16toh(*(uint16_t*)buf);
                eth->vlan_three &= BBL_ETH_VLAN_ID_MAX;
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
                eth->type = *(uint16_t*)buf;
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
            }
        }
    }
 
    if(eth->type == NB_ETH_TYPE_MPLS) {
        if(sp_len < sizeof(bbl_mpls_s)) {
            return DECODE_ERROR;
        }  
        mpls = (bbl_mpls_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_mpls_s));
        eth->mpls = mpls;
        while(mpls) {
            if(len < 5) {
                /* 4 byte MPLS + at least 1 byte payload */
                return DECODE_ERROR;
            }
            mpls->label = be32toh(*(uint32_t*)buf) >> 12;
            mpls->exp = (*(buf+2) >> 1) & 7; 
            mpls->ttl = *(buf+3); 
            if(*(buf+2) & 1) {
                /* BOS bit set */
                mpls->next = NULL;
                mpls = NULL;
            } else {
                if(sp_len < sizeof(bbl_mpls_s)) {
                    return DECODE_ERROR;
                } 
                mpls->next = (bbl_mpls_s*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_mpls_s));
                mpls = mpls->next;
            }
            BUMP_BUFFER(buf, len, sizeof(uint32_t));
        }
        /* Check next 4 bit to set type to IPv4 or IPv6 */
        switch((*buf >> 4) & 0xf) {
            case 4: 
                eth->type = NB_ETH_TYPE_IPV4; 
                break;
            case 6:
                eth->type = NB_ETH_TYPE_IPV6; 
                break;
            default: 
                return UNKNOWN_PROTOCOL;
        }
    }

    eth->type = be16toh(eth->type);
    switch(eth->type) {
        case ETH_TYPE_PPPOE_SESSION:
            return decode_pppoe_session(buf, len, sp, sp_len, eth, (bbl_pppoe_session_s**)&eth->next);
        case ETH_TYPE_PPPOE_DISCOVERY:
            return decode_pppoe_discovery(buf, len, sp, sp_len, (bbl_pppoe_discovery_s**)&eth->next);
        case ETH_TYPE_ARP:
            return decode_arp(buf, len, sp, sp_len, (bbl_arp_s**)&eth->next);
        case ETH_TYPE_IPV4:
            return decode_ipv4(buf, len, sp, sp_len, eth, (bbl_ipv4_s**)&eth->next);
        case ETH_TYPE_IPV6:
            return decode_ipv6(buf, len, sp, sp_len, eth, (bbl_ipv6_s**)&eth->next);
        case ETH_TYPE_LACP:
            return decode_lacp(buf, len, sp, sp_len, (bbl_lacp_s**)&eth->next);        
        default:
            break;
    }

    if(eth->type <= ETH_IEEE_802_3_MAX_LEN) {
        /* 802.3 ethernet header (length instead of type) */
        if(eth->type > len) {
            return DECODE_ERROR;
        }
        len = eth->type;

        if(len < LLC_HDR_LEN) {
            return DECODE_ERROR;
        }
        /* For now skip/ignore LLC header... */
        BUMP_BUFFER(buf, len, LLC_HDR_LEN);
        if(len >= ISIS_HDR_LEN_COMMON && *buf == ISIS_PROTOCOL_IDENTIFIER) {
            eth->type = ISIS_PROTOCOL_IDENTIFIER;
            return decode_isis(buf, len, sp, sp_len, (bbl_isis_s**)&eth->next);
        }
    }

    return UNKNOWN_PROTOCOL;
}
