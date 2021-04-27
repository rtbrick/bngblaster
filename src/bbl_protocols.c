/*
 * Protocol Encode/Decode Functions
 *
 * Christian Giese, July 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */
#include "bbl_protocols.h"


protocol_error_t decode_l2tp(uint8_t *buf, uint16_t len, uint8_t *sp, uint16_t sp_len, bbl_l2tp_t **_l2tp);
protocol_error_t encode_l2tp(uint8_t *buf, uint16_t *len, bbl_l2tp_t *l2tp);

uint16_t
bbl_checksum(uint16_t *buf, uint16_t len) {
         uint32_t sum = 0;
         uint16_t checksum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    /* If any bytes left, pad the bytes and add */
    if(len > 0) {
        sum += ((*buf) & htobe16(0xFF00));
    }
    /* Fold sum to 16 bits: add carrier to result */
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    /* Calculate one's complement */
    checksum = ~sum;
    return checksum;
}

uint16_t
bbl_ipv6_checksum(ipv6addr_t src, ipv6addr_t dst, uint8_t nh, uint8_t *buf, uint16_t len) {

    int i;
    uint32_t checksum = 0;
    uint16_t word16;
    bool padding = false;

    /* The following block ensures that checksum field is ignored */
    switch(nh) {
        case IPV6_NEXT_HEADER_UDP:
            word16 = ((buf[0]<<8)&0xFF00) + (buf[1]&0xFF); checksum += word16;
            word16 = ((buf[2]<<8)&0xFF00) + (buf[3]&0xFF); checksum += word16;
            word16 = ((buf[4]<<8)&0xFF00) + (buf[5]&0xFF); checksum += word16;
            i = 8;
            break;
        case IPV6_NEXT_HEADER_ICMPV6:
            word16 = ((buf[0]<<8)&0xFF00) + (buf[1]&0xFF); checksum += word16;
            i = 4;
            break;
        default:
            i = 0;
            break;
    }
    if (len % 2) {
        padding = true;
        len--;
    }
    /* Make 16 bit words out of every two adjacent 8 bit words and
     * calculate the sum of all 16 bit words */
    for (; i < len; i = i+2) {
        word16 = ((buf[i]<<8)&0xFF00) + (buf[i+1]&0xFF);
        checksum += word16;
    }
    if(padding) {
        word16 = (buf[len]<<8)&0xFF00;
        checksum += word16;
        len++;
    }

    /* Add the IPv6 pseudo header which contains the
     * source and destinations addresses */
    for (i = 0; i < IPV6_ADDR_LEN; i = i+2) {
        word16 =((src[i]<<8)) + (src[i+1]);
        checksum += word16;
    }
    for (i = 0; i<IPV6_ADDR_LEN; i = i+2) {
        word16 = ((dst[i]<<8)) + (dst[i+1]);
        checksum += word16;
    }

    /* Add the protocol number and the length of the UDP packet */
    checksum += nh + len;

    /* Keep only the last 16 bits of the 32 bit calculated sum and add the carries */
    while (checksum >> 16)
        checksum = (checksum & 0xffff) + (checksum >> 16);

    /* Take the one's complement of checksum */
    checksum = ~checksum;

    return (uint16_t)checksum;
}

uint16_t
bbl_ipv6_udp_checksum(ipv6addr_t src, ipv6addr_t dst, uint8_t *buf, uint16_t len) {
    return bbl_ipv6_checksum(src, dst, IPV6_NEXT_HEADER_UDP, buf, len);
}

uint16_t
bbl_ipv6_icmpv6_checksum(ipv6addr_t src, ipv6addr_t dst, uint8_t *buf, uint16_t len) {
    return bbl_ipv6_checksum(src, dst, IPV6_NEXT_HEADER_ICMPV6, buf, len);
}

uint16_t
bbl_ipv4_checksum(uint32_t src, uint32_t dst, uint8_t proto, uint8_t *buf, uint16_t len) {

    uint8_t *ip8;

    int i;
    uint32_t checksum = 0;
    uint16_t word16;
    bool padding = false;

    /* The following block ensures that checksum field is ignored */
    switch(proto) {
        case PROTOCOL_IPV4_UDP:
            word16 = ((buf[0]<<8)&0xFF00) + (buf[1]&0xFF); checksum += word16;
            word16 = ((buf[2]<<8)&0xFF00) + (buf[3]&0xFF); checksum += word16;
            word16 = ((buf[4]<<8)&0xFF00) + (buf[5]&0xFF); checksum += word16;
            i = 8;
            break;
        default:
            i = 0;
            break;
    }
    if (len % 2) {
        padding = true;
        len--;
    }    
    /* Make 16 bit words out of every two adjacent 8 bit words and 
     * calculate the sum of all 16 bit words */
    for (; i < len; i = i+2) {
        word16 = ((buf[i]<<8)&0xFF00) + (buf[i+1]&0xFF);
        checksum += word16;
    }
    if(padding) {
        word16 = (buf[len]<<8)&0xFF00;
        checksum += word16;
        len++;
    }

    /* Add the IPv4 pseudo header which contains the 
     * source and destinations addresses */
    ip8 = (void *)&src;
    word16 = ((ip8[0]<<8)&0xFF00) + (ip8[1]&0xFF); checksum += word16;
    word16 = ((ip8[2]<<8)&0xFF00) + (ip8[3]&0xFF); checksum += word16;
    ip8 = (void *)&dst;
    word16 = ((ip8[0]<<8)&0xFF00) + (ip8[1]&0xFF); checksum += word16;
    word16 = ((ip8[2]<<8)&0xFF00) + (ip8[3]&0xFF); checksum += word16;

    /* Add the protocol number and the length of the UDP packet */
    checksum += proto + len;

    /* Keep only the last 16 bits of the 32 bit calculated sum and add the carries */
    while (checksum >> 16)
        checksum = (checksum & 0xffff) + (checksum >> 16);
    
    /* Take the one's complement of checksum */
    checksum = ~checksum;

    return (uint16_t)checksum;
}

uint16_t
bbl_ipv4_udp_checksum(uint32_t src, uint32_t dst, uint8_t *buf, uint16_t len) {
    return bbl_ipv4_checksum(src, dst, PROTOCOL_IPV4_UDP, buf, len);
}

/*
 * ENCODE
 * ------------------------------------------------------------------------*/

/*
 * encode_dhcpv6
 */
protocol_error_t
encode_dhcpv6(uint8_t *buf, uint16_t *len,
              bbl_dhcpv6_t *dhcpv6) {

    *(uint32_t*)buf = dhcpv6->transaction_id;
    *buf = dhcpv6->type;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    if(dhcpv6->client_duid_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_CLIENTID);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->client_duid_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->client_duid, dhcpv6->client_duid_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->client_duid_len);
    }
    if(dhcpv6->server_duid_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_SERVERID);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->server_duid_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->server_duid, dhcpv6->server_duid_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->server_duid_len);
    }
    if(dhcpv6->rapid) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_RAPID_COMMIT);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
    if(dhcpv6->ia_pd_option_len) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IA_PD);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(dhcpv6->ia_pd_option_len);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        memcpy(buf, dhcpv6->ia_pd_option, dhcpv6->ia_pd_option_len);
        BUMP_WRITE_BUFFER(buf, len, dhcpv6->ia_pd_option_len);
    } else if(dhcpv6->delegated_prefix_iaid) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IA_PD);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(41);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = dhcpv6->delegated_prefix_iaid;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = 0; // T1
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = 0; // T2
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_IAPREFIX);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(25); // length
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint32_t*)buf = 0; // preferred lifetime
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        *(uint32_t*)buf = 0; // valid lifetime
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        memcpy(buf, dhcpv6->delegated_prefix, sizeof(ipv6_prefix));
        BUMP_WRITE_BUFFER(buf, len, sizeof(ipv6_prefix));
    }
    if(dhcpv6->oro) {
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_ORO);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(2);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
        *(uint16_t*)buf = htobe16(DHCPV6_OPTION_DNS_SERVERS);
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
    }
    return PROTOCOL_SUCCESS;
}

/*
 * encode_dhcp
 */
protocol_error_t
encode_dhcp(uint8_t *buf, uint16_t *len,
            bbl_dhcp_t *dhcp) {

    if(!dhcp->header) return ENCODE_ERROR;

    uint8_t  str_len;
    uint8_t  option_len;
    uint8_t *option_len_ptr;

    memcpy(buf, dhcp->header, sizeof(struct dhcp_header));
    BUMP_WRITE_BUFFER(buf, len, sizeof(struct dhcp_header));

    /* Magic Cookie */
    *(uint32_t*)buf = DHCP_MAGIC_COOKIE;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    *buf = DHCPV4_OPTION_DHCP_MESSAGE_TYPE;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = 1;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    *buf = dhcp->type;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    if(dhcp->parameter_request_list) {
        *buf = DHCPV4_OPTION_PARAM_REQUEST_LIST;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        option_len_ptr = buf;
        option_len = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        if(dhcp->option_netmask) {
            option_len++;
            *buf = DHCPV4_OPTION_SUBNET_MASK;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        if(dhcp->option_router) {
            option_len++;
            *buf = DHCPV4_OPTION_ROUTER;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        if(dhcp->option_dns1 || dhcp->option_dns2) {
            option_len++;
            *buf = DHCPV4_OPTION_DNS_SERVER;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        if(dhcp->option_domain_name) {
            option_len++;
            *buf = DHCPV4_OPTION_DOMAIN_NAME;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        }
        *option_len_ptr = option_len;
    }
    if(dhcp->client_identifier) {
        *buf = DHCPV4_OPTION_CLIENT_IDENTIFIER;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = dhcp->client_identifier_len;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        memcpy(buf, dhcp->client_identifier, dhcp->client_identifier_len);
        BUMP_WRITE_BUFFER(buf, len, dhcp->client_identifier_len);
    }
    if(dhcp->option_server_identifier) {
        *buf = DHCPV4_OPTION_SERVER_IDENTIFIER;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 4;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint32_t*)buf = dhcp->server_identifier;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }
    if(dhcp->option_address) {
        *buf = DHCPV4_OPTION_REQUESTED_IP_ADDRESS;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *buf = 4;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        *(uint32_t*)buf = dhcp->address;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
    }

    if(dhcp->access_line) {
        /* RFC3046 Relay Agent Information Option (82) */
        *buf = DHCPV4_OPTION_RELAY_AGENT_INFORMATION;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        option_len_ptr = buf;
        option_len = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
        if(dhcp->access_line->aci) {
            *buf = ACCESS_LINE_ACI;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            str_len = strnlen(dhcp->access_line->aci, UINT8_MAX);
            *buf = str_len;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            memcpy(buf, dhcp->access_line->aci, str_len);
            BUMP_WRITE_BUFFER(buf, len, str_len);
            option_len += str_len + 2;
        }
        if(dhcp->access_line->ari) {
            *buf = ACCESS_LINE_ARI;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            str_len = strnlen(dhcp->access_line->ari, UINT8_MAX);
            *buf = str_len;
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
            memcpy(buf, dhcp->access_line->ari, str_len);
            BUMP_WRITE_BUFFER(buf, len, str_len);
            option_len += str_len + 2;
        }
        *option_len_ptr = option_len;
    }

    *buf = DHCPV4_OPTION_END;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));

    /* This is optional ... */
    while(*len % 8) {
        *buf = DHCPV4_OPTION_PAD;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
    }
    return PROTOCOL_SUCCESS;
}

/*
 * encode_bbl
 */
protocol_error_t
encode_bbl(uint8_t *buf, uint16_t *len,
           bbl_bbl_t *bbl) {

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
    if(bbl->type == BBL_TYPE_UNICAST_SESSION) {
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
protocol_error_t
encode_udp(uint8_t *buf, uint16_t *len,
           bbl_udp_t *udp) {

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
            result = encode_dhcpv6(buf, len, (bbl_dhcpv6_t*)udp->next);
            break;
        case UDP_PROTOCOL_BBL:
            result = encode_bbl(buf, len, (bbl_bbl_t*)udp->next);
            break;
        case UDP_PROTOCOL_L2TP:
            result = encode_l2tp(buf, len, (bbl_l2tp_t*)udp->next);
            break;
        case UDP_PROTOCOL_DHCP:
            result = encode_dhcp(buf, len, (bbl_dhcp_t*)udp->next);
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
protocol_error_t
encode_icmpv6(uint8_t *buf, uint16_t *len,
              bbl_icmpv6_t *icmp) {


    uint8_t *start = buf;
    uint16_t icmp_len = *len;

    *(uint32_t*)buf = 0;
    *buf = icmp->type;
    *(buf+1) = icmp->code;
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));

    if(icmp->data_len) {
        /* Copy data */
        *(uint32_t*)buf = 0;
        BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
        memcpy(buf, icmp->data, icmp->data_len);
        BUMP_WRITE_BUFFER(buf, len, icmp->data_len);
    } else {
        switch(icmp->type) {
            case IPV6_ICMPV6_ROUTER_SOLICITATION:
                *(uint32_t*)buf = 0;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                break;
            case IPV6_ICMPV6_NEIGHBOR_SOLICITATION:
                *(uint32_t*)buf = 0; /* Reserved */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                /* Target address */
                memcpy(buf, icmp->prefix.address, IPV6_ADDR_LEN);
                BUMP_WRITE_BUFFER(buf, len, IPV6_ADDR_LEN);
                *(uint8_t*)buf = 1; /* Source link-layer address */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint8_t*)buf = 1; /* Length (1 = 8 byte) */
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
                *(uint8_t*)buf = 2; /* Target link-layer address */
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint8_t*)buf = 1; /* Length (1 = 8 byte) */
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
    *(uint16_t*)(start + 2) = bbl_checksum((uint16_t*)start, icmp_len);


    return PROTOCOL_SUCCESS;
}

/*
 * encode_arp
 */
protocol_error_t
encode_arp(uint8_t *buf, uint16_t *len,
           bbl_arp_t *arp) {

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
protocol_error_t
encode_icmp(uint8_t *buf, uint16_t *len,
            bbl_icmp_t *icmp) {

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
    *(uint16_t*)(start + 2) = bbl_checksum((uint16_t*)start, icmp_len);

    return PROTOCOL_SUCCESS;
}

/*
 * encode_igmp
 */
protocol_error_t
encode_igmp(uint8_t *buf, uint16_t *len,
            bbl_igmp_t *igmp) {

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
    *(uint16_t*)(start + 2) = bbl_checksum((uint16_t*)start, igmp_len);

    return PROTOCOL_SUCCESS;
}

/*
 * encode_ipv6
 */
protocol_error_t
encode_ipv6(uint8_t *buf, uint16_t *len,
             bbl_ipv6_t *ipv6) {

    protocol_error_t result;

    uint8_t *start = buf;
    uint16_t ipv6_len;
    uint16_t checksum;

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
            result = encode_icmpv6(buf, len, (bbl_icmpv6_t*)ipv6->next);
            ipv6_len = *len - ipv6_len;
            checksum = bbl_ipv6_icmpv6_checksum(ipv6->src, ipv6->dst, buf, ipv6_len);
            *(uint16_t*)(buf + 2) = htobe16(checksum); // update icmpv6 checksum
            break;
        case IPV6_NEXT_HEADER_UDP:
            result = encode_udp(buf, len, (bbl_udp_t*)ipv6->next);
            ipv6_len = *len - ipv6_len;
            *(uint16_t*)(buf + 4) = htobe16(ipv6_len); // update UDP length
            if(((bbl_udp_t*)ipv6->next)->protocol != UDP_PROTOCOL_BBL) {
                checksum = bbl_ipv6_udp_checksum(ipv6->src, ipv6->dst, buf, ipv6_len);
                *(uint16_t*)(buf + 6) = htobe16(checksum); // update UDP checksum
            }
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
protocol_error_t
encode_ipv4(uint8_t *buf, uint16_t *len,
            bbl_ipv4_t *ipv4) {

    protocol_error_t result;

    uint8_t *start = buf;
    uint16_t ipv4_len = *len;
    uint16_t udp_len = *len;
    uint16_t checksum;
    uint8_t header_len = 5; // header length 20 (4 * 5)

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
            result = encode_igmp(buf, len, (bbl_igmp_t*)ipv4->next);
            break;
        case PROTOCOL_IPV4_ICMP:
            result = encode_icmp(buf, len, (bbl_icmp_t*)ipv4->next);
            break;
        case PROTOCOL_IPV4_UDP:
            udp_len = *len;
            result = encode_udp(buf, len, (bbl_udp_t*)ipv4->next);
            udp_len = *len - udp_len;
            *(uint16_t*)(buf + 4) = htobe16(udp_len); // update UDP length
            if(((bbl_udp_t*)ipv4->next)->protocol != UDP_PROTOCOL_BBL) {
                checksum = bbl_ipv4_udp_checksum(ipv4->src, ipv4->dst, buf, udp_len);
                *(uint16_t*)(buf + 6) = htobe16(checksum); // update UDP checksum
            }
            break;
        default:
            result = PROTOCOL_SUCCESS;
            break;
    }

    /* Update total length */
    ipv4_len = *len - ipv4_len;
    *(uint16_t*)(start + 2) = htobe16(ipv4_len);

    /* Update checksum */
    *(uint16_t*)(start + 10) = bbl_checksum((uint16_t*)start, header_len * 4);

    return result;
}

/*
 * encode_ppp_pap
 */
protocol_error_t
encode_ppp_pap(uint8_t *buf, uint16_t *len,
               bbl_pap_t *pap) {

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
protocol_error_t
encode_ppp_chap(uint8_t *buf, uint16_t *len,
                bbl_chap_t *chap) {

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
protocol_error_t
encode_ppp_ip6cp(uint8_t *buf, uint16_t *len,
                 bbl_ip6cp_t *ip6cp) {

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
protocol_error_t
encode_ppp_ipcp(uint8_t *buf, uint16_t *len,
                bbl_ipcp_t *ipcp) {

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
        /* Constuct options ... */
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
protocol_error_t
encode_ppp_lcp(uint8_t *buf, uint16_t *len,
               bbl_lcp_t *lcp) {

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
            /* Constuct options ... */
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
    return PROTOCOL_SUCCESS;
}

/*
 * encode_l2tp
 */
protocol_error_t
encode_l2tp(uint8_t *buf, uint16_t *len, bbl_l2tp_t *l2tp) {

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
            BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));
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
                result = encode_ppp_lcp(buf, len, (bbl_lcp_t*)l2tp->next);
                break;
            case PROTOCOL_IPCP:
                result = encode_ppp_ipcp(buf, len, (bbl_ipcp_t*)l2tp->next);
                break;
            case PROTOCOL_IP6CP:
                result = encode_ppp_ip6cp(buf, len, (bbl_ip6cp_t*)l2tp->next);
                break;
            case PROTOCOL_PAP:
                result = encode_ppp_pap(buf, len, (bbl_pap_t*)l2tp->next);
                break;
            case PROTOCOL_CHAP:
                result = encode_ppp_chap(buf, len, (bbl_chap_t*)l2tp->next);
                break;
            case PROTOCOL_IPV4:
                result = encode_ipv4(buf, len, (bbl_ipv4_t*)l2tp->next);
                break;
            case PROTOCOL_IPV6:
                result = encode_ipv6(buf, len, (bbl_ipv6_t*)l2tp->next);
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
protocol_error_t
encode_pppoe_discovery(uint8_t *buf, uint16_t *len,
                       bbl_pppoe_discovery_t *pppoe) {

    uint16_t *pppoe_len_field;
    uint16_t *vendor_len_field;
    uint16_t  pppoe_len = 0;
    uint16_t  vendor_len = 0;
    uint8_t   str_len = 0;

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
            if(pppoe->access_line->down) {
                *buf = ACCESS_LINE_DSL_TYPE;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *buf = 4;
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint8_t));
                *(uint32_t*)buf = htobe32(pppoe->access_line->dsl_type);
                BUMP_WRITE_BUFFER(buf, len, sizeof(uint32_t));
                vendor_len += 6;
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
protocol_error_t
encode_pppoe_session(uint8_t *buf, uint16_t *len,
                     bbl_pppoe_session_t *pppoe) {

    protocol_error_t result;
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
    /* Add protocol */
    switch(pppoe->protocol) {
        case PROTOCOL_LCP:
            result = encode_ppp_lcp(buf, len, (bbl_lcp_t*)pppoe->next);
            break;
        case PROTOCOL_IPCP:
            result = encode_ppp_ipcp(buf, len, (bbl_ipcp_t*)pppoe->next);
            break;
        case PROTOCOL_IP6CP:
            result = encode_ppp_ip6cp(buf, len, (bbl_ip6cp_t*)pppoe->next);
            break;
        case PROTOCOL_PAP:
            result = encode_ppp_pap(buf, len, (bbl_pap_t*)pppoe->next);
            break;
        case PROTOCOL_CHAP:
            result = encode_ppp_chap(buf, len, (bbl_chap_t*)pppoe->next);
            break;
        case PROTOCOL_IPV4:
            result = encode_ipv4(buf, len, (bbl_ipv4_t*)pppoe->next);
            break;
        case PROTOCOL_IPV6:
            result = encode_ipv6(buf, len, (bbl_ipv6_t*)pppoe->next);
            break;
        default:
            result = UNKNOWN_PROTOCOL;
            break;
    }

    pppoe_len = *len - pppoe_len;
    pppoe_len += 2; // PPP header
    *pppoe_len_field = htobe16(pppoe_len);
    return result;
}

/*
 * encode_ethernet
 */
protocol_error_t
encode_ethernet(uint8_t *buf, uint16_t *len,
                bbl_ethernet_header_t *eth) {
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
        *(uint16_t*)buf = htobe16(ETH_TYPE_VLAN);
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

    /* Add ethertype */
    *(uint16_t*)buf = htobe16(eth->type);
    BUMP_WRITE_BUFFER(buf, len, sizeof(uint16_t));

    /* Add protocol header */
    switch(eth->type) {
        case ETH_TYPE_PPPOE_DISCOVERY:
            return encode_pppoe_discovery(buf, len, (bbl_pppoe_discovery_t*)eth->next);
        case ETH_TYPE_PPPOE_SESSION:
            return encode_pppoe_session(buf, len, (bbl_pppoe_session_t*)eth->next);
        case ETH_TYPE_ARP:
            return encode_arp(buf, len, (bbl_arp_t*)eth->next);
        case ETH_TYPE_IPV4:
            return encode_ipv4(buf, len, (bbl_ipv4_t*)eth->next);
        case ETH_TYPE_IPV6:
            return encode_ipv6(buf, len, (bbl_ipv6_t*)eth->next);
        default:
            return UNKNOWN_PROTOCOL;
    }
}

/*
 * DECODE
 * ------------------------------------------------------------------------*/

/*
 * decode_icmp
 */
protocol_error_t
decode_icmp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_icmp_t **_icmp) {

    bbl_icmp_t *icmp;

    if(len < 4 || sp_len < sizeof(bbl_icmp_t)) {
        return DECODE_ERROR;
    }

    /* Init ICMP header */
    icmp = (bbl_icmp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_icmp_t));
    //memset(icmp, 0x0, sizeof(bbl_icmp_t));

    icmp->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    icmp->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    BUMP_BUFFER(buf, len, sizeof(uint16_t)); // checksum

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
protocol_error_t
decode_icmpv6(uint8_t *buf, uint16_t len,
              uint8_t *sp, uint16_t sp_len,
              bbl_icmpv6_t **_icmpv6) {

    bbl_icmpv6_t *icmpv6;

    uint8_t  flags;
    uint8_t  option;
    uint16_t option_len;

    if(len < 4 || sp_len < sizeof(bbl_icmpv6_t)) {
        return DECODE_ERROR;
    }

    /* Init ICMP header */
    icmpv6 = (bbl_icmpv6_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_icmpv6_t));
    memset(icmpv6, 0x0, sizeof(bbl_icmpv6_t));

    icmpv6->type = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    icmpv6->code = *buf;
    BUMP_BUFFER(buf, len, sizeof(uint8_t));
    BUMP_BUFFER(buf, len, sizeof(uint16_t)); // checksum

    if(len) {
        icmpv6->data = buf;
        icmpv6->data_len = len;
    }

    switch(icmpv6->type) {
        case IPV6_ICMPV6_ROUTER_ADVERTISEMENT:
            if(len < 12) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint8_t)); // hop limit
            flags = *buf;
            if(flags & ICMPV6_FLAGS_OTHER_CONFIG) icmpv6->other = true;
            BUMP_BUFFER(buf, len, 11);
            while(len > 2) {
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
        case IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT:
            if(len < 20) {
                return DECODE_ERROR;
            }
            BUMP_BUFFER(buf, len, sizeof(uint32_t)); // flags / reserved
            memcpy(&icmpv6->prefix.address, buf, IPV6_ADDR_LEN);
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
protocol_error_t
decode_igmp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_igmp_t **_igmp) {

    bbl_igmp_t *igmp;

    uint16_t sources;

    if(len < 8 || sp_len < sizeof(bbl_igmp_t)) {
        return DECODE_ERROR;
    }

    /* Init IGMP header */
    igmp = (bbl_igmp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_igmp_t));
    memset(igmp, 0x0, sizeof(bbl_igmp_t));

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

/*
 * decode_dhcpv6
 */
protocol_error_t
decode_dhcpv6(uint8_t *buf, uint16_t len,
              uint8_t *sp, uint16_t sp_len,
              bbl_dhcpv6_t **_dhcpv6) {

    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_dhcpv6_t *dhcpv6;
    uint16_t option;
    uint16_t option_len;

    if(len < 8 || sp_len < sizeof(bbl_dhcpv6_t)) {
        return DECODE_ERROR;
    }

    /* Init DHCPv6 structure */
    dhcpv6 = (bbl_dhcpv6_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_dhcpv6_t));
    memset(dhcpv6, 0x0, sizeof(bbl_dhcpv6_t));

    dhcpv6->transaction_id = be32toh(*(uint32_t*)buf);
    dhcpv6->type = dhcpv6->transaction_id >> 24;
    dhcpv6->transaction_id &= DHCPV6_TYPE_MASK;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));

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
            case DHCPV6_OPTION_IA_PD:
                if(option_len < 41) {
                    return DECODE_ERROR;
                }
                dhcpv6->ia_pd_option = buf;
                dhcpv6->ia_pd_option_len = option_len;
                option = be16toh(*(uint16_t*)(buf+12));
                if(option == 26) {
                    dhcpv6->delegated_prefix = (ipv6_prefix*)(buf+24);
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
            default:
                break;
        }
        BUMP_BUFFER(buf, len, option_len);
    }
    *_dhcpv6 = dhcpv6;
    return ret_val;
}

/*
 * decode_dhcp
 */
protocol_error_t
decode_dhcp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_dhcp_t **_dhcp) {

    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_dhcp_t *dhcp;

    uint8_t option;
    uint8_t option_len;

    if(len < sizeof(struct dhcp_header) + 4 || sp_len < sizeof(bbl_dhcp_t)) {
        return DECODE_ERROR;
    }

    /* Init DHCP structure */
    dhcp = (bbl_dhcp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_dhcp_t));
    memset(dhcp, 0x0, sizeof(bbl_dhcp_t));

    dhcp->header = (struct dhcp_header*)buf;
    BUMP_BUFFER(buf, len, sizeof(struct dhcp_header));

    /* Magic Cookie */
    BUMP_BUFFER(buf, len, sizeof(uint32_t));

    while(len >= 2) {
        option = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(option == DHCPV4_OPTION_PAD) {
            continue;
        }
        option_len = *buf;
        BUMP_BUFFER(buf, len, sizeof(uint8_t));
        if(option_len > len) {
            return DECODE_ERROR;
        }
        switch(option) {
            case DHCPV4_OPTION_END:
                option_len = len;
                break;
            case DHCPV4_OPTION_DHCP_MESSAGE_TYPE:
                if(option_len != 1) {
                    return DECODE_ERROR;
                }
                dhcp->type = *buf;
                break;
            case DHCPV4_OPTION_IP_ADDRESS_LEASE_TIME:
                if(option_len != 4) {
                    return DECODE_ERROR;
                }
                dhcp->lease_time = be32toh(*(uint32_t*)buf);
                dhcp->option_lease_time = true;
                break;
            case DHCPV4_OPTION_CLIENT_IDENTIFIER:
                dhcp->client_identifier = buf;
                dhcp->client_identifier_len = option_len;
                break;
            case DHCPV4_OPTION_SERVER_IDENTIFIER:
                if(option_len != 4) {
                    return DECODE_ERROR;
                }
                dhcp->server_identifier = *(uint32_t*)buf;
                dhcp->option_server_identifier = true;
                break;
            case DHCPV4_OPTION_SUBNET_MASK:
                if(option_len != 4) {
                    return DECODE_ERROR;
                }
                dhcp->netmask = *(uint32_t*)buf;
                dhcp->option_netmask = true;
                break;
            case DHCPV4_OPTION_ROUTER:
                if(option_len < 4) {
                    return DECODE_ERROR;
                }
                dhcp->router = *(uint32_t*)buf;
                dhcp->option_router = true;
                break;
            case DHCPV4_OPTION_DNS_SERVER:
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
            case DHCPV4_OPTION_HOST_NAME:
                dhcp->host_name = (char*)buf;
                dhcp->host_name_len = option_len;
                break;
            case DHCPV4_OPTION_DOMAIN_NAME:
                dhcp->domain_name = (char*)buf;
                dhcp->domain_name_len = option_len;
                break;
            case DHCPV4_OPTION_INTERFACE_MTU:
                if(option_len != 2) {
                    return DECODE_ERROR;
                }
                dhcp->mtu = be16toh(*(uint16_t*)buf);
                dhcp->option_mtu = true;
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
protocol_error_t
decode_bbl(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_bbl_t **_bbl) {

    bbl_bbl_t *bbl;

    if(len < 48 || sp_len < sizeof(bbl_bbl_t)) {
        return DECODE_ERROR;
    }
    /* Init BBL header */
    bbl = (bbl_bbl_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_bbl_t));

    if(len > 48) {
        /* Bump padding... */
        BUMP_BUFFER(buf, len, (len - 48));
    }

    if(*(uint64_t*)buf != BBL_MAGIC_NUMBER) {
        return DECODE_ERROR;
    }
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
    if(bbl->type == BBL_TYPE_UNICAST_SESSION) {
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
protocol_error_t
decode_qmx_li(uint8_t *buf, uint16_t len,
              uint8_t *sp, uint16_t sp_len,
              bbl_qmx_li_t **_qmx_li) {

    bbl_qmx_li_t *qmx_li;

    if(len < 4 || sp_len < sizeof(bbl_qmx_li_t)) {
        return DECODE_ERROR;
    }
    /* Init QMX LI header */
    qmx_li = (bbl_qmx_li_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_qmx_li_t));
    qmx_li->header = *(uint32_t*)buf;
    qmx_li->liid = be32toh(*(uint32_t*)buf) & 0x003fffff;
    qmx_li->direction = (*buf >> 5) & 0x7;
    qmx_li->packet_type = (*buf >> 1) & 0xf;
    qmx_li->sub_packet_type =(be16toh(*(uint16_t*)buf) >> 6) & 0x07;
    BUMP_BUFFER(buf, len, sizeof(uint32_t));
    qmx_li->payload = buf;
    qmx_li->payload_len = len;
    *_qmx_li = qmx_li;
    return decode_ethernet(buf, len, sp, sp_len, (bbl_ethernet_header_t**)&qmx_li->next);
}

/*
 * decode_udp
 */
protocol_error_t
decode_udp(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_udp_t **_udp) {

    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_udp_t *udp;

    if(len < 8 || sp_len < sizeof(bbl_udp_t)) {
        return DECODE_ERROR;
    }

    /* Init UDP header */
    udp = (bbl_udp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_udp_t));
    //memset(udp, 0x0, sizeof(bbl_udp_t));

    udp->src = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    udp->dst = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    udp->payload_len = be16toh(*(uint16_t*)buf);
    udp->payload_len -= 8;
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    BUMP_BUFFER(buf, len, sizeof(uint16_t));

    if(udp->payload_len > len) {
        return DECODE_ERROR;
    }
    len = udp->payload_len;

    switch(udp->dst) {
        case DHCPV6_UDP_CLIENT:
        case DHCPV6_UDP_SERVER:
            udp->protocol = UDP_PROTOCOL_DHCPV6;
            ret_val = decode_dhcpv6(buf, len, sp, sp_len, (bbl_dhcpv6_t**)&udp->next);
            break;
        case BBL_UDP_PORT:
            udp->protocol = UDP_PROTOCOL_BBL;
            ret_val = decode_bbl(buf, len, sp, sp_len, (bbl_bbl_t**)&udp->next);
            break;
        case L2TP_UDP_PORT:
            udp->protocol = UDP_PROTOCOL_L2TP;
            ret_val = decode_l2tp(buf, len, sp, sp_len, (bbl_l2tp_t**)&udp->next);
            break;
        case DHCP_UDP_CLIENT:
            udp->protocol = UDP_PROTOCOL_DHCP;
            ret_val = decode_dhcp(buf, len, sp, sp_len, (bbl_dhcp_t**)&udp->next);
            break;
        case QMX_LI_UDP_PORT:
            udp->protocol = UDP_PROTOCOL_QMX_LI;
            ret_val = decode_qmx_li(buf, len, sp, sp_len, (bbl_qmx_li_t**)&udp->next);
            break;
        default:
            if(udp->src == QMX_LI_UDP_PORT) {
                udp->protocol = UDP_PROTOCOL_QMX_LI;
                ret_val = decode_qmx_li(buf, len, sp, sp_len, (bbl_qmx_li_t**)&udp->next);
            } else {
                udp->protocol = 0;
                udp->next = NULL;
            }
            break;
    }

    *_udp = udp;
    return ret_val;
}

/*
 * decode_ipv6
 */
protocol_error_t
decode_ipv6(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_ipv6_t **_ipv6) {

    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_ipv6_t *ipv6;

    if(len < 40 || sp_len < sizeof(bbl_ipv6_t)) {
        return DECODE_ERROR;
    }

    /* Init IPv6 header */
    ipv6 = (bbl_ipv6_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ipv6_t));
    //memset(ipv6, 0x0, sizeof(bbl_ipv6_t));
    
    /* Check if version is 6 */
    if(((*buf >> 4) & 0xf) != 6) {
        return DECODE_ERROR;
    }

    ipv6->tos = (be16toh(*(uint16_t*)buf) >> 4);
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

    if(ipv6->payload_len > len) { 
        return DECODE_ERROR;
    }
    len = ipv6->payload_len;

     /* Decode protocol */
    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_ICMPV6:
            ret_val = decode_icmpv6(buf, len, sp, sp_len, (bbl_icmpv6_t**)&ipv6->next);
            break;
        case IPV6_NEXT_HEADER_UDP:
            ret_val = decode_udp(buf, len, sp, sp_len, (bbl_udp_t**)&ipv6->next);
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
protocol_error_t
decode_ipv4(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_ipv4_t **_ipv4) {

    protocol_error_t ret_val = PROTOCOL_SUCCESS;

    bbl_ipv4_t *ipv4;
    const struct ip* header;

    uint16_t ipv4_header_len;
    uint16_t ipv4_total_len;

    if(len < 20 || sp_len < sizeof(bbl_ipv4_t)) {
        return DECODE_ERROR;
    }

    /* Init IPv4 header */
    ipv4 = (bbl_ipv4_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ipv4_t));
    //memset(ipv4, 0x0, sizeof(bbl_ipv4_t));

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
    ipv4_total_len = be16toh(header->ip_len);
    if(ipv4_header_len > ipv4_total_len || 
       ipv4_total_len > len)  {
        return DECODE_ERROR;
    }

    ipv4->offset = be16toh(header->ip_off);
    ipv4->ttl = header->ip_ttl;
    ipv4->protocol = header->ip_p;

    ipv4->src = header->ip_src.s_addr;
    ipv4->dst = header->ip_dst.s_addr;
    BUMP_BUFFER(buf, len, ipv4_header_len);

    ipv4->payload = buf;
    ipv4->payload_len = ipv4_total_len - ipv4_header_len;

    if(ipv4->payload_len > len) {
        return DECODE_ERROR;
    }
    len = ipv4->payload_len;

    switch(ipv4->protocol) {
        case PROTOCOL_IPV4_IGMP:
            ret_val = decode_igmp(buf, len, sp, sp_len, (bbl_igmp_t**)&ipv4->next);
            break;
        case PROTOCOL_IPV4_ICMP:
            ret_val = decode_icmp(buf, len, sp, sp_len, (bbl_icmp_t**)&ipv4->next);
            break;
        case PROTOCOL_IPV4_UDP:
            ret_val = decode_udp(buf, len, sp, sp_len, (bbl_udp_t**)&ipv4->next);
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
protocol_error_t
decode_ppp_pap(uint8_t *buf, uint16_t len,
               uint8_t *sp, uint16_t sp_len,
               bbl_pap_t **ppp_pap) {

    bbl_pap_t *pap;
    uint16_t   pap_len;

    if(len < 4 || sp_len < sizeof(bbl_pap_t)) {
        return DECODE_ERROR;
    }

    /* Init PAP header */
    pap = (bbl_pap_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_pap_t));
    memset(pap, 0x0, sizeof(bbl_pap_t));

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
protocol_error_t
decode_ppp_chap(uint8_t *buf, uint16_t len,
                uint8_t *sp, uint16_t sp_len,
                bbl_chap_t **ppp_chap) {

    bbl_chap_t *chap;
    uint16_t chap_len;

    if(len < 4 || sp_len < sizeof(bbl_chap_t)) {
        return DECODE_ERROR;
    }

    /* Init CHAP header */
    chap = (bbl_chap_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_chap_t));
    memset(chap, 0x0, sizeof(bbl_chap_t));

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
protocol_error_t
decode_ppp_ip6cp(uint8_t *buf, uint16_t len,
                 uint8_t *sp, uint16_t sp_len,
                 bbl_ip6cp_t **ppp_ip6cp) {

    bbl_ip6cp_t *ip6cp;

    uint16_t ip6cp_len = 0;
    uint8_t  ip6cp_option_type = 0;
    uint8_t  ip6cp_option_len = 0;

    if(len < 4 || sp_len < sizeof(bbl_ip6cp_t)) {
        return DECODE_ERROR;
    }

    /* Init IP6CP header */
    ip6cp = (bbl_ip6cp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ip6cp_t));
    memset(ip6cp, 0x0, sizeof(bbl_ip6cp_t));

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
                        ip6cp->ipv6_identifier = *(uint64_t*)buf;
                        break;
                    default:
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
protocol_error_t
decode_ppp_ipcp(uint8_t *buf, uint16_t len,
                uint8_t *sp, uint16_t sp_len,
                bbl_ipcp_t **ppp_ipcp) {

    bbl_ipcp_t *ipcp;

    uint16_t ipcp_len = 0;
    uint8_t  ipcp_option_type = 0;
    uint8_t  ipcp_option_len = 0;

    if(len < 4 || sp_len < sizeof(bbl_ipcp_t)) {
        return DECODE_ERROR;
    }

    /* Init IPCP header */
    ipcp = (bbl_ipcp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ipcp_t));
    memset(ipcp, 0x0, sizeof(bbl_ipcp_t));

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
                        ipcp->address = *(uint32_t*)buf;
                        break;
                    case PPP_IPCP_OPTION_DNS1:
                        ipcp->dns1 = *(uint32_t*)buf;
                        break;
                    case PPP_IPCP_OPTION_DNS2:
                        ipcp->dns2 = *(uint32_t*)buf;
                        break;
                    default:
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
protocol_error_t
decode_ppp_lcp(uint8_t *buf, uint16_t len,
               uint8_t *sp, uint16_t sp_len,
               bbl_lcp_t **ppp_lcp) {

    bbl_lcp_t *lcp;

    uint16_t lcp_len = 0;
    uint8_t  lcp_option_type = 0;
    uint8_t  lcp_option_len = 0;

    if(len < 4 || sp_len < sizeof(bbl_lcp_t)) {
        return DECODE_ERROR;
    }

    /* Init LCP header */
    lcp = (bbl_lcp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_lcp_t));
    memset(lcp, 0x0, sizeof(bbl_lcp_t));

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
                        lcp->mru = be16toh(*(uint16_t*)buf);
                        break;
                    case PPP_LCP_OPTION_AUTH:
                        lcp->auth = be16toh(*(uint16_t*)buf);
                        break;
                    case PPP_LCP_OPTION_MAGIC:
                        lcp->magic = *(uint32_t*)buf;
                        break;
                    default:
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
protocol_error_t
decode_l2tp(uint8_t *buf, uint16_t len,
            uint8_t *sp, uint16_t sp_len,
            bbl_l2tp_t **_l2tp) {

    protocol_error_t ret_val = UNKNOWN_PROTOCOL;
    bbl_l2tp_t *l2tp;

    uint16_t l2tp_len = 0;

    if(len < 8 || sp_len < sizeof(bbl_l2tp_t)) {
        return DECODE_ERROR;
    }

    /* Init L2TP header */
    l2tp = (bbl_l2tp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_l2tp_t));
    memset(l2tp, 0x0, sizeof(bbl_l2tp_t));

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
    l2tp->tunnel_id = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    l2tp->session_id = be16toh(*(uint16_t*)buf);
    BUMP_BUFFER(buf, len, sizeof(uint16_t));
    
    if(l2tp->with_sequence) {
        if(len < 4) return DECODE_ERROR;
        l2tp->ns = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        l2tp->nr = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
    } else if(l2tp->type) {
        /* Sequence is mandatory for control packets */
        return DECODE_ERROR;
    }

    if(l2tp->with_offset) {
        if(len < 2) return DECODE_ERROR;
        l2tp->offset = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(l2tp->offset) {
            if(len < l2tp->offset) return DECODE_ERROR;
            /* Actually never seen a BNG sending offset
             * different than zero... */
            BUMP_BUFFER(buf, len, l2tp->offset);
        }
    }

    if(l2tp->type) {
        /* L2TP control packet */
        if(len) {
            if(len < 8) return DECODE_ERROR;
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            if(*(uint32_t*)buf != 0) return DECODE_ERROR;
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
        if(len < 4) return DECODE_ERROR;
        
        l2tp->payload = buf;
        l2tp->payload_len = len;

        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        l2tp->protocol = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));

        /* Decode protocol */
        switch(l2tp->protocol) {
            case PROTOCOL_IPV4:
                ret_val = decode_ipv4(buf, len, sp, sp_len, (bbl_ipv4_t**)&l2tp->next);
                break;
            case PROTOCOL_IPV6:
                ret_val = decode_ipv6(buf, len, sp, sp_len, (bbl_ipv6_t**)&l2tp->next);
                break;
            case PROTOCOL_LCP:
                ret_val = decode_ppp_lcp(buf, len, sp, sp_len, (bbl_lcp_t**)&l2tp->next);
                break;
            case PROTOCOL_IPCP:
                ret_val = decode_ppp_ipcp(buf, len, sp, sp_len, (bbl_ipcp_t**)&l2tp->next);
                break;
            case PROTOCOL_IP6CP:
                ret_val = decode_ppp_ip6cp(buf, len, sp, sp_len, (bbl_ip6cp_t**)&l2tp->next);
                break;
            case PROTOCOL_PAP:
                ret_val = decode_ppp_pap(buf, len, sp, sp_len, (bbl_pap_t**)&l2tp->next);
                break;
            case PROTOCOL_CHAP:
                ret_val = decode_ppp_chap(buf, len, sp, sp_len, (bbl_chap_t**)&l2tp->next);
                break;
            default:
                break;
        }
    }
    *_l2tp = l2tp;
    return ret_val;
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
protocol_error_t
decode_pppoe_discovery(uint8_t *buf, uint16_t len,
                       uint8_t *sp, uint16_t sp_len,
                       bbl_pppoe_discovery_t **pppoe_discovery) {
    bbl_pppoe_discovery_t *pppoe;
    uint16_t pppoe_len = 0;
    uint16_t pppoe_tag_type = 0;
    uint16_t pppoe_tag_len = 0;

    if(len < 6 || sp_len < sizeof(bbl_pppoe_discovery_t)) {
        return DECODE_ERROR;
    }

    /* Init PPPoE header */
    pppoe = (bbl_pppoe_discovery_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_pppoe_discovery_t));
    memset(pppoe, 0x0, sizeof(bbl_pppoe_discovery_t));

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
protocol_error_t
decode_pppoe_session(uint8_t *buf, uint16_t len,
                     uint8_t *sp, uint16_t sp_len,
                     bbl_pppoe_session_t **pppoe_session) {

    protocol_error_t ret_val = UNKNOWN_PROTOCOL;
    bbl_pppoe_session_t *pppoe;
    const struct pppoe_ppp_session_header *header;

    uint16_t pppoe_len = 0;

    if(len < 8 || sp_len < sizeof(bbl_pppoe_session_t)) {
        return DECODE_ERROR;
    }

    /* Init PPPoE header */
    pppoe = (bbl_pppoe_session_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_pppoe_session_t));
    //memset(pppoe, 0x0, sizeof(bbl_pppoe_session_t));

    header = (struct pppoe_ppp_session_header*)buf;
    BUMP_BUFFER(buf, len, sizeof(struct pppoe_ppp_session_header));

    /* Check if version and type are both set to 1 */
    if(header->version_type != 17) {
        return DECODE_ERROR;
    }
    pppoe->session_id = be16toh(header->session_id);
    pppoe_len = be16toh(header->len) - 2; // - 2 byte PPP header
    pppoe->protocol = be16toh(header->protocol);
    if(pppoe_len > len) {
        return DECODE_ERROR;
    }
    len = pppoe_len;

    /* Decode protocol */
    switch(pppoe->protocol) {
        case PROTOCOL_IPV4:
            ret_val = decode_ipv4(buf, len, sp, sp_len, (bbl_ipv4_t**)&pppoe->next);
            break;
        case PROTOCOL_IPV6:
            ret_val = decode_ipv6(buf, len, sp, sp_len, (bbl_ipv6_t**)&pppoe->next);
            break;
        case PROTOCOL_LCP:
            ret_val = decode_ppp_lcp(buf, len, sp, sp_len, (bbl_lcp_t**)&pppoe->next);
            break;
        case PROTOCOL_IPCP:
            ret_val = decode_ppp_ipcp(buf, len, sp, sp_len, (bbl_ipcp_t**)&pppoe->next);
            break;
        case PROTOCOL_IP6CP:
            ret_val = decode_ppp_ip6cp(buf, len, sp, sp_len, (bbl_ip6cp_t**)&pppoe->next);
            break;
        case PROTOCOL_PAP:
            ret_val = decode_ppp_pap(buf, len, sp, sp_len, (bbl_pap_t**)&pppoe->next);
            break;
        case PROTOCOL_CHAP:
            ret_val = decode_ppp_chap(buf, len, sp, sp_len, (bbl_chap_t**)&pppoe->next);
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
protocol_error_t
decode_arp(uint8_t *buf, uint16_t len,
           uint8_t *sp, uint16_t sp_len,
           bbl_arp_t **_arp) {

    bbl_arp_t *arp;

    if(len < 28 || sp_len < sizeof(bbl_arp_t)) {
        return DECODE_ERROR;
    }

    /* Init ARP header */
    arp = (bbl_arp_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_arp_t));
    //memset(arp, 0x0, sizeof(bbl_arp_t));

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
 * decode_ethernet
 */
protocol_error_t
decode_ethernet(uint8_t *buf, uint16_t len,
                uint8_t *sp, uint16_t sp_len,
                bbl_ethernet_header_t **ethernet) {

    bbl_ethernet_header_t *eth;
    const struct ether_header *header;

    if(len < 14 || sp_len < sizeof(bbl_ethernet_header_t)) {
        return DECODE_ERROR;
    }

    /* Init ethernet header */
    eth = (bbl_ethernet_header_t*)sp; BUMP_BUFFER(sp, sp_len, sizeof(bbl_ethernet_header_t));
    memset(eth, 0x0, sizeof(bbl_ethernet_header_t));
    *ethernet = eth;

    eth->length = len;

    /* Decode ethernet header */
    header = (struct ether_header*)buf;
    BUMP_BUFFER(buf, len, sizeof(struct ether_header));

    eth->dst = (uint8_t*)header->ether_dhost;
    eth->src = (uint8_t*)header->ether_shost;
    eth->type = be16toh(header->ether_type);

    if(eth->type == ETH_TYPE_VLAN || eth->type == ETH_TYPE_QINQ) {
        if(len < 4) {
            return DECODE_ERROR;
        }
        eth->vlan_outer_priority = *buf >> 5;
        eth->vlan_outer = be16toh(*(uint16_t*)buf);
        eth->vlan_outer &= ETH_VLAN_ID_MAX;

        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        eth->type = be16toh(*(uint16_t*)buf);
        BUMP_BUFFER(buf, len, sizeof(uint16_t));
        if(eth->type == ETH_TYPE_VLAN || eth->type == ETH_TYPE_QINQ) {
            if(len < 4) {
                return DECODE_ERROR;
            }
            eth->vlan_inner_priority = *buf >> 5;
            eth->vlan_inner = be16toh(*(uint16_t*)buf);
            eth->vlan_inner &= ETH_VLAN_ID_MAX;
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            eth->type = be16toh(*(uint16_t*)buf);
            BUMP_BUFFER(buf, len, sizeof(uint16_t));
            if(eth->type == ETH_TYPE_VLAN || eth->type == ETH_TYPE_QINQ) {
                if(len < 4) {
                    return DECODE_ERROR;
                }
                eth->vlan_three = be16toh(*(uint16_t*)buf);
                eth->vlan_three &= ETH_VLAN_ID_MAX;
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
                eth->type = be16toh(*(uint16_t*)buf);
                BUMP_BUFFER(buf, len, sizeof(uint16_t));
            }
        }
    }

    if(eth->type == ETH_TYPE_PPPOE_SESSION) {
        return decode_pppoe_session(buf, len, sp, sp_len, (bbl_pppoe_session_t**)&eth->next);
    } else if(eth->type == ETH_TYPE_PPPOE_DISCOVERY) {
        return decode_pppoe_discovery(buf, len, sp, sp_len, (bbl_pppoe_discovery_t**)&eth->next);
    } else if(eth->type == ETH_TYPE_ARP) {
        return decode_arp(buf, len, sp, sp_len, (bbl_arp_t**)&eth->next);
    } else if(eth->type == ETH_TYPE_IPV4) {
        return decode_ipv4(buf, len, sp, sp_len, (bbl_ipv4_t**)&eth->next);
    } else if(eth->type == ETH_TYPE_IPV6) {
        return decode_ipv6(buf, len, sp, sp_len, (bbl_ipv6_t**)&eth->next);
    }

    return UNKNOWN_PROTOCOL;
}