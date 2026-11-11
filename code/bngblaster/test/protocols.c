/*
 * BNG Blaster (BBL) - Protocol Tests
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <netinet/udp.h>

#include <bbl_def.h>
#include <bbl_protocols.h>

#include <isis/isis_def.h>

#include "ethernet_packets.h"

static void
test_protocols_decode_pppoe_ipcp_conf_request(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    bbl_ethernet_header_s *eth;
    protocol_error_t decode_result;
    bbl_pppoe_session_s *pppoes;
    bbl_ipcp_s *ipcp;

    uint32_t ip;
    uint32_t dns1;
    uint32_t dns2;
    inet_pton(AF_INET, "10.137.0.0", &ip);
    inet_pton(AF_INET, "100.0.0.3", &dns1);
    inet_pton(AF_INET, "100.0.0.4", &dns2);

    decode_result = decode_ethernet(pppoe_ipcp_conf_request, sizeof(pppoe_ipcp_conf_request), sp, SCRATCHPAD_LEN, &eth);
    assert_int_equal(decode_result, PROTOCOL_SUCCESS);

    pppoes = (bbl_pppoe_session_s*)eth->next;
    ipcp = (bbl_ipcp_s*)pppoes->next;

    assert_int_equal(ipcp->code, PPP_CODE_CONF_REQUEST);
    assert_int_equal(ipcp->address, ip);
    assert_int_equal(ipcp->dns1, dns1);
    assert_int_equal(ipcp->dns2, dns2);

    free(sp);
}

/* Ethernet over MPLS (e.g. EVPN VPWS) with and without PW control word. */
static void
test_protocols_ethernet_over_mpls(bool control_word, uint8_t inner_dst_first_byte,
                                  uint16_t vlan, uint16_t inner_vlan, bool qinq)
{
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512];
    uint16_t len = 0;
    uint8_t outer_dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x01};
    uint8_t outer_src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x01, 0x02};
    uint8_t inner_dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x01};
    uint8_t inner_src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x02, 0x02};

    bbl_ethernet_header_s eth = {0};
    bbl_ethernet_header_s inner = {0};
    bbl_mpls_s transport = {0};
    bbl_mpls_s service = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_bbl_s bbl = {0};

    bbl_ethernet_header_s *decoded;
    bbl_ethernet_header_s *decoded_inner;
    protocol_error_t result;

    inner_dst[0] = inner_dst_first_byte;

    eth.dst = outer_dst;
    eth.src = outer_src;
    eth.vlan_outer = 10;
    eth.mpls = &transport;
    eth.type = ETH_TYPE_ETH;
    eth.next = &inner;
    eth.mpls_cw = control_word;
    transport.label = 16001;
    transport.ttl = 255;
    transport.next = &service;
    service.label = 5000;
    service.ttl = 255;

    inner.dst = inner_dst;
    inner.src = inner_src;
    inner.vlan_outer = vlan;
    inner.vlan_outer_priority = vlan ? 5 : 0;
    inner.vlan_inner = inner_vlan;
    inner.vlan_inner_priority = inner_vlan ? 3 : 0;
    inner.qinq = qinq;
    inner.type = ETH_TYPE_IPV4;
    inner.next = &ipv4;
    inet_pton(AF_INET, "192.0.2.1", &ipv4.src);
    inet_pton(AF_INET, "192.0.2.2", &ipv4.dst);
    ipv4.ttl = 64;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = 65056;
    udp.dst = 65056;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;
    bbl.direction = BBL_DIRECTION_DOWN;
    bbl.flow_id = 4711;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    /* Last byte of CW or 4th byte of inner destination MAC after
     * 16 (ethernet + VLAN) + 2 (type) + 8 (labels) */
    assert_int_equal(buf[16 + 2 + 8 + 3], control_word ? 0x00 : inner_dst[3]);
    assert_int_equal(buf[16 + 2 + 8 + 4], control_word ? inner_dst[0] : inner_dst[4]);

    result = decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded);
    assert_int_equal(result, PROTOCOL_SUCCESS);
    assert_int_equal(decoded->type, ETH_TYPE_ETH);
    assert_int_equal(decoded->vlan_outer, 10);
    assert_non_null(decoded->mpls);
    assert_int_equal(decoded->mpls->label, 16001);
    assert_non_null(decoded->mpls->next);
    assert_int_equal(((bbl_mpls_s*)decoded->mpls->next)->label, 5000);

    /* The receiver selects the control word variant if expected
     * (ambiguous) or the decoder already detected it (unambiguous). */
    if(control_word) {
        assert_true(decoded->mpls_cw || decoded->next_cw);
        decoded_inner = decoded->mpls_cw ? decoded->next : decoded->next_cw;
    } else {
        assert_false(decoded->mpls_cw);
        decoded_inner = (bbl_ethernet_header_s*)decoded->next;
    }
    assert_non_null(decoded_inner);
    assert_memory_equal(decoded_inner->dst, inner_dst, ETH_ADDR_LEN);
    assert_memory_equal(decoded_inner->src, inner_src, ETH_ADDR_LEN);
    assert_int_equal(decoded_inner->vlan_outer, vlan);
    assert_int_equal(decoded_inner->vlan_outer_priority, vlan ? 5 : 0);
    assert_int_equal(decoded_inner->vlan_inner, inner_vlan);
    assert_int_equal(decoded_inner->vlan_inner_priority, inner_vlan ? 3 : 0);
    assert_int_equal(decoded_inner->qinq, qinq);
    assert_int_equal(decoded_inner->type, ETH_TYPE_IPV4);
    assert_non_null(decoded_inner->bbl);
    assert_int_equal(decoded_inner->bbl->flow_id, 4711);
    free(sp);
}

static void
test_protocols_ethernet_over_mpls_cw(void **unused) {
    (void) unused;
    test_protocols_ethernet_over_mpls(true, 0x02, 0, 0, false);
    test_protocols_ethernet_over_mpls(true, 0x00, 0, 0, false);
    test_protocols_ethernet_over_mpls(true, 0x02, 100, 0, false);
    test_protocols_ethernet_over_mpls(true, 0x00, 100, 200, true);
}

static void
test_protocols_ethernet_over_mpls_no_cw(void **unused) {
    (void) unused;
    test_protocols_ethernet_over_mpls(false, 0x02, 0, 0, false);
    /* Destination MAC starting with zero byte (control word candidate). */
    test_protocols_ethernet_over_mpls(false, 0x00, 0, 0, false);
    test_protocols_ethernet_over_mpls(false, 0x00, 100, 0, false);
    test_protocols_ethernet_over_mpls(false, 0x02, 100, 200, true);
    test_protocols_ethernet_over_mpls(false, 0x00, 100, 200, true);
    /* Destination MAC starting with nibble 4 or 6 (IPv4/IPv6 candidate). */
    test_protocols_ethernet_over_mpls(false, 0x40, 0, 0, false);
    test_protocols_ethernet_over_mpls(false, 0x64, 0, 0, false);
    test_protocols_ethernet_over_mpls(false, 0x46, 100, 0, false);
}

/* ARP within EVPN VPWS services (vpws-arp) with and without PW control
 * word, where the receiver tries the decoded frame without control word
 * first and then the control word variant (see bbl_vpws_rx). */
static void
test_protocols_arp_over_mpls(bool control_word, uint8_t cw_flags, uint16_t code)
{
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512];
    uint16_t len = 0;
    uint8_t outer_dst[ETH_ADDR_LEN] = {0x64, 0x9d, 0x99, 0xb2, 0xb2, 0xec};
    uint8_t outer_src[ETH_ADDR_LEN] = {0x5c, 0x07, 0x58, 0xd4, 0x81, 0xff};
    uint8_t ce_mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
    uint8_t zero_mac[ETH_ADDR_LEN] = {0};

    bbl_ethernet_header_s eth = {0};
    bbl_ethernet_header_s inner = {0};
    bbl_mpls_s service = {0};
    bbl_arp_s arp = {0};

    bbl_ethernet_header_s *decoded;
    bbl_ethernet_header_s *decoded_inner;
    bbl_arp_s *decoded_arp;
    uint32_t sender_ip, target_ip;

    inet_pton(AF_INET, "192.0.2.202", &sender_ip);
    inet_pton(AF_INET, "192.0.2.201", &target_ip);

    eth.dst = outer_dst;
    eth.src = outer_src;
    eth.vlan_outer = 10;
    eth.mpls = &service;
    eth.type = ETH_TYPE_ETH;
    eth.next = &inner;
    eth.mpls_cw = control_word;
    service.label = 5000;
    service.ttl = 254;

    inner.dst = code == ARP_REQUEST ? NULL : ce_mac; /* broadcast request */
    inner.src = ce_mac;
    inner.vlan_outer = 20;
    inner.type = ETH_TYPE_ARP;
    inner.next = &arp;
    arp.code = code;
    arp.sender = ce_mac;
    arp.sender_ip = sender_ip;
    arp.target = code == ARP_REQUEST ? zero_mac : ce_mac;
    arp.target_ip = target_ip;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    if(control_word) {
        /* Control word flags (RFC 4385) after 18 (ethernet, VLAN, type) + 4 (label) */
        buf[18 + 4] = cw_flags;
    }
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    assert_int_equal(decoded->type, ETH_TYPE_ETH);
    assert_non_null(decoded->mpls);
    assert_int_equal(decoded->mpls->label, 5000);
    if(control_word && cw_flags) {
        /* Unambiguous control word with flags set. */
        assert_true(decoded->mpls_cw);
    }

    decoded_inner = (bbl_ethernet_header_s*)decoded->next;
    if(decoded_inner->type != ETH_TYPE_ARP && decoded->next_cw) {
        decoded_inner = (bbl_ethernet_header_s*)decoded->next_cw;
    }
    assert_int_equal(decoded_inner->type, ETH_TYPE_ARP);
    assert_int_equal(decoded_inner->vlan_outer, 20);
    assert_memory_equal(decoded_inner->src, ce_mac, ETH_ADDR_LEN);
    decoded_arp = (bbl_arp_s*)decoded_inner->next;
    assert_int_equal(decoded_arp->code, code);
    assert_int_equal(decoded_arp->sender_ip, sender_ip);
    assert_int_equal(decoded_arp->target_ip, target_ip);
    assert_memory_equal(decoded_arp->sender, ce_mac, ETH_ADDR_LEN);
    free(sp);
}

static void
test_protocols_arp_over_mpls_all(void **unused) {
    (void) unused;
    test_protocols_arp_over_mpls(true, 0, ARP_REQUEST);
    test_protocols_arp_over_mpls(false, 0, ARP_REQUEST);
    test_protocols_arp_over_mpls(true, 0, ARP_REPLY);
    test_protocols_arp_over_mpls(false, 0, ARP_REPLY);
    test_protocols_arp_over_mpls(true, 0x08, ARP_REQUEST);
    test_protocols_arp_over_mpls(true, 0x0f, ARP_REPLY);
}

/* Ethernet over MPLS is limited to one level, nested frames are not decoded
 * and must not cost exponential time for the control word retries. */
static void
test_protocols_ethernet_over_mpls_nested(void **unused) {
    (void) unused;
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[1024] = {0};
    uint8_t *block;
    uint16_t len = 0;
    uint8_t mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
    uint8_t outer_header[18] = {0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02,
                                0x88, 0x47, 0x00, 0x01, 0x41, 0x40};

    bbl_ethernet_header_s eth = {0};
    bbl_ethernet_header_s inner = {0};
    bbl_mpls_s service = {0};
    bbl_arp_s arp = {0};
    bbl_ethernet_header_s *decoded;
    struct timespec start, end;

    eth.dst = mac;
    eth.src = mac;
    eth.mpls = &service;
    eth.type = ETH_TYPE_ETH;
    eth.next = &inner;
    service.label = 5000;
    service.ttl = 254;
    inner.dst = mac;
    inner.src = mac;
    inner.type = ETH_TYPE_ARP;
    inner.next = &arp;
    arp.code = ARP_REPLY;
    arp.sender = mac;
    arp.target = mac;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);

    memmove(buf + sizeof(outer_header), buf, len);
    memcpy(buf, outer_header, sizeof(outer_header));
    len += sizeof(outer_header);
    assert_int_not_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);

    /* Two converging interpretations of each block, which doubled the work per block. */
    memset(buf, 0x0, sizeof(buf));
    buf[12] = 0x88; buf[13] = 0x47; buf[16] = 0x01;
    for(int i = 0; i < 30; i++) {
        block = buf + 18 + i * 22;
        block[0] = 0x01;
        block[12] = 0x88; block[13] = 0x47;
        block[16] = 0x88; block[17] = 0x47;
        block[20] = 0x01;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    assert_int_not_equal(decode_ethernet(buf, 679, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    clock_gettime(CLOCK_MONOTONIC, &end);
    assert_true(end.tv_sec - start.tv_sec < 2);
    free(sp);
}

/* The 32-bit flow-id is followed by 32 reserved bits, which must be
 * wire compatible with the former 64-bit little-endian flow-id. */
static void
test_protocols_bbl_flow_id(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[256];
    uint8_t *bbl_start;
    uint16_t len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_udp_s udp = {0};
    bbl_bbl_s bbl = {0};
    bbl_ethernet_header_s *decoded;

    eth.dst = dst;
    eth.src = src;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &ipv4;
    inet_pton(AF_INET, "192.0.2.1", &ipv4.src);
    inet_pton(AF_INET, "192.0.2.2", &ipv4.dst);
    ipv4.ttl = 64;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp;
    udp.src = 65056;
    udp.dst = 65056;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;
    bbl.direction = BBL_DIRECTION_DOWN;
    bbl.flow_id = 0x12345678;
    bbl.flow_seq = 1;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    bbl_start = buf + len - BBL_HEADER_LEN;
    assert_int_equal(le64toh(*(uint64_t*)(bbl_start+24)), 0x12345678);

    /* Former 64-bit flow-id encoding. */
    *(uint64_t*)(bbl_start+24) = htole64(0x87654321);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    assert_non_null(decoded->bbl);
    assert_int_equal(decoded->bbl->flow_id, 0x87654321);
    assert_int_equal(decoded->bbl->flow_seq, 1);
    free(sp);
}

/* LCP Conf-Request with CHAP authentication option (5 bytes). */
static void
test_protocols_lcp_chap(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[256];
    uint16_t len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};
    bbl_lcp_s lcp = {0};
    bbl_ethernet_header_s *decoded;
    bbl_lcp_s *decoded_lcp;

    eth.dst = dst;
    eth.src = src;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = 1;
    pppoe.protocol = PROTOCOL_LCP;
    pppoe.next = &lcp;
    lcp.code = PPP_CODE_CONF_REQUEST;
    lcp.identifier = 1;
    lcp.auth = PROTOCOL_CHAP;
    lcp.magic = 0x12345678;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_lcp = (bbl_lcp_s*)((bbl_pppoe_session_s*)decoded->next)->next;
    assert_int_equal(decoded_lcp->options_len, 5 + 6);
    assert_int_equal(decoded_lcp->auth, PROTOCOL_CHAP);
    assert_int_equal(decoded_lcp->alg, PROTOCOL_CHAP_ALG_MD5);
    assert_int_equal(decoded_lcp->magic, 0x12345678);
    assert_false(decoded_lcp->unknown_options);
    free(sp);
}

/* DHCP Offer with non-zero bytes after the END option. RFC 2132 3.2: END marks
 * the end of valid information, so the trailing bytes must be ignored. */
static void
test_protocols_dhcp_end_option(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512] = {0};
    uint8_t options[] = {
        0x63, 0x82, 0x53, 0x63,                         /* magic cookie */
        0x35, 0x01, 0x02,                               /* message type offer */
        0x36, 0x04, 0x0a, 0x00, 0x00, 0x01,             /* server identifier */
        0x33, 0x04, 0x00, 0x00, 0x0e, 0x10,             /* lease time 3600 */
        0xff,                                           /* end */
        0x10, 0x00, 0x00, 0x1c, 0xa8, 0x0b, 0x01, 0x01  /* trailing data */
    };
    uint16_t udp_len = UDP_HDR_LEN + sizeof(struct dhcp_header) + sizeof(options);
    uint16_t ip_len = sizeof(struct iphdr) + udp_len;
    uint32_t server;

    struct ether_header *eth_hdr = (struct ether_header*)buf;
    struct iphdr *ip_hdr = (struct iphdr*)(buf + ETH_HDR_LEN);
    struct udphdr *udp_hdr = (struct udphdr*)((uint8_t*)ip_hdr + sizeof(struct iphdr));
    struct dhcp_header *dhcp_hdr = (struct dhcp_header*)((uint8_t*)udp_hdr + UDP_HDR_LEN);

    bbl_ethernet_header_s *eth;
    bbl_ipv4_s *ipv4;
    bbl_udp_s *udp;
    bbl_dhcp_s *dhcp;

    eth_hdr->ether_type = htobe16(ETH_TYPE_IPV4);
    ip_hdr->version = 4;
    ip_hdr->ihl = sizeof(struct iphdr) / 4;
    ip_hdr->tot_len = htobe16(ip_len);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = PROTOCOL_IPV4_UDP;
    udp_hdr->source = htobe16(DHCP_UDP_SERVER);
    udp_hdr->dest = htobe16(DHCP_UDP_CLIENT);
    udp_hdr->len = htobe16(udp_len);
    dhcp_hdr->op = BOOTREPLY;
    memcpy((uint8_t*)dhcp_hdr + sizeof(struct dhcp_header), options, sizeof(options));
    inet_pton(AF_INET, "10.0.0.1", &server);

    assert_int_equal(decode_ethernet(buf, ETH_HDR_LEN + ip_len, sp, SCRATCHPAD_LEN, &eth), PROTOCOL_SUCCESS);
    ipv4 = (bbl_ipv4_s*)eth->next;
    udp = (bbl_udp_s*)ipv4->next;
    dhcp = (bbl_dhcp_s*)udp->next;
    assert_int_equal(dhcp->type, DHCP_MESSAGE_OFFER);
    assert_int_equal(dhcp->server_identifier, server);
    assert_int_equal(dhcp->lease_time, 3600);
    free(sp);
}

static void
test_protocols_dhcp_agent_option_repeated(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512] = {0};
    uint8_t options[] = {
        0x63, 0x82, 0x53, 0x63,                         /* magic cookie */
        0x35, 0x01, 0x01,                               /* message type discover */
        0x52, 0x07, 0x01, 0x05, 'a', 'c', 'i', '-', '1',/* relay agent information */
        0x52, 0x1b, 0x01, 0x14,                         /* relay agent information */
        'c', 'i', 'r', 'c', 'u', 'i', 't', '-', 'i', 'd',
        '-', '0', '0', '0', '0', '0', '0', '0', '0', '2',
        0x02, 0x03, 'a', 'r', 'i',
        0xff                                            /* end */
    };
    uint16_t udp_len = UDP_HDR_LEN + sizeof(struct dhcp_header) + sizeof(options);
    uint16_t ip_len = sizeof(struct iphdr) + udp_len;

    struct ether_header *eth_hdr = (struct ether_header*)buf;
    struct iphdr *ip_hdr = (struct iphdr*)(buf + ETH_HDR_LEN);
    struct udphdr *udp_hdr = (struct udphdr*)((uint8_t*)ip_hdr + sizeof(struct iphdr));
    struct dhcp_header *dhcp_hdr = (struct dhcp_header*)((uint8_t*)udp_hdr + UDP_HDR_LEN);

    bbl_ethernet_header_s *eth;
    bbl_ipv4_s *ipv4;
    bbl_udp_s *udp;
    bbl_dhcp_s *dhcp;

    eth_hdr->ether_type = htobe16(ETH_TYPE_IPV4);
    ip_hdr->version = 4;
    ip_hdr->ihl = sizeof(struct iphdr) / 4;
    ip_hdr->tot_len = htobe16(ip_len);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = PROTOCOL_IPV4_UDP;
    udp_hdr->source = htobe16(DHCP_UDP_CLIENT);
    udp_hdr->dest = htobe16(DHCP_UDP_SERVER);
    udp_hdr->len = htobe16(udp_len);
    dhcp_hdr->op = BOOTREQUEST;
    memcpy((uint8_t*)dhcp_hdr + sizeof(struct dhcp_header), options, sizeof(options));

    assert_int_equal(decode_ethernet(buf, ETH_HDR_LEN + ip_len, sp, SCRATCHPAD_LEN, &eth), PROTOCOL_SUCCESS);
    ipv4 = (bbl_ipv4_s*)eth->next;
    udp = (bbl_udp_s*)ipv4->next;
    dhcp = (bbl_dhcp_s*)udp->next;
    assert_int_equal(dhcp->type, DHCP_MESSAGE_DISCOVER);
    assert_non_null(dhcp->access_line);
    assert_string_equal(dhcp->access_line->aci, "circuit-id-000000002");
    assert_string_equal(dhcp->access_line->ari, "ari");
    free(sp);
}

static void
test_protocols_dhcpv6_timer_byte_order(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512];
    uint8_t reencoded[512];
    uint16_t len = 0;
    uint16_t reencoded_len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    ipv6addr_t src_ip = {0};
    ipv6addr_t dst_ip = {0};
    ipv6addr_t address = {0};
    ipv6_prefix prefix = {0};
    bbl_ethernet_header_s eth = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_dhcpv6_s dhcpv6 = {0};
    bbl_ethernet_header_s *decoded;
    bbl_dhcpv6_s *decoded_dhcpv6;

    inet_pton(AF_INET6, "fe80::1", src_ip);
    inet_pton(AF_INET6, "ff02::1:2", dst_ip);
    inet_pton(AF_INET6, "2001:db8::1", address);
    eth.dst = dst;
    eth.src = src;
    eth.type = ETH_TYPE_IPV6;
    eth.next = &ipv6;
    ipv6.src = src_ip;
    ipv6.dst = dst_ip;
    ipv6.protocol = IPV6_NEXT_HEADER_UDP;
    ipv6.ttl = 64;
    ipv6.next = &udp;
    udp.src = DHCPV6_UDP_CLIENT;
    udp.dst = DHCPV6_UDP_SERVER;
    udp.protocol = UDP_PROTOCOL_DHCPV6;
    udp.next = &dhcpv6;
    dhcpv6.type = DHCPV6_MESSAGE_RENEW;
    dhcpv6.ia_na_iaid = htobe32(1);
    dhcpv6.ia_na_t1 = 40;
    dhcpv6.ia_na_t2 = 64;
    dhcpv6.ia_na_preferred_lifetime = 80;
    dhcpv6.ia_na_valid_lifetime = 160;
    dhcpv6.ia_na_address = &address;
    dhcpv6.ia_pd_iaid = htobe32(2);
    dhcpv6.ia_pd_t1 = 150;
    dhcpv6.ia_pd_t2 = 240;
    dhcpv6.ia_pd_preferred_lifetime = 300;
    dhcpv6.ia_pd_valid_lifetime = 600;
    dhcpv6.ia_pd_prefix = &prefix;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_dhcpv6 = (bbl_dhcpv6_s*)((bbl_udp_s*)((bbl_ipv6_s*)decoded->next)->next)->next;
    assert_int_equal(decoded_dhcpv6->ia_na_t1, 40);
    assert_int_equal(decoded_dhcpv6->ia_na_t2, 64);
    assert_int_equal(decoded_dhcpv6->ia_na_preferred_lifetime, 80);
    assert_int_equal(decoded_dhcpv6->ia_na_valid_lifetime, 160);
    assert_int_equal(decoded_dhcpv6->ia_pd_t1, 150);
    assert_int_equal(decoded_dhcpv6->ia_pd_t2, 240);
    assert_int_equal(decoded_dhcpv6->ia_pd_preferred_lifetime, 300);
    assert_int_equal(decoded_dhcpv6->ia_pd_valid_lifetime, 600);
    assert_int_equal(decoded_dhcpv6->ia_na_option_len, 40);
    assert_int_equal(decoded_dhcpv6->ia_pd_option_len, 41);
    udp.next = decoded_dhcpv6;
    assert_int_equal(encode_ethernet(reencoded, &reencoded_len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(reencoded_len, len);
    assert_memory_equal(reencoded, buf, len);
    free(sp);
}

/* DHCPv6 options of 256 bytes or more are decoded and echoed with
 * their full length (16 bit option length). */
static void
test_protocols_dhcpv6_long_interface_id(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[1024];
    uint8_t reencoded[1024];
    uint8_t interface_id[300];
    uint16_t interface_id_len = sizeof(interface_id);
    uint16_t len = 0;
    uint16_t reencoded_len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    ipv6addr_t src_ip = {0};
    ipv6addr_t dst_ip = {0};
    bbl_ethernet_header_s eth = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_dhcpv6_s dhcpv6 = {0};
    bbl_ethernet_header_s *decoded;
    bbl_dhcpv6_s *decoded_dhcpv6;

    memset(interface_id, 0x5a, sizeof(interface_id));
    inet_pton(AF_INET6, "fe80::1", src_ip);
    inet_pton(AF_INET6, "ff02::1:2", dst_ip);
    eth.dst = dst;
    eth.src = src;
    eth.type = ETH_TYPE_IPV6;
    eth.next = &ipv6;
    ipv6.src = src_ip;
    ipv6.dst = dst_ip;
    ipv6.protocol = IPV6_NEXT_HEADER_UDP;
    ipv6.ttl = 64;
    ipv6.next = &udp;
    udp.src = DHCPV6_UDP_SERVER;
    udp.dst = DHCPV6_UDP_CLIENT;
    udp.protocol = UDP_PROTOCOL_DHCPV6;
    udp.next = &dhcpv6;
    dhcpv6.type = DHCPV6_MESSAGE_REPLY;
    dhcpv6.interface_id = interface_id;
    dhcpv6.interface_id_len = interface_id_len;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_dhcpv6 = (bbl_dhcpv6_s*)((bbl_udp_s*)((bbl_ipv6_s*)decoded->next)->next)->next;
    assert_int_equal(decoded_dhcpv6->interface_id_len, 300);
    udp.next = decoded_dhcpv6;
    assert_int_equal(encode_ethernet(reencoded, &reencoded_len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(reencoded_len, len);
    assert_memory_equal(reencoded, buf, len);
    free(sp);
}

/* Gratuitous ARP: broadcast ARP request with sender IP == target IP. */
static void
test_protocols_gratuitous_arp(void **unused) {
    (void) unused;

    uint8_t buf[512];
    uint16_t len = 0;
    uint8_t mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t broadcast[ETH_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t zero_mac[ETH_ADDR_LEN] = {0};
    uint32_t ip;
    bbl_ethernet_header_s eth = {0};
    bbl_arp_s arp = {0};

    inet_pton(AF_INET, "192.0.2.10", &ip);
    eth.src = mac;
    eth.vlan_outer = 100;
    eth.type = ETH_TYPE_ARP;
    eth.next = &arp;
    arp.code = ARP_REQUEST;
    arp.sender = mac;
    arp.sender_ip = ip;
    arp.target_ip = ip;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(len, 18 + 28);
    assert_memory_equal(buf, broadcast, ETH_ADDR_LEN);
    assert_memory_equal(buf + 6, mac, ETH_ADDR_LEN);
    assert_int_equal(be16toh(*(uint16_t*)(buf + 12)), ETH_TYPE_VLAN);
    assert_int_equal(be16toh(*(uint16_t*)(buf + 14)) & 4095, 100);
    assert_int_equal(be16toh(*(uint16_t*)(buf + 16)), ETH_TYPE_ARP);
    assert_int_equal(be16toh(*(uint16_t*)(buf + 24)), ARP_REQUEST);
    assert_memory_equal(buf + 26, mac, ETH_ADDR_LEN);
    assert_memory_equal(buf + 32, &ip, sizeof(ip));
    assert_memory_equal(buf + 36, zero_mac, ETH_ADDR_LEN);
    assert_memory_equal(buf + 42, &ip, sizeof(ip));
}

/* RFC 1071 checksum over IPv6 pseudo header and ICMPv6 message. */
static bool
test_icmpv6_checksum_valid(uint8_t *src, uint8_t *dst, uint8_t *icmp, uint16_t icmp_len)
{
    uint32_t sum = IPV6_NEXT_HEADER_ICMPV6 + icmp_len;
    uint16_t i;

    for(i = 0; i < IPV6_ADDR_LEN; i += 2) {
        sum += (src[i] << 8) | src[i+1];
        sum += (dst[i] << 8) | dst[i+1];
    }
    for(i = 0; i + 1 < icmp_len; i += 2) {
        sum += (icmp[i] << 8) | icmp[i+1];
    }
    if(icmp_len & 1) {
        sum += icmp[icmp_len-1] << 8;
    }
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum == 0xffff;
}

/* Unsolicited NA (RFC 4861 section 7.2.6) to all-nodes with only override set. */
static void
test_protocols_unsolicited_na(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512];
    uint16_t len = 0;
    uint8_t mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t all_nodes_mac[ETH_ADDR_LEN] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
    ipv6addr_t ip = {0};
    bbl_ethernet_header_s eth = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_icmpv6_s icmpv6 = {0};
    bbl_ethernet_header_s *decoded;
    bbl_ipv6_s *decoded_ipv6;
    bbl_icmpv6_s *decoded_icmpv6;

    inet_pton(AF_INET6, "2001:db8::10", ip);
    eth.dst = all_nodes_mac;
    eth.src = mac;
    eth.type = ETH_TYPE_IPV6;
    eth.next = &ipv6;
    ipv6.src = ip;
    ipv6.dst = (void*)ipv6_multicast_all_nodes;
    ipv6.protocol = IPV6_NEXT_HEADER_ICMPV6;
    ipv6.ttl = 255;
    ipv6.next = &icmpv6;
    icmpv6.type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
    icmpv6.flags = IPV6_ICMPV6_NA_FLAG_OVERRIDE;
    memcpy(icmpv6.prefix.address, ip, IPV6_ADDR_LEN);
    icmpv6.mac = mac;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(len, 14 + 40 + 32);
    assert_memory_equal(buf, all_nodes_mac, ETH_ADDR_LEN);
    assert_int_equal(buf[14+7], 255); /* hop limit */
    assert_memory_equal(buf + 14 + 8, ip, IPV6_ADDR_LEN);
    assert_memory_equal(buf + 14 + 24, ipv6_multicast_all_nodes, IPV6_ADDR_LEN);
    assert_int_equal(buf[54], IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT);
    assert_int_equal(buf[54+4], IPV6_ICMPV6_NA_FLAG_OVERRIDE); /* R=0 S=0 O=1 */
    assert_memory_equal(buf + 54 + 8, ip, IPV6_ADDR_LEN);
    assert_int_equal(buf[54+24], 2); /* target link-layer address */
    assert_int_equal(buf[54+25], 1);
    assert_memory_equal(buf + 54 + 26, mac, ETH_ADDR_LEN);

    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_ipv6 = (bbl_ipv6_s*)decoded->next;
    assert_int_equal(decoded_ipv6->protocol, IPV6_NEXT_HEADER_ICMPV6);
    decoded_icmpv6 = (bbl_icmpv6_s*)decoded_ipv6->next;
    assert_int_equal(decoded_icmpv6->type, IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT);
    assert_memory_equal(decoded_icmpv6->prefix.address, ip, IPV6_ADDR_LEN);
    assert_true(test_icmpv6_checksum_valid(buf + 14 + 8, buf + 14 + 24, buf + 54, len - 54));
    free(sp);
}

/* PPP-Max-Payload tag (RFC 4638) echoed in PADS. */
static void
test_protocols_pppoe_max_payload(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512];
    uint16_t len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_discovery_s pppoe = {0};
    bbl_ethernet_header_s *decoded;
    bbl_pppoe_discovery_s *decoded_pppoe;

    eth.dst = dst;
    eth.src = src;
    eth.vlan_outer = 100;
    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADS;
    pppoe.session_id = 1;
    pppoe.max_payload = 1570;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    assert_int_equal(decoded->type, ETH_TYPE_PPPOE_DISCOVERY);
    decoded_pppoe = (bbl_pppoe_discovery_s*)decoded->next;
    assert_int_equal(decoded_pppoe->code, PPPOE_PADS);
    assert_int_equal(decoded_pppoe->max_payload, 1570);

    pppoe.max_payload = 0;
    len = 0;
    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    assert_int_equal(((bbl_pppoe_discovery_s*)decoded->next)->max_payload, 0);
    free(sp);
}

/* The option length must not be truncated to 8 bit. */
static void
test_protocols_ppp_options_len(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512] = {0};
    uint8_t header[26] = {0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02,
                          0x88, 0x64, 0x11, 0x00, 0x00, 0x01,
                          0x01, 0x32, /* PPPoE length 306 */
                          0x00, 0x00, /* PPP protocol */
                          0x01, 0x01, 0x01, 0x30}; /* conf-request, length 304 */
    uint16_t protocols[] = {PROTOCOL_LCP, PROTOCOL_IPCP, PROTOCOL_IP6CP};
    uint16_t options_len = 0;
    uint16_t len = sizeof(header) + 300;
    bbl_ethernet_header_s *decoded;
    bbl_pppoe_session_s *pppoe;

    memcpy(buf, header, sizeof(header));
    /* Unknown options with length 40, 100 and 160. */
    buf[26] = 0x7f; buf[27] = 40;
    buf[26 + 40] = 0x7f; buf[27 + 40] = 100;
    buf[26 + 140] = 0x7f; buf[27 + 140] = 160;

    for(size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); i++) {
        *(uint16_t*)(buf + 20) = htobe16(protocols[i]);
        assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
        pppoe = (bbl_pppoe_session_s*)decoded->next;
        switch(protocols[i]) {
            case PROTOCOL_LCP:
                options_len = ((bbl_lcp_s*)pppoe->next)->options_len;
                break;
            case PROTOCOL_IPCP:
                options_len = ((bbl_ipcp_s*)pppoe->next)->options_len;
                break;
            default:
                options_len = ((bbl_ip6cp_s*)pppoe->next)->options_len;
                break;
        }
        assert_int_equal(options_len, 300);
    }
    free(sp);
}

static void
test_protocols_igmpv3_query_short(void **unused) {
    (void) unused;

    /* IGMPv3 query without space for the announced source. */
    uint16_t ip_len = sizeof(struct iphdr) + 12;
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t *buf = calloc(1, ETH_HDR_LEN + ip_len);
    uint8_t *igmp_hdr = buf + ETH_HDR_LEN + sizeof(struct iphdr);
    struct ether_header *eth_hdr = (struct ether_header*)buf;
    struct iphdr *ip_hdr = (struct iphdr*)(buf + ETH_HDR_LEN);
    bbl_ethernet_header_s *eth;
    bbl_igmp_s *igmp;

    eth_hdr->ether_type = htobe16(ETH_TYPE_IPV4);
    ip_hdr->version = 4;
    ip_hdr->ihl = sizeof(struct iphdr) / 4;
    ip_hdr->tot_len = htobe16(ip_len);
    ip_hdr->ttl = 1;
    ip_hdr->protocol = PROTOCOL_IPV4_IGMP;
    igmp_hdr[0] = IGMP_TYPE_QUERY;
    igmp_hdr[11] = 1; /* number of sources */

    assert_int_equal(decode_ethernet(buf, ETH_HDR_LEN + ip_len, sp, SCRATCHPAD_LEN, &eth), PROTOCOL_SUCCESS);
    igmp = (bbl_igmp_s*)((bbl_ipv4_s*)eth->next)->next;
    assert_int_equal(igmp->version, IGMP_VERSION_3);
    assert_int_equal(igmp->source, 0);
    free(buf);
    free(sp);
}

static void
test_protocols_lacp_invalid_tlv(void **unused) {
    (void) unused;

    /* Ethernet header (14) + subtype + version, followed by the actor TLV. */
    const uint16_t actor = 16;
    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t lacpdu[512];
    uint8_t buf[512];
    uint16_t len = 0;
    uint16_t terminator;
    uint8_t mac[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t dst[ETH_ADDR_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02};
    bbl_ethernet_header_s eth = {0};
    bbl_lacp_s lacp = {0};
    bbl_ethernet_header_s *decoded;

    eth.dst = dst;
    eth.src = mac;
    eth.type = ETH_TYPE_LACP;
    eth.next = &lacp;
    lacp.actor_system_id = mac;
    lacp.partner_system_id = mac;
    assert_int_equal(encode_ethernet(lacpdu, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(lacpdu[actor], LACP_TLV_ACTOR_INFORMATION);
    assert_int_equal(lacpdu[actor+1], 20);
    terminator = actor + 20 + 20 + 16;
    assert_int_equal(lacpdu[terminator], LACP_TLV_TERMINATOR);
    assert_int_equal(decode_ethernet(lacpdu, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);

    /* TLV with length zero must not loop forever. */
    memcpy(buf, lacpdu, len);
    buf[actor] = LACP_TLV_COLLECTOR_INFORMATION;
    buf[actor+1] = 0;
    assert_int_not_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);

    /* Terminator with non-zero length ends the TLVs. */
    memcpy(buf, lacpdu, len);
    buf[terminator+1] = 50;
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);

    /* Actor TLV is mandatory. */
    memcpy(buf, lacpdu, len);
    buf[actor] = 0x7f;
    assert_int_not_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);

    /* Ethernet header without LACP payload. */
    assert_int_not_equal(decode_ethernet(lacpdu, 14, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    free(sp);
}

/* IS-IS uses 802.3 up to 1500 byte LLC + PDU and jumbo LLC above. */
static void
test_protocols_isis_jumbo_len(uint16_t pdu_len, uint16_t type)
{
    static uint8_t pdu[11997];
    static uint8_t buf[12288];
    uint8_t sp[1024];
    uint8_t dst[ETH_ADDR_LEN] = {0x09, 0x00, 0x2b, 0x00, 0x00, 0x05};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint16_t len = 0;
    bbl_ethernet_header_s eth = {0};
    bbl_ethernet_header_s *decoded = NULL;
    bbl_isis_s isis = {0};
    bbl_isis_s *decoded_isis;

    memset(pdu, 0x0, sizeof(pdu));
    pdu[0] = ISIS_PROTOCOL_IDENTIFIER;
    pdu[1] = 27;
    pdu[4] = 20;
    pdu[pdu_len-1] = 0xaa;

    eth.dst = dst;
    eth.src = src;
    eth.type = ISIS_PROTOCOL_IDENTIFIER;
    eth.next = &isis;
    isis.type = 20;
    isis.pdu = pdu;
    isis.pdu_len = pdu_len;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(len, 2*ETH_ADDR_LEN + 2 + LLC_HDR_LEN + pdu_len);
    assert_int_equal(be16toh(*(uint16_t*)(buf+2*ETH_ADDR_LEN)), type);
    assert_int_equal(buf[14], 0xfe);
    assert_int_equal(buf[15], 0xfe);
    assert_int_equal(buf[16], 0x03);

    assert_int_equal(decode_ethernet(buf, len, sp, sizeof(sp), &decoded), PROTOCOL_SUCCESS);
    assert_int_equal(decoded->type, ISIS_PROTOCOL_IDENTIFIER);
    decoded_isis = (bbl_isis_s*)decoded->next;
    assert_int_equal(decoded_isis->pdu_len, pdu_len);
    assert_int_equal(decoded_isis->pdu[pdu_len-1], 0xaa);
}

static void
test_protocols_isis_jumbo(void **unused) {
    (void) unused;

    test_protocols_isis_jumbo_len(1492, 1492+LLC_HDR_LEN);
    test_protocols_isis_jumbo_len(1497, 1500);
    test_protocols_isis_jumbo_len(1498, ETH_TYPE_LLC_JUMBO);
    /* LLC + PDU length equals ethertype IPv4 */
    test_protocols_isis_jumbo_len(2045, ETH_TYPE_LLC_JUMBO);
    test_protocols_isis_jumbo_len(11997, ETH_TYPE_LLC_JUMBO);
}

/* A computed UDP checksum of zero must be sent as 0xffff (RFC 768). */
static void
test_protocols_udp_checksum_zero(void **unused) {
    (void) unused;

    uint8_t udp[10] = {0x12, 0x34, 0x56, 0x78, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00};
    ipv6addr_t src6 = {0xfe, 0x80, [15] = 1};
    ipv6addr_t dst6 = {0xfe, 0x80, [15] = 2};
    uint32_t src4 = htobe32(0x0a000001);
    uint32_t dst4 = htobe32(0x0a000002);
    uint32_t v;
    uint16_t c4, c6;
    int ones4 = 0, ones6 = 0;

    /* Every payload word is tried, so the sum hits all values. */
    for(v = 0; v <= 0xffff; v++) {
        *(uint16_t*)(udp + 8) = v;
        c4 = bbl_ipv4_udp_checksum(src4, dst4, udp, sizeof(udp));
        c6 = bbl_ipv6_udp_checksum(src6, dst6, udp, sizeof(udp));
        assert_int_not_equal(c4, 0);
        assert_int_not_equal(c6, 0);
        if(c4 == 0xffff) ones4++;
        if(c6 == 0xffff) ones6++;
    }
    /* A non-zero sum never folds to zero, so 0xffff is only
     * returned for the one payload with a computed zero. */
    assert_int_equal(ones4, 1);
    assert_int_equal(ones6, 1);
}

/* Server DUIDs up to 130 bytes and the Client Identifier are decoded,
 * longer DUIDs are invalid (RFC 8415 section 11.1). */
static void
test_protocols_dhcpv6_duid(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[1024];
    uint16_t len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t client_duid[20];
    uint8_t server_duid[DHCPV6_DUID_LEN_MAX + 1];
    ipv6addr_t src_ip = {0};
    ipv6addr_t dst_ip = {0};
    bbl_ethernet_header_s eth = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_udp_s udp = {0};
    bbl_dhcpv6_s dhcpv6 = {0};
    bbl_ethernet_header_s *decoded;
    bbl_dhcpv6_s *decoded_dhcpv6;

    memset(client_duid, 0x11, sizeof(client_duid));
    memset(server_duid, 0x22, sizeof(server_duid));
    inet_pton(AF_INET6, "fe80::1", src_ip);
    inet_pton(AF_INET6, "fe80::2", dst_ip);
    eth.dst = dst;
    eth.src = src;
    eth.type = ETH_TYPE_IPV6;
    eth.next = &ipv6;
    ipv6.src = src_ip;
    ipv6.dst = dst_ip;
    ipv6.protocol = IPV6_NEXT_HEADER_UDP;
    ipv6.ttl = 64;
    ipv6.next = &udp;
    udp.src = DHCPV6_UDP_SERVER;
    udp.dst = DHCPV6_UDP_CLIENT;
    udp.protocol = UDP_PROTOCOL_DHCPV6;
    udp.next = &dhcpv6;
    dhcpv6.type = DHCPV6_MESSAGE_REPLY;
    dhcpv6.xid = 0x123456;
    dhcpv6.client_duid = client_duid;
    dhcpv6.client_duid_len = sizeof(client_duid);
    dhcpv6.server_duid = server_duid;
    dhcpv6.server_duid_len = 100;

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_dhcpv6 = (bbl_dhcpv6_s*)((bbl_udp_s*)((bbl_ipv6_s*)decoded->next)->next)->next;
    assert_int_equal(decoded_dhcpv6->server_duid_len, 100);
    assert_memory_equal(decoded_dhcpv6->server_duid, server_duid, 100);
    assert_int_equal(decoded_dhcpv6->client_duid_len, sizeof(client_duid));
    assert_memory_equal(decoded_dhcpv6->client_duid, client_duid, sizeof(client_duid));

    dhcpv6.server_duid_len = DHCPV6_DUID_LEN_MAX + 1;
    len = 0;
    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), DECODE_ERROR);
    free(sp);
}

/* The Relay-Session-Id tag is decoded and encoded (RFC 2516 appendix A). */
static void
test_protocols_pppoe_relay_session_id(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    uint8_t buf[512];
    uint16_t len = 0;
    uint8_t dst[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t src[ETH_ADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t relay_session_id[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_discovery_s pppoe = {0};
    bbl_ethernet_header_s *decoded;
    bbl_pppoe_discovery_s *decoded_pppoe;

    eth.dst = dst;
    eth.src = src;
    eth.type = ETH_TYPE_PPPOE_DISCOVERY;
    eth.next = &pppoe;
    pppoe.code = PPPOE_PADR;
    pppoe.relay_session_id = relay_session_id;
    pppoe.relay_session_id_len = sizeof(relay_session_id);

    assert_int_equal(encode_ethernet(buf, &len, &eth), PROTOCOL_SUCCESS);
    assert_int_equal(decode_ethernet(buf, len, sp, SCRATCHPAD_LEN, &decoded), PROTOCOL_SUCCESS);
    decoded_pppoe = (bbl_pppoe_discovery_s*)decoded->next;
    assert_int_equal(decoded_pppoe->relay_session_id_len, sizeof(relay_session_id));
    assert_memory_equal(decoded_pppoe->relay_session_id, relay_session_id, sizeof(relay_session_id));
    free(sp);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_protocols_decode_pppoe_ipcp_conf_request),
        cmocka_unit_test(test_protocols_ethernet_over_mpls_cw),
        cmocka_unit_test(test_protocols_ethernet_over_mpls_no_cw),
        cmocka_unit_test(test_protocols_arp_over_mpls_all),
        cmocka_unit_test(test_protocols_ethernet_over_mpls_nested),
        cmocka_unit_test(test_protocols_bbl_flow_id),
        cmocka_unit_test(test_protocols_lcp_chap),
        cmocka_unit_test(test_protocols_dhcp_end_option),
        cmocka_unit_test(test_protocols_dhcp_agent_option_repeated),
        cmocka_unit_test(test_protocols_dhcpv6_timer_byte_order),
        cmocka_unit_test(test_protocols_dhcpv6_long_interface_id),
        cmocka_unit_test(test_protocols_gratuitous_arp),
        cmocka_unit_test(test_protocols_unsolicited_na),
        cmocka_unit_test(test_protocols_pppoe_max_payload),
        cmocka_unit_test(test_protocols_ppp_options_len),
        cmocka_unit_test(test_protocols_lacp_invalid_tlv),
        cmocka_unit_test(test_protocols_igmpv3_query_short),
        cmocka_unit_test(test_protocols_isis_jumbo),
        cmocka_unit_test(test_protocols_udp_checksum_zero),
        cmocka_unit_test(test_protocols_dhcpv6_duid),
        cmocka_unit_test(test_protocols_pppoe_relay_session_id),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
