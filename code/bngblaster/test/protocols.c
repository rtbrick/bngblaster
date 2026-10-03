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

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_protocols_decode_pppoe_ipcp_conf_request),
        cmocka_unit_test(test_protocols_ethernet_over_mpls_cw),
        cmocka_unit_test(test_protocols_ethernet_over_mpls_no_cw),
        cmocka_unit_test(test_protocols_arp_over_mpls_all),
        cmocka_unit_test(test_protocols_bbl_flow_id),
        cmocka_unit_test(test_protocols_lcp_chap),
        cmocka_unit_test(test_protocols_dhcp_end_option),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
