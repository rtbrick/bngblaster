/*
 * LSPGEN - Unit Tests
 *
 * The topologies are generated as with the lspgen command and the
 * serialized packets, config, stream and sequence cache files are
 * verified.
 *
 * Christian Giese, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <jansson.h>

/* The test includes lspgen.c to access its static functions. */
#define main lspgen_main
#include "../src/lspgen.c"
#undef main

#define TEST_LSP_BUFFER_SIZE    1492

#define OSPF2_HDR_OFFSET        20 /* IPv4 header */
#define OSPF3_HDR_OFFSET        40 /* IPv6 header */
#define OSPF2_LSA_OFFSET        (OSPF2_HDR_OFFSET+24+4)
#define OSPF3_LSA_OFFSET        (OSPF3_HDR_OFFSET+16+4)
#define OSPF_LSA_HDR_LEN        20

static char test_dir[] = "/tmp/lspgen-test-XXXXXX";

/*
 * Test helpers
 */

static lsdb_ctx_t *
test_ctx(lsdb_proto_id_t protocol_id, uint32_t num_nodes)
{
    lsdb_ctx_t *ctx;

    ctx = lsdb_alloc_ctx("default");
    assert_non_null(ctx);
    lspgen_init_ctx(ctx);

    /* Protocol defaults like set by argument -P. */
    ctx->protocol_id = protocol_id;
    if (protocol_id == PROTO_OSPF2) {
        ctx->no_ipv6 = true;
    }
    if (protocol_id == PROTO_OSPF3) {
        ctx->no_ipv4 = true;
    }
    if (protocol_id == PROTO_OSPF2 || protocol_id == PROTO_OSPF3) {
        ctx->topology_id.area = 0;
        ctx->sequence = 0x80000001;
        ctx->lsp_lifetime = 3600;
    }
    ctx->num_nodes = num_nodes;
    lspgen_compute_srgb_range(ctx);
    return ctx;
}

static void
test_gen_attr(lsdb_ctx_t *ctx)
{
    lspgen_check_srgb_range(ctx);
    lsdb_init_graph(ctx);
    switch (ctx->protocol_id) {
        case PROTO_ISIS:
            lspgen_gen_isis_attr(ctx);
            break;
        case PROTO_OSPF2:
            lspgen_gen_ospf2_attr(ctx);
            break;
        case PROTO_OSPF3:
            lspgen_gen_ospf3_attr(ctx);
            break;
        default:
            fail();
    }
}

static void
test_generate(lsdb_ctx_t *ctx)
{
    test_gen_attr(ctx);
    lspgen_gen_packet(ctx);
}

static lsdb_ctx_t *
test_read_config(const char *filename)
{
    lsdb_ctx_t *ctx;

    ctx = lsdb_alloc_ctx("default");
    assert_non_null(ctx);
    lspgen_init_ctx(ctx);
    ctx->config_filename = strdup(filename);
    ctx->config_read = true;
    lspgen_read_config(ctx);
    lspgen_gen_packet(ctx);
    return ctx;
}

static void
test_write_file(const char *filename, const char *content)
{
    FILE *file;

    file = fopen(filename, "w");
    assert_non_null(file);
    assert_int_equal(fputs(content, file) >= 0, true);
    assert_int_equal(fclose(file), 0);
}

static long
test_file_size(const char *filename)
{
    struct stat st;

    if (stat(filename, &st) != 0) {
        return -1;
    }
    return st.st_size;
}

typedef void (*test_packet_cb)(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet, void *arg);

static uint32_t
test_foreach_packet(lsdb_ctx_t *ctx, test_packet_cb cb, void *arg)
{
    dict_itor *node_itor, *packet_itor;
    lsdb_node_t *node;
    uint32_t packets = 0;

    node_itor = dict_itor_new(ctx->node_dict);
    assert_non_null(node_itor);
    if (dict_itor_first(node_itor)) {
        do {
            node = *dict_itor_datum(node_itor);
            if (!node->packet_dict) {
                continue;
            }
            packet_itor = dict_itor_new(node->packet_dict);
            assert_non_null(packet_itor);
            if (dict_itor_first(packet_itor)) {
                do {
                    cb(ctx, node, *dict_itor_datum(packet_itor), arg);
                    packets++;
                } while (dict_itor_next(packet_itor));
            }
            dict_itor_free(packet_itor);
        } while (dict_itor_next(node_itor));
    }
    dict_itor_free(node_itor);
    return packets;
}

static lsdb_node_t *
test_get_node(lsdb_ctx_t *ctx, const char *node_id)
{
    lsdb_node_t node_template;

    memset(&node_template, 0, sizeof(node_template));
    lsdb_scan_node_id(node_template.key.node_id, (char *)node_id);
    return lsdb_get_node(ctx, &node_template);
}

/* Ones complement sum in network byte order. */
static uint16_t
test_ones_sum(const uint8_t *buf, uint32_t len, uint32_t sum)
{
    uint32_t idx;

    for (idx = 0; idx + 1 < len; idx += 2) {
        sum += (buf[idx] << 8) | buf[idx+1];
    }
    if (len & 1) {
        sum += buf[len-1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum;
}

typedef void (*test_lsa_cb)(lsdb_packet_t *packet, uint16_t lsa_type, uint8_t *lsa, uint16_t lsa_len, void *arg);

/*
 * Walk all LSAs of an OSPF LS update packet. The OSPFv2 LSA type
 * is returned with the opaque type in the upper byte (e.g. 0x070a).
 */
static void
test_foreach_lsa(lsdb_ctx_t *ctx, lsdb_packet_t *packet, test_lsa_cb cb, void *arg)
{
    uint8_t *lsa;
    uint32_t idx, num_lsa, lsa_idx;
    uint16_t lsa_type, lsa_len;

    if (ctx->protocol_id == PROTO_OSPF2) {
        num_lsa = read_be_uint(packet->data+OSPF2_LSA_OFFSET-4, 4);
        idx = OSPF2_LSA_OFFSET;
    } else {
        num_lsa = read_be_uint(packet->data+OSPF3_LSA_OFFSET-4, 4);
        idx = OSPF3_LSA_OFFSET;
    }
    for (lsa_idx = 0; lsa_idx < num_lsa; lsa_idx++) {
        assert_true(idx + OSPF_LSA_HDR_LEN <= packet->buf[0].idx);
        lsa = packet->data+idx;
        lsa_len = read_be_uint(lsa+18, 2);
        assert_true(lsa_len >= OSPF_LSA_HDR_LEN);
        assert_true(idx + lsa_len <= packet->buf[0].idx);
        if (ctx->protocol_id == PROTO_OSPF2) {
            lsa_type = lsa[3] | (lsa[4] << 8);
        } else {
            lsa_type = read_be_uint(lsa+2, 2);
        }
        cb(packet, lsa_type, lsa, lsa_len, arg);
        idx += lsa_len;
    }
}

typedef struct test_tlv_ {
    uint16_t lsa_type;
    uint16_t body_offset; /* TLVs start after the LSA header + offset */
    uint16_t tlv_type;
    uint32_t count;
    uint16_t length;
    uint8_t value[64];
} test_tlv_t;

static void
test_find_tlv_cb(lsdb_packet_t *packet, uint16_t lsa_type, uint8_t *lsa, uint16_t lsa_len, void *arg)
{
    test_tlv_t *tlv = arg;
    uint16_t idx, type, len;

    UNUSED(packet);
    if (lsa_type != tlv->lsa_type) {
        return;
    }
    idx = OSPF_LSA_HDR_LEN + tlv->body_offset;
    while (idx + 4 <= lsa_len) {
        type = read_be_uint(lsa+idx, 2);
        len = read_be_uint(lsa+idx+2, 2);
        assert_true(idx + 4 + len <= lsa_len);
        if (type == tlv->tlv_type) {
            if (!tlv->count) {
                tlv->length = len;
                memcpy(tlv->value, lsa+idx+4, len < sizeof(tlv->value) ? len : sizeof(tlv->value));
            }
            tlv->count++;
        }
        idx += 4 + ((len + 3) & ~3);
    }
}

typedef struct test_find_ {
    test_tlv_t *tlv;
} test_find_t;

static void
test_find_tlv_packet_cb(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet, void *arg)
{
    UNUSED(node);
    test_foreach_lsa(ctx, packet, test_find_tlv_cb, arg);
}

/* Find the first TLV of a node, the count includes all TLVs of this type. */
static void
test_node_tlv(lsdb_ctx_t *ctx, lsdb_node_t *node, test_tlv_t *tlv)
{
    dict_itor *itor;

    tlv->count = 0;
    itor = dict_itor_new(node->packet_dict);
    assert_non_null(itor);
    assert_true(dict_itor_first(itor));
    do {
        test_find_tlv_packet_cb(ctx, node, *dict_itor_datum(itor), tlv);
    } while (dict_itor_next(itor));
    dict_itor_free(itor);
}

/*
 * Tests
 */

static void
test_scan_node_id(void **unused)
{
    uint8_t node_id[LSDB_MAX_NODE_ID_SIZE];
    uint8_t isis[] = { 0x19, 0x21, 0x68, 0x00, 0x10, 0x01, 0x00, 0x00 };
    uint8_t ipv4[] = { 10, 0, 0, 1, 0, 0, 0, 0 };
    uint8_t odd[] = { 0x12, 0x30, 0, 0, 0, 0, 0, 0 };
    UNUSED(unused);

    memset(node_id, 0xff, sizeof(node_id));
    memset(node_id, 0, sizeof(node_id));
    lsdb_scan_node_id(node_id, "1921.6800.1001.00");
    assert_memory_equal(node_id, isis, sizeof(isis));

    memset(node_id, 0, sizeof(node_id));
    lsdb_scan_node_id(node_id, "1921.6800.1001");
    assert_memory_equal(node_id, isis, sizeof(isis));

    /* Upper case and lower case hex digits. */
    memset(node_id, 0, sizeof(node_id));
    lsdb_scan_node_id(node_id, "ABCD.ef01.0000.00");
    assert_int_equal(node_id[0], 0xab);
    assert_int_equal(node_id[1], 0xcd);
    assert_int_equal(node_id[2], 0xef);
    assert_int_equal(node_id[3], 0x01);

    memset(node_id, 0, sizeof(node_id));
    lsdb_scan_node_id(node_id, "10.0.0.1");
    assert_memory_equal(node_id, ipv4, sizeof(ipv4));

    /* An odd number of digits must not leave the previous digit in the last byte. */
    memset(node_id, 0, sizeof(node_id));
    lsdb_scan_node_id(node_id, "123");
    assert_memory_equal(node_id, odd, sizeof(odd));
}

static void
test_store_bcd_addr(void **unused)
{
    uint8_t node_id[LSDB_MAX_NODE_ID_SIZE];
    uint8_t expected[] = { 0x19, 0x21, 0x68, 0x00, 0x20, 0x55 };
    __uint128_t addr;
    UNUSED(unused);

    /* 192.168.2.55 -> 192 168 002 055 -> 1921.6800.2055 */
    addr = (192U << 24) | (168U << 16) | (2U << 8) | 55U;
    memset(node_id, 0, sizeof(node_id));
    lspgen_store_bcd_addr(addr, node_id, 4);
    assert_memory_equal(node_id, expected, sizeof(expected));
    assert_int_equal(node_id[6], 0);
}

static void
test_isis_connector(void **unused)
{
    lsdb_ctx_t *ctx;
    char arg[64];
    uint8_t upper[] = { 0x19, 0x21, 0x68, 0x00, 0x00, 0xab, 0x00 };
    uint8_t high[] = { 0x89, 0x21, 0x68, 0x00, 0x10, 0x01, 0x01 };
    UNUSED(unused);

    ctx = test_ctx(PROTO_ISIS, 10);

    snprintf(arg, sizeof(arg), "1921.6800.00AB");
    lspgen_add_connector(ctx, arg);
    assert_int_equal(ctx->num_connector, 1);
    assert_memory_equal(ctx->connector[0].remote_node_id, upper, sizeof(upper));

    /* The most significant digit above 7 must not saturate. */
    snprintf(arg, sizeof(arg), "8921.6800.1001.0102");
    lspgen_add_connector(ctx, arg);
    assert_int_equal(ctx->num_connector, 2);
    assert_memory_equal(ctx->connector[1].remote_node_id, high, sizeof(high));

    /* Without any hex digit, the connector is rejected. */
    snprintf(arg, sizeof(arg), "xyz");
    lspgen_add_connector(ctx, arg);
    assert_int_equal(ctx->num_connector, 2);

    lsdb_delete_ctx(ctx);
}

static void
test_ospf_connector(void **unused)
{
    lsdb_ctx_t *ctx;
    char arg[64];
    uint8_t remote[] = { 10, 0, 0, 11 };
    uint8_t local[] = { 10, 0, 0, 2 };
    UNUSED(unused);

    ctx = test_ctx(PROTO_OSPF2, 10);

    snprintf(arg, sizeof(arg), "10.0.0.11:10.0.0.2");
    lspgen_add_connector(ctx, arg);
    assert_int_equal(ctx->num_connector, 1);
    assert_memory_equal(ctx->connector[0].remote_node_id, remote, sizeof(remote));
    assert_memory_equal(ctx->connector[0].local_link_id, local, sizeof(local));

    snprintf(arg, sizeof(arg), "1.1.1.1:foo");
    lspgen_add_connector(ctx, arg);
    snprintf(arg, sizeof(arg), "foo:1.1.1.1");
    lspgen_add_connector(ctx, arg);
    snprintf(arg, sizeof(arg), "1.1.1.1");
    lspgen_add_connector(ctx, arg);
    assert_int_equal(ctx->num_connector, 1);

    lsdb_delete_ctx(ctx);
}

static void
test_isis_lsp_cb(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet, void *arg)
{
    uint32_t *max_len = arg;
    UNUSED(ctx);
    UNUSED(node);

    assert_int_equal(read_be_uint(packet->data+8, 2), packet->buf[0].idx);
    assert_int_equal(validate_fletcher_checksum(packet->data+12, packet->buf[0].idx-12), 0);
    if (packet->buf[0].idx > *max_len) {
        *max_len = packet->buf[0].idx;
    }
}

static void
test_isis_lsp_size(void **unused)
{
    lsdb_ctx_t *ctx;
    uint32_t max_len, packets;
    UNUSED(unused);

    /* Many fragments with MD5 authentication. */
    ctx = test_ctx(PROTO_ISIS, 10);
    ctx->num_ext = 20000;
    ctx->authentication_key = strdup("secret");
    ctx->authentication_type = ISIS_AUTH_MD5;
    test_generate(ctx);

    max_len = 0;
    packets = test_foreach_packet(ctx, test_isis_lsp_cb, &max_len);
    assert_true(packets > 100);
    assert_true(max_len <= TEST_LSP_BUFFER_SIZE);
    lsdb_delete_ctx(ctx);

    /* Large attributes with Flex-Algo and simple authentication. */
    ctx = test_ctx(PROTO_ISIS, 50);
    ctx->num_ext = 5000;
    ctx->link_multiplier = 4;
    assert_true(lspgen_parse_sr_algo(ctx, "0,1,128"));
    ctx->authentication_key = strdup("simple-authentication-key");
    ctx->authentication_type = ISIS_AUTH_SIMPLE;
    test_generate(ctx);

    max_len = 0;
    test_foreach_packet(ctx, test_isis_lsp_cb, &max_len);
    assert_true(max_len <= TEST_LSP_BUFFER_SIZE);
    lsdb_delete_ctx(ctx);
}

static void
test_ospf_header_cb(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet, void *arg)
{
    uint8_t *area = arg;
    uint8_t *hdr, pseudo[40];
    uint32_t len;
    UNUSED(node);

    if (ctx->protocol_id == PROTO_OSPF2) {
        hdr = packet->data+OSPF2_HDR_OFFSET;
        len = packet->buf[0].idx-OSPF2_HDR_OFFSET;
        assert_int_equal(read_be_uint(hdr+2, 2), len);
        assert_memory_equal(hdr+8, area, 4);
        assert_int_equal(test_ones_sum(packet->data, OSPF2_HDR_OFFSET, 0), 0xffff);
        assert_int_equal(test_ones_sum(hdr, len, 0), 0xffff);
    } else {
        hdr = packet->data+OSPF3_HDR_OFFSET;
        len = packet->buf[0].idx-OSPF3_HDR_OFFSET;
        assert_int_equal(read_be_uint(hdr+2, 2), len);
        assert_memory_equal(hdr+8, area, 4);
        /* Pseudo header of source, destination, length and next header. */
        memcpy(pseudo, packet->data+8, 32);
        write_be_uint(pseudo+32, 4, len);
        write_be_uint(pseudo+36, 4, 89);
        assert_int_equal(test_ones_sum(hdr, len, test_ones_sum(pseudo, sizeof(pseudo), 0)), 0xffff);
    }
}

static void
test_ospf_header(void **unused)
{
    lsdb_ctx_t *ctx;
    uint8_t area[] = { 192, 168, 1, 1 };
    lsdb_proto_id_t protocols[] = { PROTO_OSPF2, PROTO_OSPF3 };
    size_t idx;
    UNUSED(unused);

    for (idx = 0; idx < sizeof(protocols)/sizeof(protocols[0]); idx++) {
        ctx = test_ctx(protocols[idx], 20);
        ctx->num_ext = 10;
        memcpy(&ctx->topology_id.area, area, sizeof(area));
        test_generate(ctx);
        assert_int_equal(test_foreach_packet(ctx, test_ospf_header_cb, area), 20);
        lsdb_delete_ctx(ctx);
    }
}

static void
test_ospf_sr(void **unused)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t *node;
    test_tlv_t tlv;
    UNUSED(unused);

    /* OSPFv2 Router Information LSA (opaque type 4) and Extended Prefix LSA (opaque type 7). */
    ctx = test_ctx(PROTO_OSPF2, 10);
    test_generate(ctx);
    node = test_get_node(ctx, "192.168.0.3");
    assert_non_null(node);

    memset(&tlv, 0, sizeof(tlv));
    tlv.lsa_type = 0x040a;
    tlv.tlv_type = 9; /* SID/Label Range */
    test_node_tlv(ctx, node, &tlv);
    assert_int_equal(tlv.count, 1);
    assert_int_equal(tlv.length, 11);

    memset(&tlv, 0, sizeof(tlv));
    tlv.lsa_type = 0x070a;
    tlv.tlv_type = 1; /* Extended Prefix */
    test_node_tlv(ctx, node, &tlv);
    assert_int_equal(tlv.count, 1);
    assert_int_equal(tlv.value[1], 32); /* prefix length */
    assert_int_equal(tlv.value[3], OSPF_EXT_PREFIX_FLAG_N);
    lsdb_delete_ctx(ctx);

    /* OSPFv3 Router Information LSA and E-Intra-Area-Prefix LSA */
    ctx = test_ctx(PROTO_OSPF3, 10);
    test_generate(ctx);
    node = test_get_node(ctx, "192.168.0.3");
    assert_non_null(node);

    memset(&tlv, 0, sizeof(tlv));
    tlv.lsa_type = 0xa00c;
    tlv.tlv_type = 9; /* SID/Label Range */
    test_node_tlv(ctx, node, &tlv);
    assert_int_equal(tlv.count, 1);
    assert_int_equal(tlv.length, 11);

    memset(&tlv, 0, sizeof(tlv));
    tlv.lsa_type = 0xa029;
    tlv.body_offset = 12; /* referenced LSA */
    tlv.tlv_type = 6; /* Intra-Area-Prefix */
    test_node_tlv(ctx, node, &tlv);
    assert_int_equal(tlv.count, 1);
    assert_int_equal(tlv.value[4], 128); /* prefix length */
    assert_int_equal(tlv.value[5], OSPF3_PREFIX_OPTION_N);
    lsdb_delete_ctx(ctx);
}

static void
test_ospf_external_cb(lsdb_packet_t *packet, uint16_t lsa_type, uint8_t *lsa, uint16_t lsa_len, void *arg)
{
    uint32_t *externals = arg;
    UNUSED(packet);

    if (lsa_type == 5) {
        assert_true(lsa_len >= 24);
        assert_int_equal(read_be_uint(lsa+4, 4), 0); /* 0.0.0.0 */
        assert_int_equal(read_be_uint(lsa+20, 4), 0); /* network mask of /0 */
        (*externals)++;
    }
}

static void
test_ospf_external_packet_cb(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet, void *arg)
{
    UNUSED(node);
    test_foreach_lsa(ctx, packet, test_ospf_external_cb, arg);
}

static void
test_ipv4_default_route(void **unused)
{
    lsdb_ctx_t *ctx;
    uint32_t externals = 0;
    UNUSED(unused);

    ctx = test_ctx(PROTO_OSPF2, 5);
    ctx->num_ext = 1;
    assert_true(scan_ipv4_prefix("0.0.0.0/0", &ctx->ipv4_ext_prefix));
    test_generate(ctx);
    test_foreach_packet(ctx, test_ospf_external_packet_cb, &externals);
    assert_int_equal(externals, 1);
    lsdb_delete_ctx(ctx);
}

static uint32_t
test_node_number(lsdb_node_t *node)
{
    assert_non_null(node->node_name);
    assert_memory_equal(node->node_name, "node", 4);
    return strtoul(node->node_name+4, NULL, 10);
}

static void
test_subgraph_links(void **unused)
{
    lsdb_ctx_t *ctx;
    lsdb_link_t *link;
    lsdb_node_t *remote;
    dict_itor *itor;
    uint32_t local_number, remote_number, crossing = 0;
    UNUSED(unused);

    /* 1500 nodes are generated as two subgraphs of 750 nodes. */
    ctx = test_ctx(PROTO_ISIS, 1500);
    lsdb_init_graph(ctx);
    assert_int_equal(ctx->nodecount, 1500);

    itor = dict_itor_new(ctx->link_dict);
    assert_non_null(itor);
    assert_true(dict_itor_first(itor));
    do {
        link = *dict_itor_datum(itor);
        remote = test_get_node(ctx, lsdb_format_node_id(link->key.remote_node_id));
        assert_non_null(remote);
        local_number = test_node_number(link->node);
        remote_number = test_node_number(remote);
        if ((local_number <= 750) != (remote_number <= 750)) {
            assert_int_equal(link->link_metric, 99);
            crossing++;
        }
    } while (dict_itor_next(itor));
    dict_itor_free(itor);

    /* Two links between the subgraphs in both directions. */
    assert_int_equal(crossing, 4);
    lsdb_delete_ctx(ctx);
}

/*
 * Compare the packets of all nodes of two contexts.
 */
static void
test_compare_cb(lsdb_ctx_t *ctx, lsdb_node_t *node, lsdb_packet_t *packet, void *arg)
{
    lsdb_ctx_t *other_ctx = arg;
    lsdb_node_t *other_node;
    lsdb_packet_t packet_template;
    void **p;
    UNUSED(ctx);

    other_node = lsdb_get_node(other_ctx, node);
    assert_non_null(other_node);
    assert_non_null(other_node->packet_dict);
    packet_template.key.id = packet->key.id;
    p = dict_search(other_node->packet_dict, &packet_template.key);
    assert_non_null(p);
    assert_int_equal(((lsdb_packet_t *)*p)->buf[0].idx, packet->buf[0].idx);
    assert_memory_equal(((lsdb_packet_t *)*p)->data, packet->data, packet->buf[0].idx);
}

static void
test_config_round_trip(void **unused)
{
    lsdb_ctx_t *ctx, *read_ctx;
    char connector[3][32] = { "1921.6800.1001", "10.0.0.11:10.0.0.2", "10.0.0.11:0.0.0.1" };
    lsdb_proto_id_t protocols[] = { PROTO_ISIS, PROTO_OSPF2, PROTO_OSPF3 };
    uint8_t area[] = { 192, 168, 100, 200 }; /* longest area key */
    uint32_t packets;
    size_t idx;
    UNUSED(unused);

    for (idx = 0; idx < sizeof(protocols)/sizeof(protocols[0]); idx++) {
        ctx = test_ctx(protocols[idx], 20);
        ctx->num_ext = 10;
        ctx->link_multiplier = 2;
        if (protocols[idx] != PROTO_ISIS) {
            memcpy(&ctx->topology_id.area, area, sizeof(area));
        }
        lspgen_add_connector(ctx, connector[idx]);
        assert_int_equal(ctx->num_connector, 1);
        test_generate(ctx);
        ctx->config_filename = strdup("round-trip.json");
        lspgen_write_config(ctx);

        read_ctx = test_read_config("round-trip.json");
        assert_int_equal(read_ctx->protocol_id, protocols[idx]);
        assert_int_equal(read_ctx->topology_id.area, ctx->topology_id.area);
        assert_int_equal(read_ctx->nodecount, ctx->nodecount);
        assert_memory_equal(read_ctx->root_node_id, ctx->root_node_id, sizeof(ctx->root_node_id));

        packets = test_foreach_packet(ctx, test_compare_cb, read_ctx);
        assert_true(packets >= 20);
        assert_int_equal(test_foreach_packet(read_ctx, test_compare_cb, ctx), packets);

        lsdb_delete_ctx(read_ctx);
        lsdb_delete_ctx(ctx);
        unlink("round-trip.json");
    }
}

static void
test_ospf_prefix_sid_config(void **unused)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t *node;
    test_tlv_t tlv;
    UNUSED(unused);

    /* Two loopbacks with prefix SID on the same node. */
    test_write_file("prefix-sid.json",
        "{\"instance\": \"default\", \"protocol\": \"ospf2\", \"area0.0.0.0\": [\n"
        " {\"node_id\": \"10.0.0.1\", \"hostname\": \"R1\",\n"
        "  \"capability_list\": [{\"router_id\": \"10.0.0.1\", \"srgb_base\": 10000, \"srgb_range\": 100}],\n"
        "  \"ipv4_prefix_list\": [\n"
        "   {\"ipv4_prefix\": \"10.0.0.1/32\", \"metric\": 0, \"segment_id\": 1, \"node_flag\": true},\n"
        "   {\"ipv4_prefix\": \"10.0.0.101/32\", \"metric\": 0, \"segment_id\": 101, \"node_flag\": true}],\n"
        "  \"neighbor_list\": [{\"remote_node_id\": \"10.0.0.2\", \"local_link_id\": \"172.16.0.1\", \"metric\": 10}]}]}\n");

    ctx = test_read_config("prefix-sid.json");
    node = test_get_node(ctx, "10.0.0.1");
    assert_non_null(node);

    /* Each prefix has its own Extended Prefix TLV. */
    memset(&tlv, 0, sizeof(tlv));
    tlv.lsa_type = 0x070a;
    tlv.tlv_type = 1;
    test_node_tlv(ctx, node, &tlv);
    assert_int_equal(tlv.count, 2);
    assert_int_equal(tlv.length, 20);

    lsdb_delete_ctx(ctx);
    unlink("prefix-sid.json");
}

static void
test_stream_file(void **unused)
{
    lsdb_ctx_t *ctx;
    json_t *root, *destinations, *destination;
    json_error_t error;
    lsdb_proto_id_t protocols[] = { PROTO_ISIS, PROTO_OSPF2, PROTO_OSPF3 };
    const char *loopbacks[] = { "192.168.0.4", "192.168.0.4", "fc00::c0a8:4" };
    const char *address;
    bool found;
    size_t idx, dst_idx;
    UNUSED(unused);

    for (idx = 0; idx < sizeof(protocols)/sizeof(protocols[0]); idx++) {
        ctx = test_ctx(protocols[idx], 5);
        ctx->num_ext = 2;
        test_generate(ctx);
        ctx->stream_filename = strdup("stream.json");
        lspgen_dump_stream(ctx);

        root = json_load_file("stream.json", 0, &error);
        assert_non_null(root);
        destinations = json_object_get(root, "destinations");
        assert_true(json_is_array(destinations));
        /* 5 loopbacks, 2 prefixes per link and 2 externals per address family. */
        assert_int_equal(json_array_size(destinations), protocols[idx] == PROTO_ISIS ? 2 * (5 + 20 + 2) : 5 + 20 + 2);
        found = false;
        json_array_foreach(destinations, dst_idx, destination) {
            address = json_string_value(json_object_get(destination, protocols[idx] == PROTO_OSPF3 ?
                                        "destination-ipv6-address" : "destination-ipv4-address"));
            if (address && strcmp(address, loopbacks[idx]) == 0) {
                found = true;
            }
        }
        assert_true(found);
        json_decref(root);
        lsdb_delete_ctx(ctx);
        unlink("stream.json");
    }
}

static void
test_no_attributes(void **unused)
{
    lsdb_ctx_t *ctx;
    UNUSED(unused);

    /* OSPFv3 without IPv6 has no attributes, which must not crash
     * or generate empty packets. */
    ctx = test_ctx(PROTO_OSPF3, 5);
    ctx->no_ipv6 = true;
    test_generate(ctx);
    ctx->config_filename = strdup("no-attributes.json");
    lspgen_write_config(ctx);
    ctx->stream_filename = strdup("no-attributes-stream.json");
    lspgen_dump_stream(ctx);
    ctx->pcap_filename = strdup("no-attributes.pcap");
    lspgen_dump_pcap(ctx);
    assert_int_equal(ctx->ctrl_stats.packets_queued, 0);
    lsdb_delete_ctx(ctx);
    unlink("no-attributes.json");
    unlink("no-attributes-stream.json");
    unlink("no-attributes.pcap");
}

static void
test_seq_cache(void **unused)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t *node;
    long size;
    UNUSED(unused);

    ctx = test_ctx(PROTO_ISIS, 5);
    test_generate(ctx);
    lspgen_write_seq_cache(ctx);
    lsdb_delete_ctx(ctx);
    size = test_file_size("isis-level1-sequence-cache.json");
    assert_true(size > 0);

    /* The sequence numbers are incremented by the next run. */
    ctx = test_ctx(PROTO_ISIS, 5);
    test_gen_attr(ctx);
    lspgen_read_seq_cache(ctx);
    node = test_get_node(ctx, "1921.6800.0000.00");
    assert_non_null(node);
    assert_int_equal(node->sequence, 2);
    lsdb_delete_ctx(ctx);

    /* An empty LSDB must not overwrite the sequence cache. */
    ctx = test_ctx(PROTO_ISIS, 5);
    lspgen_write_seq_cache(ctx);
    lsdb_delete_ctx(ctx);
    assert_int_equal(test_file_size("isis-level1-sequence-cache.json"), size);

    unlink("isis-level1-sequence-cache.json");
}

static void
test_bump_sequence(void **unused)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t node;
    UNUSED(unused);

    ctx = test_ctx(PROTO_ISIS, 5);
    memset(&node, 0, sizeof(node));
    node.ctx = ctx;
    node.sequence = 1;
    lsdb_bump_sequence(&node);
    assert_int_equal(node.sequence, 2);
    node.sequence = UINT32_MAX;
    lsdb_bump_sequence(&node);
    assert_int_equal(node.sequence, UINT32_MAX);

    /* OSPF sequence numbers are signed, 0x80000000 is reserved. */
    ctx->protocol_id = PROTO_OSPF2;
    node.sequence = UINT32_MAX;
    lsdb_bump_sequence(&node);
    assert_int_equal(node.sequence, 0);
    node.sequence = INT32_MAX;
    lsdb_bump_sequence(&node);
    assert_int_equal(node.sequence, INT32_MAX);
    lsdb_delete_ctx(ctx);
}

static void
test_delete_node(void **unused)
{
    lsdb_ctx_t *ctx;
    lsdb_node_t *node;
    uint32_t nodes, links, node_links;
    UNUSED(unused);

    ctx = test_ctx(PROTO_ISIS, 10);
    test_generate(ctx);
    nodes = ctx->nodecount;
    links = ctx->linkcount;
    node = test_get_node(ctx, "1921.6800.0003.00");
    assert_non_null(node);
    node_links = node->linkcount;
    assert_true(node_links > 0);

    lsdb_delete_node(ctx, node);
    assert_int_equal(ctx->nodecount, nodes - 1);
    assert_int_equal(ctx->linkcount, links - node_links);
    assert_null(test_get_node(ctx, "1921.6800.0003.00"));
    lsdb_delete_ctx(ctx);
}

static void
test_parse_sr_algo(void **unused)
{
    lsdb_ctx_t *ctx;
    char arg[64];
    UNUSED(unused);

    ctx = test_ctx(PROTO_ISIS, 10);
    assert_true(lspgen_parse_sr_algo(ctx, "0,1,128"));
    assert_int_equal(ctx->sr_algo_count, 3);
    assert_false(lspgen_parse_sr_algo(ctx, "0,0"));
    assert_false(lspgen_parse_sr_algo(ctx, "2"));
    assert_false(lspgen_parse_sr_algo(ctx, "0,1,128,129,130"));

    /* Flex-Algos are added to the SR algorithms, with algorithm 0 by default. */
    ctx->sr_algo_count = 0;
    snprintf(arg, sizeof(arg), "128:igp,129:min-delay:200");
    assert_true(lspgen_parse_flex_algo(ctx, arg));
    assert_int_equal(ctx->fad_count, 2);
    assert_true(lspgen_add_flex_algo_to_sr_algo(ctx));
    assert_int_equal(ctx->sr_algo_count, 3);
    assert_int_equal(ctx->sr_algo[0], 0);
    assert_int_equal(ctx->sr_algo[1], 128);
    assert_int_equal(ctx->sr_algo[2], 129);
    lsdb_delete_ctx(ctx);
}

static int
test_setup(void **unused)
{
    UNUSED(unused);

    log_id[NORMAL].enable = false;
    log_id[ERROR].enable = false;
    if (!mkdtemp(test_dir) || chdir(test_dir) != 0) {
        return -1;
    }
    return 0;
}

static int
test_teardown(void **unused)
{
    UNUSED(unused);

    if (chdir("/") != 0) {
        return -1;
    }
    return rmdir(test_dir);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_scan_node_id),
        cmocka_unit_test(test_store_bcd_addr),
        cmocka_unit_test(test_isis_connector),
        cmocka_unit_test(test_ospf_connector),
        cmocka_unit_test(test_isis_lsp_size),
        cmocka_unit_test(test_ospf_header),
        cmocka_unit_test(test_ospf_sr),
        cmocka_unit_test(test_ipv4_default_route),
        cmocka_unit_test(test_subgraph_links),
        cmocka_unit_test(test_config_round_trip),
        cmocka_unit_test(test_ospf_prefix_sid_config),
        cmocka_unit_test(test_stream_file),
        cmocka_unit_test(test_no_attributes),
        cmocka_unit_test(test_seq_cache),
        cmocka_unit_test(test_bump_sequence),
        cmocka_unit_test(test_delete_node),
        cmocka_unit_test(test_parse_sr_algo),
    };
    return cmocka_run_group_tests(tests, test_setup, test_teardown);
}
