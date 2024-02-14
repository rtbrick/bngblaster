/*
 * Common Utils Tests
 *
 * Christian Giese, June 2021
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <utils.h>

static void
test_val2key(void **unused) {
    (void) unused;

    struct keyval_ numbers[] = {
        { 1, "one" },
        { 2, "two" },
        { 0, NULL}
    };
    assert_string_equal(val2key(numbers, 1), "one");
    assert_string_equal(val2key(numbers, 2), "two");
    assert_string_equal(val2key(numbers, 0), "Unknown");
}

static void
test_key2val(void **unused) {
    (void) unused;

    struct keyval_ numbers[] = {
        { 1, "one" },
        { 2, "two" },
        { 0, NULL}
    };
    assert_int_equal(key2val(numbers, "one"), 1);
    assert_int_equal(key2val(numbers, "two"), 2);
    assert_int_equal(key2val(numbers, "Unknown"), 0);
}

static void
test_keyval_get_key(void **unused) {
    (void) unused;

    struct keyval_ numbers[] = {
        { 1, "one" },
        { 2, "two" },
        { 0, NULL}
    };
    assert_string_equal(keyval_get_key(numbers, 1), "one");
    assert_string_equal(keyval_get_key(numbers, 2), "two");
    assert_string_equal(keyval_get_key(numbers, 0), "unknown");
}

static void
test_format_mac_address(void **unused) {
    (void) unused;

    uint8_t mac[MAC_STR_LEN] = {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6};
    assert_string_equal(format_mac_address(mac), "a1:b2:c3:d4:e5:f6");
}

static void
test_format_ipv4_address(void **unused) {
    (void) unused;

    uint32_t ipv4 = htobe32(0x01020304);
    assert_string_equal(format_ipv4_address(&ipv4), "1.2.3.4");
}

static void
test_scan_ipv4_address(void **unused) {
    (void) unused;

    uint32_t ipv4 = htobe32(0x01020304);
    uint32_t ipv4_test = 0;
    scan_ipv4_address("1.2.3.4", &ipv4_test);

    assert_int_equal(ipv4,ipv4_test);
}

static void
test_format_ipv6_address(void **unused) {
    (void) unused;

    ipv6addr_t ipv6 = {0};
    ipv6[0] = 0xfe;
    ipv6[1] = 0x80;
    ipv6[15] = 0x04;

    assert_string_equal(format_ipv6_address(&ipv6), "fe80::4");
}

static void
test_scan_ipv6_address(void **unused) {
    (void) unused;

    ipv6addr_t ipv6 = {0};
    ipv6[0] = 0xfe;
    ipv6[1] = 0x80;
    ipv6[15] = 0x01;
    ipv6addr_t ipv6_test = {0};
    scan_ipv6_address("fe80::1", &ipv6_test);

    assert_memory_equal(ipv6_test,ipv6,sizeof(ipv6addr_t));
}

static void
test_format_ipv4_prefix(void **unused) {
    (void) unused;

    ipv4_prefix ipv4;
    ipv4.address = htobe32(0x01020304); 
    ipv4.len = 16;

    assert_string_equal(format_ipv4_prefix(&ipv4), "1.2.3.4/16");
}

static void
test_scan_ipv4_prefix(void **unused) {
    (void) unused;

    ipv4_prefix ipv4 = {0};
    ipv4.address = htobe32(0x01020304); 
    ipv4.len = 16;  
    ipv4_prefix ipv4_test = {0};
    scan_ipv4_prefix("1.2.3.4/16", &ipv4_test);

    assert_memory_equal(&ipv4_test,&ipv4,sizeof(ipv4_prefix));
}

static void
test_format_ipv6_prefix(void **unused) {
    (void) unused;

    ipv6_prefix ipv6 = {0};
    ipv6.len = 64;
    ipv6.address[0] = 0xfe;
    ipv6.address[1] = 0x80;
    ipv6.address[15] = 0x02;

    assert_string_equal(format_ipv6_prefix(&ipv6), "fe80::2/64");
}

static void
test_scan_ipv6_prefix(void **unused) {
    (void) unused;

    ipv6_prefix ipv6 = {0};
    ipv6.len = 64;
    ipv6.address[0] = 0xfe;
    ipv6.address[1] = 0x80;
    ipv6.address[15] = 0x02;
    ipv6_prefix ipv6_test = {0};
    scan_ipv6_prefix("fe80::2/64", &ipv6_test);

    assert_memory_equal(&ipv6_test,&ipv6,sizeof(ipv6_prefix));
}

static void
test_format_iso_prefix(void **unused) {
    (void) unused;

    iso_prefix iso = {0};
    iso.len = 24;
    iso.address[0] = 73;
    iso.address[1] = 73;
    iso.address[2] = 1;

    assert_string_equal(format_iso_prefix(&iso), "49.4901/24");
}

static void
test_scan_iso_prefix(void **unused) {
    (void) unused;

    iso_prefix iso = {0};
    iso.len = 24;
    iso.address[0] = 73;
    iso.address[1] = 73;
    iso.address[2] = 2;
    iso_prefix iso_test = {0};

    scan_iso_prefix("49.4902/24", &iso_test);

    assert_memory_equal(&iso_test,&iso,sizeof(iso_prefix));
}

static void
test_replace_substring(void **unused) {
    (void) unused;

    assert_string_equal(replace_substring("1234{i}90", "{i}", "5678"), "1234567890");
    assert_string_equal(replace_substring("{i1}{i2}{i2}", "{i2}", "2"), "{i1}22");
    assert_string_equal(replace_substring("1234{long-variable-name}567890", "{long-variable-name}", ""), "1234567890");
}

static void
test_string_or_na(void **unused) {
    (void) unused;

    assert_string_equal(string_or_na("hello"), "hello");
    assert_string_equal(string_or_na("{i1}22"), "{i1}22");
    assert_string_equal(string_or_na("123"), "123");
}

static void
test_ipv4_multicast_mac(void **unused) {
    (void) unused;

    uint32_t ipv4;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint8_t mac_expected[ETH_ADDR_LEN] = {0x01, 0x00, 0x5e, 0x01, 0x02, 0x03};

    inet_pton(AF_INET, "239.1.2.3", &ipv4);
    ipv4_multicast_mac(ipv4, mac);

    assert_memory_equal(mac_expected, mac, ETH_ADDR_LEN);
}

static void
test_ipv6_multicast_mac(void **unused) {
    (void) unused;

    ipv6addr_t ipv6;
    uint8_t mac[ETH_ADDR_LEN] = {0};
    uint8_t mac_expected[ETH_ADDR_LEN] = {0x33, 0x33, 0x01, 0x02, 0x03, 0x04};

    inet_pton(AF_INET6, "ff02::0102:0304", ipv6);
    ipv6_multicast_mac(ipv6, mac);

    assert_memory_equal(mac_expected, mac, ETH_ADDR_LEN);
}

static void
test_ipv4_mask_to_len(void **unused) {
    (void) unused;

    uint32_t ipv4;

    inet_pton(AF_INET, "0.0.0.0", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 0);

    inet_pton(AF_INET, "255.0.0.0", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 8);

    inet_pton(AF_INET, "255.255.0.0", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 16);

    inet_pton(AF_INET, "255.255.255.0", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 24);

    inet_pton(AF_INET, "255.255.254.0", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 23);

    inet_pton(AF_INET, "255.255.255.252", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 30);

    inet_pton(AF_INET, "255.255.255.255", &ipv4);
    assert_int_equal(ipv4_mask_to_len(ipv4), 32);

    ipv4 = htobe32(0xff00ff00);
    assert_int_equal(ipv4_mask_to_len(ipv4), 0);

    ipv4 = htobe32(0xffffff01);
    assert_int_equal(ipv4_mask_to_len(ipv4), 0);
}

static void
test_ipv4_len_to_mask(void **unused) {
    (void) unused;

    uint32_t mask_a;
    uint32_t mask_b;

    inet_pton(AF_INET, "0.0.0.0", &mask_a);
    mask_b = ipv4_len_to_mask(0);
    assert_int_equal(mask_a, mask_b);

    inet_pton(AF_INET, "255.255.255.0", &mask_a);
    mask_b = ipv4_len_to_mask(24);
    assert_int_equal(mask_a, mask_b);

    inet_pton(AF_INET, "255.255.255.252", &mask_a);
    mask_b = ipv4_len_to_mask(30);
    assert_int_equal(mask_a, mask_b);

    inet_pton(AF_INET, "255.255.255.255", &mask_a);
    mask_b = ipv4_len_to_mask(32);
    assert_int_equal(mask_a, mask_b);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_val2key),
        cmocka_unit_test(test_key2val),
        cmocka_unit_test(test_keyval_get_key),
        cmocka_unit_test(test_format_mac_address),
        cmocka_unit_test(test_format_ipv4_address),
        cmocka_unit_test(test_format_ipv4_prefix),
        cmocka_unit_test(test_scan_ipv4_prefix),
        cmocka_unit_test(test_format_ipv6_address),
        cmocka_unit_test(test_scan_ipv6_address),
        cmocka_unit_test(test_scan_ipv4_address),
        cmocka_unit_test(test_format_ipv6_prefix),
        cmocka_unit_test(test_scan_ipv6_prefix),
        cmocka_unit_test(test_format_iso_prefix),
        cmocka_unit_test(test_scan_iso_prefix),
        cmocka_unit_test(test_replace_substring),
        cmocka_unit_test(test_string_or_na),
        cmocka_unit_test(test_ipv4_multicast_mac),
        cmocka_unit_test(test_ipv6_multicast_mac),
        cmocka_unit_test(test_ipv4_mask_to_len),
        cmocka_unit_test(test_ipv4_len_to_mask),

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}