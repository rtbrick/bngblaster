/*
 * BNG Blaster (BBL) - Util Tests
 *
 * Christian Giese, June 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <bbl.h>
#include <bbl_utils.h>

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
    assert_string_equal(val2key(numbers, 3), "Unknown");
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
test_format_ipv6_address(void **unused) {
    (void) unused;

    ipv6addr_t ipv6 = {0};
    ipv6[0] = 0xfe;
    ipv6[1] = 0x80;
    ipv6[15] = 0x01;

    assert_string_equal(format_ipv6_address(&ipv6), "fe80::1");
}

static void
test_format_ipv6_prefix(void **unused) {
    (void) unused;

    ipv6_prefix ipv6 = {0};
    ipv6.len = 64;
    ipv6.address[0] = 0xfe;
    ipv6.address[1] = 0x80;
    ipv6.address[15] = 0x01;

    assert_string_equal(format_ipv6_prefix(&ipv6), "fe80::1/64");
}

static void
test_replace_substring(void **unused) {
    (void) unused;

    assert_string_equal(replace_substring("1234{i}90", "{i}", "5678"), "1234567890"); 
    assert_string_equal(replace_substring("{i1}{i2}{i2}", "{i2}", "2"), "{i1}22"); 
    assert_string_equal(replace_substring("1234{long-variable-name}567890", "{long-variable-name}", ""), "1234567890"); 
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_val2key),
        cmocka_unit_test(test_format_mac_address),
        cmocka_unit_test(test_format_ipv4_address),
        cmocka_unit_test(test_format_ipv6_address),
        cmocka_unit_test(test_format_ipv6_prefix),
        cmocka_unit_test(test_replace_substring),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
