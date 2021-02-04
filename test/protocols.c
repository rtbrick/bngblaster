/*
 * BNG Blaster (BBL) - Protocol Tests
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <bbl.h>
#include <bbl_protocols.h>
#include "ethernet_packets.h"

static void
test_protocols_decode_pppoe_ipcp_conf_request(void **unused) {
    (void) unused;

    uint8_t *sp = calloc(1, SCRATCHPAD_LEN);
    bbl_ethernet_header_t *eth;
    protocol_error_t decode_result;
    bbl_pppoe_session_t *pppoes;
    bbl_ipcp_t *ipcp;

    uint32_t ip;
    uint32_t dns1;
    uint32_t dns2;
    inet_pton(AF_INET, "10.137.0.0", &ip);
    inet_pton(AF_INET, "100.0.0.3", &dns1);
    inet_pton(AF_INET, "100.0.0.4", &dns2);

    decode_result = decode_ethernet(pppoe_ipcp_conf_request, sizeof(pppoe_ipcp_conf_request), sp, SCRATCHPAD_LEN, &eth);
    assert_int_equal(decode_result, PROTOCOL_SUCCESS);

    pppoes = (bbl_pppoe_session_t*)eth->next;
    ipcp = (bbl_ipcp_t*)pppoes->next;

    assert_int_equal(ipcp->code, PPP_CODE_CONF_REQUEST);
    assert_int_equal(ipcp->address, ip);
    assert_int_equal(ipcp->dns1, dns1);
    assert_int_equal(ipcp->dns2, dns2);

}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_protocols_decode_pppoe_ipcp_conf_request),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
