/*
 * BNG Blaster (BBL) - ANCP OAM Tests
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/bbl_ancp.c"

static uint32_t
make_oam_request(uint8_t *packet, bool include_circuit_id, uint8_t loop_count)
{
    uint8_t parameters[2] = {loop_count, 5};
    uint8_t opaque[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t circuit_id[] = "line-1";
    size_t tlv_length = 0;
    uint16_t tlv_count = 0;
    uint32_t packet_len;

    memset(packet, 0, 128);
    ancp_put_u16(packet, ANCP_PROTOCOL_ID);
    packet[4] = ANCP_VERSION;
    packet[5] = ANCP_MESSAGE_PORT_MANAGEMENT;
    ancp_put_u16(packet + 6, 0x2000);
    packet[12] = 0x80;
    packet[13] = 1;
    packet[30] = ANCP_FUNCTION_REMOTE_LOOPBACK;
    packet[37] = ANCP_MESSAGE_PORT_MANAGEMENT;
    packet[38] = ANCP_TECHNOLOGY_DSL;

    if(include_circuit_id) {
        assert_true(ancp_add_tlv(packet + 44, 84, &tlv_length, 0x0001,
                                 circuit_id, sizeof(circuit_id) - 1));
        tlv_count++;
    }
    assert_true(ancp_add_tlv(packet + 44, 84, &tlv_length, 0x0007,
                             parameters, sizeof(parameters)));
    assert_true(ancp_add_tlv(packet + 44, 84, &tlv_length, 0x0008,
                             opaque, sizeof(opaque)));
    tlv_count += 2;
    ancp_put_u16(packet + 40, tlv_count);
    ancp_put_u16(packet + 42, tlv_length);
    packet_len = 44 + tlv_length;
    ancp_put_u16(packet + 2, packet_len - 4);
    ancp_put_u16(packet + 14, packet_len - 4);
    return packet_len;
}

static void
test_adjacency_capabilities(void **state)
{
    uint8_t packet[48] = {0};
    (void)state;

    packet[37] = 2;
    ancp_put_u16(packet + 38, 8);
    ancp_put_u16(packet + 40, ANCP_CAPABILITY_DSL_TOPOLOGY);
    ancp_put_u16(packet + 44, ANCP_CAPABILITY_DSL_REMOTE_LOOPBACK);

    assert_true(ancp_has_topology_capability(packet, sizeof(packet)));
    assert_true(ancp_has_capability(packet, sizeof(packet),
                                    ANCP_CAPABILITY_DSL_REMOTE_LOOPBACK));
    ancp_put_u16(packet + 46, 4);
    assert_false(ancp_has_capability(packet, sizeof(packet),
                                     ANCP_CAPABILITY_DSL_REMOTE_LOOPBACK));
}

static void
test_ancp_access_types(void **state)
{
    (void)state;

    assert_true(ancp_access_type_supported(ACCESS_TYPE_IPOE));
    assert_true(ancp_access_type_supported(ACCESS_TYPE_PPPOE));
    assert_false(ancp_access_type_supported(ACCESS_TYPE_PPPOL2TP));
}

static void
test_pppoe_port_up_uses_access_circuit_id_and_profile(void **state)
{
    bbl_session_s session = {0};
    bbl_access_line_profile_s profile = {0};
    uint8_t packet[2092];
    uint16_t packet_len;
    uint32_t offset;
    bool found_circuit_id = false;
    bool found_actual_rate = false;
    bool found_expected_rate = false;
    bool found_down_status = false;
    (void)state;

    session.access_type = ACCESS_TYPE_PPPOE;
    session.agent_circuit_id = "line-pppoe";
    session.ancp_line_profile = &profile;
    session.rate_up = 10240;
    session.rate_down = 50000;
    session.dsl_type = 5;
    profile.etr_up = 9000;

    assert_true(ancp_build_port_message(&session, ANCP_MESSAGE_PORT_UP,
                                        packet, &packet_len));
    assert_int_equal(packet[5], ANCP_MESSAGE_PORT_UP);
    assert_int_equal(packet[38], ANCP_TECHNOLOGY_DSL);

    offset = 44;
    while(offset < packet_len) {
        uint16_t type = ancp_get_u16(packet + offset);
        uint16_t value_len = ancp_get_u16(packet + offset + 2);
        uint32_t value_offset = offset + 4;
        uint32_t value_end = value_offset + value_len;
        uint32_t padded_len = (value_len + 3u) & ~3u;

        if(type == 0x0001) {
            found_circuit_id = value_len == strlen("line-pppoe") &&
                               memcmp(packet + value_offset, "line-pppoe",
                                      value_len) == 0;
        } else if(type == 0x0004) {
            while(value_offset + 4 <= value_end) {
                uint16_t line_type = ancp_get_u16(packet + value_offset);
                uint16_t line_len = ancp_get_u16(packet + value_offset + 2);
                if(line_type == 0x0081) {
                    found_actual_rate = line_len == 4 &&
                        ancp_get_u32(packet + value_offset + 4) == 10240;
                } else if(line_type == 0x009B) {
                    found_expected_rate = line_len == 4 &&
                        ancp_get_u32(packet + value_offset + 4) == 9000;
                }
                value_offset += 4 + ((line_len + 3u) & ~3u);
            }
        }
        offset += 4 + padded_len;
    }

    assert_true(found_circuit_id);
    assert_true(found_actual_rate);
    assert_true(found_expected_rate);

    assert_true(ancp_build_port_message(&session, ANCP_MESSAGE_PORT_DOWN,
                                        packet, &packet_len));
    assert_int_equal(packet[5], ANCP_MESSAGE_PORT_DOWN);
    offset = 44;
    while(offset < packet_len) {
        uint16_t type = ancp_get_u16(packet + offset);
        uint16_t value_len = ancp_get_u16(packet + offset + 2);
        uint32_t value_offset = offset + 4;
        uint32_t value_end = value_offset + value_len;
        uint32_t padded_len = (value_len + 3u) & ~3u;

        if(type == 0x0004) {
            while(value_offset + 4 <= value_end) {
                uint16_t line_type = ancp_get_u16(packet + value_offset);
                uint16_t line_len = ancp_get_u16(packet + value_offset + 2);
                if(line_type == 0x008F) {
                    found_down_status = line_len == 4 &&
                        ancp_get_u32(packet + value_offset + 4) == 2;
                }
                value_offset += 4 + ((line_len + 3u) & ~3u);
            }
        }
        offset += 4 + padded_len;
    }
    assert_true(found_down_status);
}

static void
test_oam_success_response(void **state)
{
    uint8_t request_packet[128];
    uint32_t request_len;
    ancp_oam_request_s request;
    uint16_t result_code;
    uint8_t *response_packet;
    uint16_t response_len;
    uint32_t offset;
    bool found_circuit_id = false;
    bool found_parameters = false;
    bool found_opaque = false;
    bool found_response_string = false;
    (void)state;

    request_len = make_oam_request(request_packet, true, 2);
    assert_true(ancp_parse_oam_request(request_packet, request_len,
                                       &request, &result_code));
    assert_int_equal(result_code, 0);
    assert_true(request.circuit_id != NULL);
    assert_true(ancp_build_oam_response(request_packet, request_len, &request,
                                        ANCP_RESULT_SUCCESS,
                                        ANCP_RESULT_CODE_LINE_SHOWTIME,
                                        &response_packet, &response_len));

    assert_int_equal(ancp_get_u16(response_packet + 6), 0x3503);
    assert_int_equal(ancp_get_u16(response_packet + 2), response_len - 4);
    assert_int_equal(ancp_get_u16(response_packet + 14), response_len - 4);
    assert_int_equal(ancp_get_u16(response_packet + 40), 3);

    offset = 44;
    while(offset < response_len) {
        uint16_t type = ancp_get_u16(response_packet + offset);
        uint16_t value_len = ancp_get_u16(response_packet + offset + 2);
        uint32_t padded_len = (value_len + 3u) & ~3u;
        if(type == 0x0001) {
            found_circuit_id = value_len == 6 &&
                               memcmp(response_packet + offset + 4,
                                      "line-1", 6) == 0;
        } else if(type == 0x0007) {
            found_parameters = true;
        } else if(type == 0x0008) {
            found_opaque = value_len == 8 &&
                           response_packet[offset + 11] == 8;
        } else if(type == 0x0009) {
            static const char expected[] =
                "BNG Blaster: OAM simulated locally; no physical loopback was performed.";
            found_response_string = value_len == sizeof(expected) - 1 &&
                                    memcmp(response_packet + offset + 4,
                                           expected, value_len) == 0;
        }
        offset += 4 + padded_len;
    }
    assert_true(found_circuit_id);
    assert_false(found_parameters);
    assert_true(found_opaque);
    assert_true(found_response_string);
    free(response_packet);
}

static void
test_oam_request_accepts_zero_message_type_subfield(void **state)
{
    uint8_t request_packet[128];
    uint32_t request_len;
    ancp_oam_request_s request;
    uint16_t result_code;
    (void)state;

    request_len = make_oam_request(request_packet, true, 2);
    request_packet[37] = 0;
    assert_true(ancp_parse_oam_request(request_packet, request_len,
                                       &request, &result_code));
    assert_int_equal(result_code, 0);

    request_packet[37] = 1;
    assert_false(ancp_parse_oam_request(request_packet, request_len,
                                        &request, &result_code));
}

static void
test_oam_request_accepts_bngj08_tlv_padding(void **state)
{
    uint8_t request_packet[128];
    uint32_t request_len;
    ancp_oam_request_s request;
    uint16_t result_code;
    (void)state;

    request_len = make_oam_request(request_packet, true, 2);
    request_packet[37] = 0;
    ancp_put_u16(request_packet + 14, 12);
    ancp_put_u16(request_packet + 46, 8);
    ancp_put_u16(request_packet + 58, 4);

    assert_true(ancp_parse_oam_request(request_packet, request_len,
                                       &request, &result_code));
    assert_int_equal(result_code, 0);
    assert_int_equal(request.circuit_id_len, 6);
}

static void
test_oam_failure_preserves_request_tlvs(void **state)
{
    uint8_t request_packet[128];
    uint32_t request_len;
    ancp_oam_request_s request;
    uint16_t result_code;
    uint8_t *response_packet;
    uint16_t response_len;
    (void)state;

    request_len = make_oam_request(request_packet, true, 2);
    assert_true(ancp_parse_oam_request(request_packet, request_len,
                                       &request, &result_code));
    assert_true(ancp_build_oam_response(request_packet, request_len, &request,
                                        ANCP_RESULT_FAILURE,
                                        ANCP_RESULT_CODE_PORT_NOT_FOUND,
                                        &response_packet, &response_len));

    assert_int_equal(response_len, request_len);
    assert_int_equal(ancp_get_u16(response_packet + 6), 0x4500);
    assert_memory_equal(response_packet, request_packet, 6);
    assert_memory_equal(response_packet + 8, request_packet + 8,
                        request_len - 8);
    free(response_packet);
}

static void
test_oam_invalid_count_and_missing_circuit_id(void **state)
{
    uint8_t packet[128];
    uint32_t packet_len;
    ancp_oam_request_s request;
    uint16_t result_code;
    (void)state;

    packet_len = make_oam_request(packet, true, 33);
    assert_true(ancp_parse_oam_request(packet, packet_len, &request,
                                       &result_code));
    assert_int_equal(result_code, ANCP_RESULT_CODE_INVALID_TEST_PARAMETER);

    packet_len = make_oam_request(packet, false, 1);
    assert_true(ancp_parse_oam_request(packet, packet_len, &request,
                                       &result_code));
    assert_int_equal(result_code, ANCP_RESULT_CODE_MANDATORY_TLV_MISSING);
}

static void
test_port_up_trigger_and_desired_state(void **state)
{
    bbl_ancp_config_s config = {0};
    struct bbl_ancp_connection_ connection = {0};
    bbl_session_s session = {0};
    (void)state;

    connection.config = &config;
    session.ancp_config = &config;
    config.connection = &connection;

    /* Default trigger adjacency: Port-Up with adjacency, before PPPoE. */
    assert_true(ancp_port_up_trigger_reached(&connection, 0, 4));
    assert_false(ancp_port_desired(&connection, &session, false));
    connection.state = ANCP_STATE_ESTABLISHED;
    connection.port_up_triggered = true;
    assert_true(ancp_port_desired(&connection, &session, false));
    assert_false(ancp_port_desired(&connection, &session, true));
    session.ancp_port_admin = ANCP_PORT_ADMIN_DOWN;
    assert_false(ancp_port_desired(&connection, &session, false));

    config.port_up_trigger = ANCP_PORT_UP_TRIGGER_COUNT;
    config.port_up_count = 2;
    connection.sessions_established = 1;
    assert_false(ancp_port_up_trigger_reached(&connection, 0, 4));
    connection.sessions_established = 2;
    assert_true(ancp_port_up_trigger_reached(&connection, 0, 4));

    config.port_up_trigger = ANCP_PORT_UP_TRIGGER_ALL_ESTABLISHED;
    assert_false(ancp_port_up_trigger_reached(&connection, 0, 4));
    connection.sessions_established = 4;
    assert_true(ancp_port_up_trigger_reached(&connection, 0, 4));

    config.port_up_trigger = ANCP_PORT_UP_TRIGGER_DELAY;
    config.port_up_delay = 30;
    connection.established_at = 100;
    assert_false(ancp_port_up_trigger_reached(&connection, 129, 4));
    assert_true(ancp_port_up_trigger_reached(&connection, 130, 4));

    /* Trigger established follows the session state, API overrides it. */
    config.port_up_trigger = ANCP_PORT_UP_TRIGGER_ESTABLISHED;
    session.ancp_port_admin = ANCP_PORT_ADMIN_AUTO;
    assert_false(ancp_port_up_trigger_reached(&connection, 130, 4));
    assert_false(ancp_port_desired(&connection, &session, false));
    session.session_state = BBL_ESTABLISHED;
    assert_true(ancp_port_desired(&connection, &session, false));
    session.session_state = BBL_IDLE;
    session.ancp_port_admin = ANCP_PORT_ADMIN_UP;
    assert_true(ancp_port_desired(&connection, &session, false));
}

static void
test_session_start_waits_for_adjacency(void **state)
{
    bbl_ancp_config_s config = {0};
    struct bbl_ancp_connection_ connection = {0};
    bbl_session_s session = {0};
    (void)state;

    assert_true(bbl_ancp_session_ready(&session));
    connection.config = &config;
    config.connection = &connection;
    session.ancp_config = &config;

    assert_false(bbl_ancp_session_ready(&session));
    connection.state = ANCP_STATE_ESTABLISHED;
    assert_false(bbl_ancp_session_ready(&session));
    session.ancp_port_up = true;
    assert_true(bbl_ancp_session_ready(&session));

    session.ancp_port_up = false;
    session.ancp_port_admin = ANCP_PORT_ADMIN_DOWN;
    assert_true(bbl_ancp_session_ready(&session));

    session.ancp_port_admin = ANCP_PORT_ADMIN_AUTO;
    config.port_up_trigger = ANCP_PORT_UP_TRIGGER_ALL_ESTABLISHED;
    assert_true(bbl_ancp_session_ready(&session));
    connection.state = ANCP_STATE_SYNSENT;
    assert_false(bbl_ancp_session_ready(&session));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_adjacency_capabilities),
        cmocka_unit_test(test_ancp_access_types),
        cmocka_unit_test(test_pppoe_port_up_uses_access_circuit_id_and_profile),
        cmocka_unit_test(test_oam_success_response),
        cmocka_unit_test(test_oam_request_accepts_zero_message_type_subfield),
        cmocka_unit_test(test_oam_request_accepts_bngj08_tlv_padding),
        cmocka_unit_test(test_oam_failure_preserves_request_tlvs),
        cmocka_unit_test(test_oam_invalid_count_and_missing_circuit_id),
        cmocka_unit_test(test_port_up_trigger_and_desired_state),
        cmocka_unit_test(test_session_start_waits_for_adjacency),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
