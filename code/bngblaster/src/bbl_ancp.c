/*
 * BNG Blaster (BBL) - ANCP access node
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"

#define ANCP_PROTOCOL_ID 0x880C
#define ANCP_VERSION 50
#define ANCP_MESSAGE_ADJACENCY 10
#define ANCP_MESSAGE_PORT_UP 80
#define ANCP_MESSAGE_PORT_DOWN 81
#define ANCP_CODE_SYN 1
#define ANCP_CODE_SYNACK 2
#define ANCP_CODE_ACK 3
#define ANCP_CODE_RSTACK 4
#define ANCP_CAPABILITY_DSL_TOPOLOGY 1
#define ANCP_ADJACENCY_TIMER 250
#define ANCP_MAX_MESSAGE (UINT16_MAX + 4)
#define ANCP_RECONNECT_SECONDS 5

typedef enum {
    ANCP_STATE_IDLE,
    ANCP_STATE_CONNECTING,
    ANCP_STATE_SYNSENT,
    ANCP_STATE_SYNRCVD,
    ANCP_STATE_ESTABLISHED
} ancp_state_t;

struct bbl_ancp_connection_
{
    bbl_ancp_config_s *config;
    bbl_tcp_ctx_s *tcpc;
    timer_s *timer;
    ancp_state_t state;
    uint8_t peer_name[6];
    uint32_t peer_port;
    uint32_t peer_instance;
    uint32_t local_instance;
    uint8_t adjacency_timer;
    uint8_t p_flag;
    uint8_t partition_id;
    uint32_t rx_len;
    uint32_t rx_expected;
    uint8_t rx_buffer[ANCP_MAX_MESSAGE];
    time_t last_tx;
    time_t last_rx;
    time_t reconnect_at;
};

static uint16_t
ancp_get_u16(const uint8_t *buf)
{
    return ((uint16_t)buf[0] << 8) | buf[1];
}

static uint32_t
ancp_get_u32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
}

static void
ancp_put_u16(uint8_t *buf, uint16_t value)
{
    buf[0] = value >> 8;
    buf[1] = value;
}

static void
ancp_put_u32(uint8_t *buf, uint32_t value)
{
    buf[0] = value >> 24;
    buf[1] = value >> 16;
    buf[2] = value >> 8;
    buf[3] = value;
}

static bool
ancp_send_packet(struct bbl_ancp_connection_ *connection, uint8_t *buf, uint16_t len)
{
    if(!connection->tcpc || !bbl_tcp_send_copy(connection->tcpc, buf, len)) {
        return false;
    }
    connection->last_tx = time(NULL);
    return true;
}

static bool
ancp_send_adjacency(struct bbl_ancp_connection_ *connection, uint8_t code)
{
    uint8_t buf[44] = {0};
    bbl_network_interface_s *interface = connection->config->interface;

    ancp_put_u16(buf, ANCP_PROTOCOL_ID);
    ancp_put_u16(buf + 2, sizeof(buf) - 4);
    buf[4] = ANCP_VERSION;
    buf[5] = ANCP_MESSAGE_ADJACENCY;
    buf[6] = connection->adjacency_timer;
    buf[7] = code;
    memcpy(buf + 8, interface->mac, ETH_ADDR_LEN);

    if(code != ANCP_CODE_SYN) {
        memcpy(buf + 14, connection->peer_name, sizeof(connection->peer_name));
        ancp_put_u32(buf + 20, 0);
        ancp_put_u32(buf + 24, connection->peer_port);
    }

    buf[28] = connection->p_flag; /* No partition. */
    buf[29] = connection->local_instance >> 16;
    buf[30] = connection->local_instance >> 8;
    buf[31] = connection->local_instance;
    buf[32] = connection->partition_id;
    buf[33] = connection->peer_instance >> 16;
    buf[34] = connection->peer_instance >> 8;
    buf[35] = connection->peer_instance;
    buf[36] = 0;
    buf[37] = 1;
    ancp_put_u16(buf + 38, 4);
    ancp_put_u16(buf + 40, ANCP_CAPABILITY_DSL_TOPOLOGY);
    ancp_put_u16(buf + 42, 0);

    return ancp_send_packet(connection, buf, sizeof(buf));
}

static bool
ancp_add_tlv(uint8_t *buf, size_t capacity, size_t *len, uint16_t type,
             const uint8_t *value, uint16_t value_len)
{
    size_t padded_len = (value_len + 3u) & ~3u;
    if(*len + 4 + padded_len > capacity) {
        return false;
    }
    ancp_put_u16(buf + *len, type);
    ancp_put_u16(buf + *len + 2, value_len);
    if(value_len) {
        memcpy(buf + *len + 4, value, value_len);
    }
    if(padded_len > value_len) {
        memset(buf + *len + 4 + value_len, 0, padded_len - value_len);
    }
    *len += 4 + padded_len;
    return true;
}

static bool
ancp_add_u32_tlv(uint8_t *buf, size_t capacity, size_t *len, uint16_t type, uint32_t value)
{
    uint8_t value_buf[4];
    ancp_put_u32(value_buf, value);
    return ancp_add_tlv(buf, capacity, len, type, value_buf, sizeof(value_buf));
}

static bool
ancp_add_profile_rate(uint8_t *buf, size_t capacity, size_t *len,
                      uint16_t type, uint32_t value)
{
    return !value || ancp_add_u32_tlv(buf, capacity, len, type, value);
}

static bool
ancp_build_line_tlv(bbl_session_s *session, uint8_t *buf, size_t capacity,
                    size_t *len, bool port_up, uint16_t *line_type)
{
    bbl_access_line_profile_s *profile = session->ancp_line_profile;
    size_t line_len = 0;
    uint32_t rate_up = session->rate_up ? session->rate_up : profile->act_up;
    uint32_t rate_down = session->rate_down ? session->rate_down : profile->act_down;
    uint32_t dsl_type = session->dsl_type ? session->dsl_type : profile->dsl_type;
    bool pon = profile->pon_type || profile->ont_onu_avg_down ||
               profile->ont_onu_peak_down || profile->ont_onu_max_up ||
               profile->ont_onu_ass_up || profile->pon_max_up || profile->pon_max_down;

    if(pon) {
        uint16_t pon_type;
        uint16_t first_rate;

        if(profile->pon_access_line_version == DRAFT_LIHAWI_00 ||
           profile->pon_access_line_version == DRAFT_LIHAWI_01) {
            pon_type = 0x0092;
            first_rate = 0x0093;
        } else {
            pon_type = 0x0097;
            first_rate = 0x00B0;
        }
        if(!ancp_add_u32_tlv(buf, capacity, &line_len, pon_type, profile->pon_type) ||
           !ancp_add_profile_rate(buf, capacity, &line_len, first_rate, profile->ont_onu_avg_down) ||
           !ancp_add_profile_rate(buf, capacity, &line_len, first_rate + 1, profile->ont_onu_peak_down) ||
           !ancp_add_profile_rate(buf, capacity, &line_len, first_rate + 2, profile->ont_onu_max_up) ||
           !ancp_add_profile_rate(buf, capacity, &line_len, first_rate + 3, profile->ont_onu_ass_up) ||
           !ancp_add_profile_rate(buf, capacity, &line_len, first_rate + 4, profile->pon_max_up) ||
           !ancp_add_profile_rate(buf, capacity, &line_len, first_rate + 5, profile->pon_max_down)) {
            return false;
        }
        *line_type = 0x0012;
        *len = line_len;
        return true;
    }

    if(!ancp_add_u32_tlv(buf, capacity, &line_len, 0x0091, dsl_type)) {
        return false;
    }
    if(profile->data_link_encaps) {
        uint8_t encaps[4];
        ancp_put_u32(encaps, profile->data_link_encaps);
        if(!ancp_add_tlv(buf, capacity, &line_len, 0x0090, encaps, 3)) {
            return false;
        }
    }
    if(!ancp_add_u32_tlv(buf, capacity, &line_len, 0x008F, port_up ? 1 : 2) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0081, rate_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0082, rate_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0083, profile->min_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0084, profile->min_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0085, profile->att_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0086, profile->att_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0087, profile->max_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0088, profile->max_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x0089, profile->min_up_low) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x008A, profile->min_down_low) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x008B, profile->max_interl_delay_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x008C, profile->act_interl_delay_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x008D, profile->max_interl_delay_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x008E, profile->act_interl_delay_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x009B, profile->etr_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x009C, profile->etr_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x009D, profile->attetr_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x009E, profile->attetr_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x009F, profile->gdr_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x00A0, profile->gdr_down) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x00A1, profile->attgdr_up) ||
       !ancp_add_profile_rate(buf, capacity, &line_len, 0x00A2, profile->attgdr_down)) {
        return false;
    }
    *line_type = 0x0004;
    *len = line_len;
    return true;
}

static bool
ancp_build_port_message(bbl_session_s *session, uint8_t message_type,
                        uint8_t *buf, uint16_t *message_len)
{
    uint8_t tlvs[2048];
    uint8_t line[1024];
    size_t tlv_len = 0;
    size_t line_len = 0;
    size_t len = 44;
    uint16_t tlv_count = 0;
    uint16_t line_type;

    if(!session->agent_circuit_id ||
       !ancp_add_tlv(tlvs, sizeof(tlvs), &tlv_len, 0x0001,
                     (const uint8_t *)session->agent_circuit_id,
                     strlen(session->agent_circuit_id))) {
        return false;
    }
    tlv_count++;
    if(session->agent_remote_id) {
        if(!ancp_add_tlv(tlvs, sizeof(tlvs), &tlv_len, 0x0002,
                         (const uint8_t *)session->agent_remote_id,
                         strlen(session->agent_remote_id))) {
            return false;
        }
        tlv_count++;
    }
    if(session->access_aggregation_circuit_id) {
        if(!ancp_add_tlv(tlvs, sizeof(tlvs), &tlv_len, 0x0003,
                         (const uint8_t *)session->access_aggregation_circuit_id,
                         strlen(session->access_aggregation_circuit_id))) {
            return false;
        }
        tlv_count++;
    }
    if(!ancp_build_line_tlv(session, line, sizeof(line), &line_len,
                            message_type == ANCP_MESSAGE_PORT_UP, &line_type) ||
       !ancp_add_tlv(tlvs, sizeof(tlvs), &tlv_len,
                     line_type, line, line_len)) {
        return false;
    }
    tlv_count++;

    memset(buf, 0, 44 + tlv_len);
    ancp_put_u16(buf, ANCP_PROTOCOL_ID);
    ancp_put_u16(buf + 2, 40 + tlv_len);
    buf[4] = ANCP_VERSION;
    buf[5] = message_type;
    buf[12] = 0x80;
    buf[13] = 1;
    ancp_put_u16(buf + 14, 40 + tlv_len);
    buf[36] = 0;
    buf[37] = message_type;
    buf[38] = line_type == 0x0012 ? 1 : 5;
    buf[39] = 0;
    ancp_put_u16(buf + 40, tlv_count);
    ancp_put_u16(buf + 42, tlv_len);
    memcpy(buf + 44, tlvs, tlv_len);
    len += tlv_len;
    *message_len = len;
    return true;
}

static bool
ancp_send_port_message(bbl_session_s *session, uint8_t message_type)
{
    uint8_t buf[2092];
    uint16_t len;
    struct bbl_ancp_connection_ *connection = session->ancp_config->connection;

    if(connection->state != ANCP_STATE_ESTABLISHED || !connection->tcpc) {
        return false;
    }
    if(!ancp_build_port_message(session, message_type, buf, &len)) {
        LOG(ERROR, "ANCP session %u failed to encode Port-%s\n",
            session->session_id, message_type == ANCP_MESSAGE_PORT_UP ? "Up" : "Down");
        return false;
    }
    if(!ancp_send_packet(connection, buf, len)) {
        LOG(ERROR, "ANCP session %u failed to queue Port-%s\n",
            session->session_id, message_type == ANCP_MESSAGE_PORT_UP ? "Up" : "Down");
        return false;
    }
    return true;
}

static bool
ancp_has_topology_capability(const uint8_t *packet, uint32_t packet_len)
{
    uint16_t total_len;
    uint32_t cap_end;
    uint32_t offset = 40;
    uint8_t count;
    uint8_t i;
    bool found = false;

    if(packet_len < 40) {
        return false;
    }
    count = packet[37];
    total_len = ancp_get_u16(packet + 38);
    if((uint32_t)total_len != packet_len - 40) {
        return false;
    }
    cap_end = 40u + (uint32_t)total_len;
    for(i = 0; i < count; i++) {
        uint16_t type;
        uint16_t data_len;
        uint32_t padded_len;
        if(offset + 4 > cap_end) {
            return false;
        }
        type = ancp_get_u16(packet + offset);
        data_len = ancp_get_u16(packet + offset + 2);
        padded_len = (data_len + 3u) & ~3u;
        if(offset + 4 + padded_len > cap_end) {
            return false;
        }
        if(type == ANCP_CAPABILITY_DSL_TOPOLOGY) {
            if(data_len != 0) {
                return false;
            }
            found = true;
        }
        offset += 4 + padded_len;
    }
    return offset == cap_end && found;
}

static bool
ancp_record_peer(struct bbl_ancp_connection_ *connection, const uint8_t *packet,
                 uint32_t packet_len)
{
    if(packet_len < 44 || !ancp_has_topology_capability(packet, packet_len)) {
        return false;
    }
    uint8_t peer_p_flag = packet[28] & 0x0F;
    if(packet[6] == 0 || (packet[28] >> 4) > 1 ||
       (peer_p_flag != 1 && peer_p_flag != 2)) {
        return false;
    }
    memcpy(connection->peer_name, packet + 8, sizeof(connection->peer_name));
    connection->peer_port = ancp_get_u32(packet + 20);
    connection->peer_instance = ((uint32_t)packet[29] << 16) |
                                ((uint32_t)packet[30] << 8) | packet[31];
    connection->adjacency_timer = packet[6] > ANCP_ADJACENCY_TIMER ?
                                  packet[6] : ANCP_ADJACENCY_TIMER;
    connection->p_flag = 1;
    connection->last_rx = time(NULL);
    return connection->peer_instance != 0;
}

static bool
ancp_receiver_is_local(struct bbl_ancp_connection_ *connection, const uint8_t *packet)
{
    return memcmp(packet + 14, connection->config->interface->mac, ETH_ADDR_LEN) == 0 &&
           ancp_get_u32(packet + 24) == 0 &&
           (((uint32_t)packet[33] << 16) | ((uint32_t)packet[34] << 8) | packet[35]) ==
               connection->local_instance &&
           packet[32] == connection->partition_id;
}

static bool
ancp_peer_matches(struct bbl_ancp_connection_ *connection, const uint8_t *packet)
{
    uint32_t sender_instance = ((uint32_t)packet[29] << 16) |
                               ((uint32_t)packet[30] << 8) | packet[31];
    return memcmp(connection->peer_name, packet + 8, sizeof(connection->peer_name)) == 0 &&
           connection->peer_port == ancp_get_u32(packet + 20) &&
           connection->peer_instance == sender_instance &&
           connection->partition_id == packet[32];
}

static bool
ancp_options_match(struct bbl_ancp_connection_ *connection, const uint8_t *packet)
{
    return packet[4] == ANCP_VERSION &&
           packet[6] == connection->adjacency_timer &&
           (packet[28] >> 4) == 0 &&
           (packet[28] & 0x0F) == connection->p_flag &&
           packet[32] == connection->partition_id &&
           packet[36] == 0;
}

static void
ancp_connection_announce_sessions(struct bbl_ancp_connection_ *connection)
{
    uint32_t i;
    for(i = 0; i < g_ctx->sessions; i++) {
        bbl_session_s *session = &g_ctx->session_list[i];
        if(session->ancp_config == connection->config &&
           session->session_state == BBL_ESTABLISHED && !session->ancp_port_up) {
            session->ancp_port_up = ancp_send_port_message(session, ANCP_MESSAGE_PORT_UP);
        }
    }
}

static void
ancp_connection_set_down(struct bbl_ancp_connection_ *connection)
{
    uint32_t i;
    for(i = 0; i < g_ctx->sessions; i++) {
        bbl_session_s *session = &g_ctx->session_list[i];
        if(session->ancp_config == connection->config) {
            session->ancp_port_up = false;
        }
    }
}

static void
ancp_connection_drop(struct bbl_ancp_connection_ *connection)
{
    bbl_tcp_ctx_s *tcpc = connection->tcpc;
    connection->tcpc = NULL;
    connection->state = ANCP_STATE_IDLE;
    connection->rx_len = 0;
    connection->rx_expected = 0;
    connection->reconnect_at = time(NULL) + ANCP_RECONNECT_SECONDS;
    ancp_connection_set_down(connection);
    if(tcpc) {
        bbl_tcp_ctx_free_deferred(tcpc);
    }
}

static bool
ancp_send_rstack(struct bbl_ancp_connection_ *connection, const uint8_t *packet)
{
    uint8_t buf[44] = {0};

    ancp_put_u16(buf, ANCP_PROTOCOL_ID);
    ancp_put_u16(buf + 2, sizeof(buf) - 4);
    buf[4] = ANCP_VERSION;
    buf[5] = ANCP_MESSAGE_ADJACENCY;
    buf[6] = connection->adjacency_timer;
    buf[7] = ANCP_CODE_RSTACK;
    memcpy(buf + 8, packet + 14, 6);
    memcpy(buf + 14, packet + 8, 6);
    ancp_put_u32(buf + 20, ancp_get_u32(packet + 24));
    ancp_put_u32(buf + 24, ancp_get_u32(packet + 20));
    buf[28] = connection->p_flag;
    memcpy(buf + 29, packet + 33, 3);
    buf[32] = connection->partition_id;
    memcpy(buf + 33, packet + 29, 3);
    buf[37] = 1;
    ancp_put_u16(buf + 38, 4);
    ancp_put_u16(buf + 40, ANCP_CAPABILITY_DSL_TOPOLOGY);

    return ancp_send_packet(connection, buf, sizeof(buf));
}

static bool
ancp_send_rstack_from_state(struct bbl_ancp_connection_ *connection)
{
    uint8_t packet[44] = {0};
    bbl_network_interface_s *interface = connection->config->interface;

    memcpy(packet + 8, interface->mac, ETH_ADDR_LEN);
    memcpy(packet + 14, connection->peer_name, sizeof(connection->peer_name));
    ancp_put_u32(packet + 24, connection->peer_port);
    packet[29] = connection->local_instance >> 16;
    packet[30] = connection->local_instance >> 8;
    packet[31] = connection->local_instance;
    packet[32] = connection->partition_id;
    packet[33] = connection->peer_instance >> 16;
    packet[34] = connection->peer_instance >> 8;
    packet[35] = connection->peer_instance;

    return ancp_send_rstack(connection, packet);
}

static void
ancp_reset_link(struct bbl_ancp_connection_ *connection)
{
    connection->local_instance = (connection->local_instance + 1) & 0x00FFFFFF;
    if(!connection->local_instance) {
        connection->local_instance = 1;
    }
    connection->peer_instance = 0;
    connection->peer_port = 0;
    memset(connection->peer_name, 0, sizeof(connection->peer_name));
    connection->adjacency_timer = ANCP_ADJACENCY_TIMER;
    connection->p_flag = 1;
    connection->state = ANCP_STATE_SYNSENT;
    ancp_connection_set_down(connection);
    if(!ancp_send_adjacency(connection, ANCP_CODE_SYN)) {
        ancp_connection_drop(connection);
    }
}

static void
ancp_handle_adjacency(struct bbl_ancp_connection_ *connection,
                      const uint8_t *packet, uint32_t packet_len)
{
    uint8_t code;
    bool m_flag;
    bool peer_matches;
    bool local_matches;
    uint32_t sender_instance;

    if(packet_len < 44 || packet[5] != ANCP_MESSAGE_ADJACENCY) {
        LOG(ERROR, "ANCP session %u received malformed adjacency message\n",
            connection->config->ancp_session_id);
        ancp_connection_drop(connection);
        return;
    }
    if(packet[4] != ANCP_VERSION) {
        return;
    }
    code = packet[7] & 0x7F;
    m_flag = (packet[7] & 0x80) != 0;
    if(code == ANCP_CODE_SYN && !m_flag) {
        return;
    }
    if(code != ANCP_CODE_RSTACK && !ancp_has_topology_capability(packet, packet_len)) {
        LOG(ERROR, "ANCP session %u peer did not advertise DSL topology discovery\n",
            connection->config->ancp_session_id);
        ancp_connection_drop(connection);
        return;
    }

    peer_matches = ancp_peer_matches(connection, packet);
    local_matches = ancp_receiver_is_local(connection, packet);
    sender_instance = ((uint32_t)packet[29] << 16) |
                      ((uint32_t)packet[30] << 8) | packet[31];

    if(code == ANCP_CODE_RSTACK) {
        if(connection->state != ANCP_STATE_SYNSENT &&
           sender_instance == connection->peer_instance && local_matches) {
            ancp_reset_link(connection);
        }
        return;
    }
    if(code == ANCP_CODE_SYN) {
        if(connection->state == ANCP_STATE_ESTABLISHED) {
            connection->last_rx = time(NULL);
            if(!ancp_send_adjacency(connection, ANCP_CODE_ACK)) {
                ancp_connection_drop(connection);
            }
            return;
        }
        if(!ancp_record_peer(connection, packet, packet_len)) {
            LOG(ERROR, "ANCP session %u peer did not advertise DSL topology discovery\n",
                connection->config->ancp_session_id);
            ancp_connection_drop(connection);
            return;
        }
        connection->state = ANCP_STATE_SYNRCVD;
        if(!ancp_send_adjacency(connection, ANCP_CODE_SYNACK)) {
            ancp_connection_drop(connection);
        }
        return;
    }
    if(code == ANCP_CODE_SYNACK) {
        if(connection->state != ANCP_STATE_SYNSENT &&
           connection->state != ANCP_STATE_SYNRCVD &&
           connection->state != ANCP_STATE_ESTABLISHED) {
            return;
        }
        if(!local_matches ||
           (connection->state != ANCP_STATE_SYNSENT &&
            (!peer_matches || !ancp_options_match(connection, packet))) ||
           (connection->state == ANCP_STATE_SYNSENT &&
            (packet[28] >> 4) != 0)) {
            LOG(ERROR, "ANCP session %u received inconsistent SYNACK\n",
                connection->config->ancp_session_id);
            if(!ancp_send_rstack(connection, packet)) {
                ancp_connection_drop(connection);
            }
            return;
        }
        if(connection->state == ANCP_STATE_SYNSENT) {
            if(!ancp_record_peer(connection, packet, packet_len) ||
               !ancp_options_match(connection, packet)) {
                LOG(ERROR, "ANCP session %u peer did not advertise DSL topology discovery\n",
                    connection->config->ancp_session_id);
                if(!ancp_send_rstack(connection, packet)) {
                    ancp_connection_drop(connection);
                }
                return;
            }
        }
        connection->last_rx = time(NULL);
        if(!ancp_send_adjacency(connection, ANCP_CODE_ACK)) {
            ancp_connection_drop(connection);
            return;
        }
        if(connection->state != ANCP_STATE_ESTABLISHED) {
            connection->state = ANCP_STATE_ESTABLISHED;
            LOG(INFO, "ANCP session %u adjacency established on %s\n",
                connection->config->ancp_session_id,
                connection->config->network_interface);
            ancp_connection_announce_sessions(connection);
        }
        return;
    }
    if(code == ANCP_CODE_ACK) {
        if(connection->state == ANCP_STATE_SYNSENT) {
            if(!ancp_send_rstack(connection, packet)) {
                ancp_connection_drop(connection);
            }
        } else if(connection->state == ANCP_STATE_SYNRCVD &&
                  peer_matches && local_matches &&
                  ancp_options_match(connection, packet)) {
            if(!ancp_send_adjacency(connection, ANCP_CODE_ACK)) {
                ancp_connection_drop(connection);
                return;
            }
            connection->last_rx = time(NULL);
            connection->state = ANCP_STATE_ESTABLISHED;
            LOG(INFO, "ANCP session %u adjacency established on %s\n",
                connection->config->ancp_session_id,
                connection->config->network_interface);
            ancp_connection_announce_sessions(connection);
        } else if(connection->state == ANCP_STATE_ESTABLISHED &&
                  peer_matches && local_matches &&
                  ancp_options_match(connection, packet)) {
            connection->last_rx = time(NULL);
            if(time(NULL) - connection->last_tx >=
               (connection->adjacency_timer + 9) / 10 &&
               !ancp_send_adjacency(connection, ANCP_CODE_ACK)) {
                ancp_connection_drop(connection);
            }
        } else if(connection->state == ANCP_STATE_SYNRCVD ||
                  connection->state == ANCP_STATE_ESTABLISHED) {
            if(!ancp_send_rstack(connection, packet)) {
                ancp_connection_drop(connection);
            }
        }
        return;
    }
    LOG(ERROR, "ANCP session %u received unknown adjacency code %u\n",
        connection->config->ancp_session_id, code);
}

static void
ancp_handle_packet(struct bbl_ancp_connection_ *connection,
                   const uint8_t *packet, uint32_t packet_len)
{
    if(packet_len < 8 || ancp_get_u16(packet) != ANCP_PROTOCOL_ID) {
        LOG(ERROR, "ANCP session %u received invalid TCP encapsulation\n",
            connection->config->ancp_session_id);
        ancp_connection_drop(connection);
        return;
    }
    if(packet[5] == ANCP_MESSAGE_ADJACENCY) {
        ancp_handle_adjacency(connection, packet, packet_len);
    } else if(connection->state != ANCP_STATE_ESTABLISHED) {
        LOG(ERROR, "ANCP session %u received non-adjacency message before synchronization\n",
            connection->config->ancp_session_id);
    } else {
        connection->last_rx = time(NULL);
    }
}

static void
ancp_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    struct bbl_ancp_connection_ *connection = arg;
    uint32_t copy_len;

    while(len && connection->tcpc) {
        if(connection->rx_expected == 0) {
            copy_len = 4 - connection->rx_len;
            if(copy_len > len) {
                copy_len = len;
            }
            memcpy(connection->rx_buffer + connection->rx_len, buf, copy_len);
            connection->rx_len += copy_len;
            buf += copy_len;
            len -= copy_len;
            if(connection->rx_len < 4) {
                continue;
            }
            if(ancp_get_u16(connection->rx_buffer) != ANCP_PROTOCOL_ID) {
                LOG(ERROR, "ANCP session %u received invalid protocol identifier\n",
                    connection->config->ancp_session_id);
                ancp_connection_drop(connection);
                return;
            }
            connection->rx_expected = ancp_get_u16(connection->rx_buffer + 2) + 4u;
            if(connection->rx_expected < 8 || connection->rx_expected > ANCP_MAX_MESSAGE) {
                LOG(ERROR, "ANCP session %u received invalid message length %u\n",
                    connection->config->ancp_session_id, connection->rx_expected);
                ancp_connection_drop(connection);
                return;
            }
        }

        copy_len = connection->rx_expected - connection->rx_len;
        if(copy_len > len) {
            copy_len = len;
        }
        memcpy(connection->rx_buffer + connection->rx_len, buf, copy_len);
        connection->rx_len += copy_len;
        buf += copy_len;
        len -= copy_len;

        if(connection->rx_len == connection->rx_expected) {
            uint32_t packet_len = connection->rx_len;
            connection->rx_len = 0;
            connection->rx_expected = 0;
            ancp_handle_packet(connection, connection->rx_buffer, packet_len);
        }
    }
}

static void
ancp_connected_cb(void *arg)
{
    struct bbl_ancp_connection_ *connection = arg;
    connection->state = ANCP_STATE_SYNSENT;
    connection->last_rx = time(NULL);
    if(!ancp_send_adjacency(connection, ANCP_CODE_SYN)) {
        ancp_connection_drop(connection);
    }
}

static void
ancp_error_cb(void *arg, err_t err)
{
    struct bbl_ancp_connection_ *connection = arg;
    UNUSED(err);
    ancp_connection_drop(connection);
}

static void
ancp_connect(struct bbl_ancp_connection_ *connection)
{
    bbl_ancp_config_s *config = connection->config;
    ipv4addr_t *source_address = config->source_address ?
                                 &config->source_address :
                                 &config->interface->ip.address;

    connection->reconnect_at = time(NULL) + ANCP_RECONNECT_SECONDS;
    connection->local_instance = (connection->local_instance + 1) & 0x00FFFFFF;
    if(!connection->local_instance) {
        connection->local_instance = 1;
    }
    connection->peer_instance = 0;
    connection->peer_port = 0;
    memset(connection->peer_name, 0, sizeof(connection->peer_name));
    connection->adjacency_timer = ANCP_ADJACENCY_TIMER;
    connection->p_flag = 1;
    connection->partition_id = 0;
    connection->tcpc = bbl_tcp_ipv4_connect(config->interface, source_address,
                                             &config->peer_address, config->port,
                                             0, 0, NULL);
    if(!connection->tcpc) {
        LOG(ERROR, "ANCP session %u TCP connect failed\n", config->ancp_session_id);
        return;
    }
    connection->tcpc->arg = connection;
    connection->tcpc->connected_cb = ancp_connected_cb;
    connection->tcpc->receive_cb = ancp_receive_cb;
    connection->tcpc->error_cb = ancp_error_cb;
    connection->state = ANCP_STATE_CONNECTING;
}

static void
ancp_timer_job(timer_s *timer)
{
    struct bbl_ancp_connection_ *connection = timer->data;
    time_t now = time(NULL);
    time_t interval = (connection->adjacency_timer + 9) / 10;

    if(!connection->tcpc) {
        if(now >= connection->reconnect_at) {
            ancp_connect(connection);
        }
        return;
    }
    if(connection->state == ANCP_STATE_ESTABLISHED &&
       now - connection->last_rx > 3 * interval) {
        LOG(ERROR, "ANCP session %u lost adjacency synchronization\n",
            connection->config->ancp_session_id);
        if(!ancp_send_rstack_from_state(connection)) {
            ancp_connection_drop(connection);
        } else {
            ancp_reset_link(connection);
        }
        return;
    }
    if(now - connection->last_tx < interval) {
        return;
    }
    if(connection->state == ANCP_STATE_SYNSENT) {
        if(!ancp_send_adjacency(connection, ANCP_CODE_SYN)) {
            ancp_connection_drop(connection);
        }
    } else if(connection->state == ANCP_STATE_SYNRCVD) {
        if(!ancp_send_adjacency(connection, ANCP_CODE_SYNACK)) {
            ancp_connection_drop(connection);
        }
    } else if(connection->state == ANCP_STATE_ESTABLISHED) {
        if(!ancp_send_adjacency(connection, ANCP_CODE_ACK)) {
            ancp_connection_drop(connection);
        }
    }
}

static bbl_ancp_config_s *
ancp_config_get(uint16_t ancp_session_id)
{
    bbl_ancp_config_s *config = g_ctx->config.ancp_config;
    while(config) {
        if(config->ancp_session_id == ancp_session_id) {
            return config;
        }
        config = config->next;
    }
    return NULL;
}

static bbl_access_line_profile_s *
ancp_profile_get(uint16_t profile_id)
{
    bbl_access_line_profile_s *profile = g_ctx->config.ancp_line_profile;
    while(profile) {
        if(profile->access_line_profile_id == profile_id) {
            return profile;
        }
        profile = profile->next;
    }
    return NULL;
}

bool
bbl_ancp_init(void)
{
    bbl_ancp_config_s *config = g_ctx->config.ancp_config;
    bbl_access_config_s *access_config;
    struct bbl_ancp_connection_ *connection;
    uint32_t local_instance;

    for(access_config = g_ctx->config.access_config;
        access_config;
        access_config = access_config->next) {
        if(!access_config->ancp_session_id) {
            if(access_config->ancp_line_profile_id) {
                LOG(ERROR, "ANCP line profile configured without ancp-session-id\n");
                return false;
            }
            continue;
        }
        if(access_config->access_type != ACCESS_TYPE_IPOE ||
           !access_config->agent_circuit_id ||
           !access_config->ancp_line_profile_id) {
            LOG(ERROR, "ANCP requires IPoE, agent-circuit-id and ancp-line-profile-id on each access entry\n");
            return false;
        }
        access_config->ancp_config = ancp_config_get(access_config->ancp_session_id);
        access_config->ancp_line_profile =
            ancp_profile_get(access_config->ancp_line_profile_id);
        if(!access_config->ancp_config || !access_config->ancp_line_profile) {
            LOG(ERROR, "ANCP access entry references an unknown session or line profile\n");
            return false;
        }
    }

    for(; config; config = config->next) {
        bbl_ancp_config_s *other;
        for(other = g_ctx->config.ancp_config; other != config; other = other->next) {
            if(other->ancp_session_id == config->ancp_session_id) {
                LOG(ERROR, "Duplicate ANCP session ID %u\n", config->ancp_session_id);
                return false;
            }
        }
        config->interface = bbl_network_interface_get(config->network_interface);
        if(!config->interface || !config->interface->ip.address) {
            LOG(ERROR, "ANCP session %u requires an IPv4 network interface with a static address\n",
                config->ancp_session_id);
            return false;
        }
        if(!config->source_address) {
            config->source_address = config->interface->ip.address;
        }
        local_instance = ((uint32_t)time(NULL) ^ (uint32_t)getpid() ^
                          (uint32_t)(uintptr_t)config) & 0x00FFFFFF;
        if(!local_instance) {
            local_instance = 1;
        }
        connection = calloc(1, sizeof(*connection));
        if(!connection) {
            LOG(ERROR, "Failed to allocate ANCP connection %u\n", config->ancp_session_id);
            return false;
        }
        connection->config = config;
        connection->local_instance = local_instance;
        connection->adjacency_timer = ANCP_ADJACENCY_TIMER;
        connection->p_flag = 1;
        connection->reconnect_at = time(NULL);
        config->connection = connection;
        timer_add_periodic(&g_ctx->timer_root, &connection->timer, "ANCP",
                           0, SEC, connection, ancp_timer_job);
    }
    return true;
}

void
bbl_ancp_session_state_change(bbl_session_s *session, session_state_t old_state,
                              session_state_t new_state)
{
    if(!session->ancp_config) {
        return;
    }
    if(new_state == BBL_ESTABLISHED && !session->ancp_port_up) {
        session->ancp_port_up = ancp_send_port_message(session, ANCP_MESSAGE_PORT_UP);
    } else if(old_state == BBL_ESTABLISHED && new_state != BBL_ESTABLISHED &&
              session->ancp_port_up) {
        ancp_send_port_message(session, ANCP_MESSAGE_PORT_DOWN);
        session->ancp_port_up = false;
    }
}
