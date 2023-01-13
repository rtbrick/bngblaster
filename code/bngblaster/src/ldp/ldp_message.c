/*
 * BNG Blaster (BBL) - LDP Protocol Messages
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

void
ldp_pdu_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->pdu_start_idx) {
        /* update PDU length */
        len = buffer->idx - session->pdu_start_idx;
        write_be_uint(buffer->data+session->pdu_start_idx-2, 2, len); 
        session->pdu_start_idx = 0;
    }
    session->stats.pdu_tx++;
}

bool
ldp_pdu_init(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;

    if(session->pdu_start_idx) {
        ldp_pdu_close(session);
    }

    if(IO_BUF_REMAINING(buffer) < LDP_MIN_PDU_LEN) {
        return false;
    }

    push_be_uint(buffer, 2, 1); /* PDU Version */
    push_be_uint(buffer, 2, 0); /* PDU Length */
    session->pdu_start_idx = buffer->idx;
    push_data(buffer, (uint8_t*)&session->local.lsr_id, 4);
    push_be_uint(buffer, 2, session->local.label_space_id);
    return true;
}

static void
ldp_msg_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->msg_start_idx) {
        /* update message length */
        len = buffer->idx - session->msg_start_idx;
        write_be_uint(buffer->data+session->msg_start_idx-2, 2, len); 
        session->msg_start_idx = 0;
    }
    session->stats.message_tx++;
}

static bool
ldp_msg_init(ldp_session_s *session, uint16_t type)
{
    io_buffer_t *buffer = &session->write_buf;

    if(session->msg_start_idx) {
        ldp_msg_close(session);
    }

    if(IO_BUF_REMAINING(buffer) < LDP_MIN_MSG_LEN) {
        return false;
    }

    push_be_uint(buffer, 2, type); /* Type */
    push_be_uint(buffer, 2, 0); /* Length */
    session->msg_start_idx = buffer->idx;
    push_be_uint(buffer, 4, session->message_id++);
    return true;
}

static void
ldp_tlv_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->tlv_start_idx) {
        /* update length */
        len = buffer->idx - session->tlv_start_idx;
        write_be_uint(buffer->data+session->tlv_start_idx-2, 2, len); 
        session->tlv_start_idx = 0;
    }
}

static bool
ldp_tlv_init(ldp_session_s *session, uint16_t type)
{
    io_buffer_t *buffer = &session->write_buf;

    if(session->tlv_start_idx) {
        ldp_tlv_close(session);
    }

    if(IO_BUF_REMAINING(buffer) < LDP_MIN_TLV_LEN) {
        return false;
    }

    push_be_uint(buffer, 2, type); /* Type */
    push_be_uint(buffer, 2, 0); /* Length */
    session->tlv_start_idx = buffer->idx;
    return true;
}

void
ldp_push_init_message(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    ldp_msg_init(session, LDP_MESSAGE_TYPE_INITIALIZATION);
    ldp_tlv_init(session, LDP_TLV_TYPE_COMMON_SESSION_PARAMETERS);
    push_be_uint(buffer, 2, 1);
    push_be_uint(buffer, 2, session->local.keepalive_time);
    push_be_uint(buffer, 2, 0);
    push_be_uint(buffer, 2, LDP_MAX_PDU_LEN_INIT);
    push_data(buffer, (uint8_t*)&session->peer.lsr_id, 4);
    push_be_uint(buffer, 2, session->peer.label_space_id);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

void
ldp_push_keepalive_message(ldp_session_s *session)
{
    ldp_msg_init(session, LDP_MESSAGE_TYPE_KEEPALIVE);
    ldp_msg_close(session);
    session->stats.keepalive_tx++;
}

void
ldp_push_notification_message(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    ldp_msg_init(session, LDP_MESSAGE_TYPE_NOTIFICATION);
    ldp_tlv_init(session, LDP_TLV_TYPE_STATUS);
    push_be_uint(buffer, 4, session->error_code);
    push_be_uint(buffer, 4, 0);
    push_be_uint(buffer, 2, 0);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

void
ldp_push_label_mapping_message(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label)
{
    io_buffer_t *buffer = &session->write_buf;
    uint8_t prefix_bytes = BITS_TO_BYTES(prefix->len);

    ldp_msg_init(session, LDP_MESSAGE_TYPE_LABEL_MAPPING);
    ldp_tlv_init(session, LDP_TLV_TYPE_FEC);
    push_be_uint(buffer, 1, 2); /* Prefix FEC */
    push_be_uint(buffer, 2, 1); /* IPv4 */
    push_be_uint(buffer, 1, prefix->len); /* IPv4 */
    push_data(buffer, (uint8_t*)&prefix->address, prefix_bytes);
    ldp_tlv_close(session);
    ldp_tlv_init(session, LDP_TLV_TYPE_GENERIC_LABEL);
    push_be_uint(buffer, 4, label);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

void
ldp_push_self_message(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    ldp_adjacency_s *adjacency = session->instance->adjacencies;
    uint32_t lsr_id = session->instance->config->lsr_id;
    uint32_t local_ipv4 = session->local.ipv4_address;
    uint32_t ipv4;

    uint8_t prefix_len;
    uint8_t prefix_bytes;

    ldp_msg_init(session, LDP_MESSAGE_TYPE_ADDRESS);
    ldp_tlv_init(session, LDP_TLV_TYPE_ADDRESS_LIST);
    push_be_uint(buffer, 2, 1); /* IPv4 */
    push_data(buffer, (uint8_t*)&lsr_id, 4);
    if(lsr_id != local_ipv4) {
        push_data(buffer, (uint8_t*)&local_ipv4, 4);
    }
    while(adjacency) {
        ipv4 = adjacency->interface->ip.address;
        if(ipv4 && ipv4 != lsr_id && ipv4 != local_ipv4) {
            push_data(buffer, (uint8_t*)&adjacency->interface->ip.address, 4);
        }
        adjacency = adjacency->next;
    }
    ldp_tlv_close(session);
    ldp_msg_close(session);

    ldp_msg_init(session, LDP_MESSAGE_TYPE_LABEL_MAPPING);
    ldp_tlv_init(session, LDP_TLV_TYPE_FEC);
    push_be_uint(buffer, 1, LDP_FEC_ELEMENT_TYPE_PREFIX);
    push_be_uint(buffer, 2, IANA_AFI_IPV4);
    push_be_uint(buffer, 1, 32);
    push_data(buffer, (uint8_t*)&lsr_id, 4);
    adjacency = session->instance->adjacencies;
    while(adjacency) {
        ipv4 = adjacency->interface->ip.address;
        prefix_len = adjacency->interface->ip.len; 
        prefix_bytes = BITS_TO_BYTES(prefix_len);
        push_be_uint(buffer, 1, LDP_FEC_ELEMENT_TYPE_PREFIX);
        push_be_uint(buffer, 2, IANA_AFI_IPV4);
        push_be_uint(buffer, 1, prefix_len);
        push_data(buffer, (uint8_t*)&adjacency->interface->ip.address, prefix_bytes);
        adjacency = adjacency->next;
    }
    ldp_tlv_close(session);
    ldp_tlv_init(session, LDP_TLV_TYPE_GENERIC_LABEL);
    push_be_uint(buffer, 4, 3); /* Implicit NULL Label */
    ldp_tlv_close(session);
    ldp_msg_close(session);
}