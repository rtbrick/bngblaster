/*
 * BNG Blaster (BBL) - LDP Protocol Messages
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

static void
ldp_pdu_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->pdu_start_idx) {
        /* update PDU length */
        len = buffer->idx - buffer->start_idx;
        write_be_uint(buffer->data+session->pdu_start_idx-2, 2, len); 
        session->pdu_start_idx = 0;
    }
}

static bool
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
        len = buffer->idx - buffer->start_idx;
        write_be_uint(buffer->data+session->msg_start_idx-2, 2, len); 
        session->msg_start_idx = 0;
    }
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
    push_be_uint(buffer, session->message_id++, 4);
    return true;
}

static void
ldp_tlv_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->tlv_start_idx) {
        /* update length */
        len = buffer->idx - buffer->start_idx;
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
    push_be_uint(buffer, session->message_id++, 4);
    return true;
}

void
ldp_push_init_message(ldp_session_s *session, bool keepalive)
{
    io_buffer_t *buffer = &session->write_buf;
 
    ldp_pdu_init(session);
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
    if(!keepalive) {
        ldp_msg_init(session, LDP_MESSAGE_TYPE_KEEPALIVE);
        ldp_msg_close(session);
    }
    ldp_pdu_close(session);
}

void
ldp_push_keepalive_message(ldp_session_s *session)
{
    ldp_pdu_init(session);
    ldp_msg_init(session, LDP_MESSAGE_TYPE_KEEPALIVE);
    ldp_msg_close(session);
    ldp_pdu_close(session);
}

void
ldp_push_notification_message(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;

    ldp_pdu_init(session);
    ldp_msg_init(session, LDP_MESSAGE_TYPE_NOTIFICATION);
    ldp_tlv_init(session, LDP_TLV_TYPE_STATUS);
    push_be_uint(buffer, 4, session->error_code);
    push_be_uint(buffer, 4, 0);
    push_be_uint(buffer, 2, 0);
    ldp_tlv_close(session);
    ldp_msg_close(session);
    ldp_pdu_close(session);
}