
/*
 * BNG Blaster (BBL) - LDP Message Receive Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

struct keyval_ ldp_msg_names[] = {
    { LDP_MESSAGE_TYPE_NOTIFICATION,        "notification" },
    { LDP_MESSAGE_TYPE_HELLO,               "hello" },
    { LDP_MESSAGE_TYPE_INITIALIZATION,      "initialization" },
    { LDP_MESSAGE_TYPE_KEEPALIVE,           "keepalive" },
    { LDP_MESSAGE_TYPE_ADDRESS,             "address" },
    { LDP_MESSAGE_TYPE_ADDRESS_WITHDRAW,    "address-withdraw" },
    { LDP_MESSAGE_TYPE_LABEL_MAPPING,       "label-mapping" },
    { LDP_MESSAGE_TYPE_LABEL_REQUEST,       "label-request" },
    { LDP_MESSAGE_TYPE_LABEL_WITHDRAW,      "label-withdraw" },
    { LDP_MESSAGE_TYPE_LABEL_RELEASE,       "label-release" },
    { LDP_MESSAGE_TYPE_ABORT_REQUEST,       "abort-request" },
    { 0, NULL}
};

/*
 * When there is only little data left and
 * the buffer start is close to buffer end,
 * then 'rebase' the buffer by copying
 * the tail data to the buffer head.
 */
static void
ldp_rebase_buffer(io_buffer_t *buffer)
{
    uint32_t size;

    size = buffer->idx - buffer->start_idx;
    if(size) {
        /* Copy what is left to the buffer start. */
        memcpy(buffer->data, buffer->data+buffer->start_idx, size);
    }
    buffer->start_idx = 0;
    buffer->idx = size;
}

static void
ldp_read(ldp_session_s *session)
{
    uint32_t size;
    uint16_t length;

    io_buffer_t *buffer = &session->read_buf;

    uint32_t lsr_id;
    uint16_t label_space_id;

    uint8_t *pdu_start;
    uint16_t pdu_version;
    uint16_t pdu_length;

    uint8_t *msg_start;
    uint16_t msg_type;
    uint16_t msg_length;

    while(true) {
        pdu_start = buffer->data+buffer->start_idx;
        size = buffer->idx - buffer->start_idx;

        /* Minimum PDU size */
        if(size < 4) {
            break;
        }

        pdu_version = read_be_uint(pdu_start, 2);
        pdu_length  = read_be_uint(pdu_start+2, 2);

        /* The PDU length is defined as two octet integer specifying 
         * the total length of the PDU in octets, excluding the version 
         * and PDU length fields. */

        if(pdu_version != 1 || 
           pdu_length < LDP_IDENTIFIER_LEN || 
           pdu_length > session->max_pdu_len) {
            //ldp_decode_error(session);
            break;
        }

        length = pdu_length+4;

        /* Full message on the wire to consume? */
        if(length > size) {
            break;
        }

        /* Read LDP Identifier. */
        lsr_id = read_be_uint(pdu_start+4, 4);
        label_space_id = read_be_uint(pdu_start+8, 2);

        if(lsr_id != session->peer.lsr_id || 
           label_space_id != session->peer.label_space_id) {
            /* TODO: INVALID MESSAGE!!!! */
            break;
        }

        pdu_length -= LDP_IDENTIFIER_LEN;
        msg_start = pdu_start+10;
        while(pdu_length >= 4) {
            msg_type = read_be_uint(msg_start, 2);
            msg_length = read_be_uint(msg_start+2, 2);

            UNUSED(msg_length);

            LOG(DEBUG, "LDP (%s - %s) read %s message\n",
                format_ipv4_address(&session->local.ipv4_address),
                format_ipv4_address(&session->peer.ipv4_address),
                keyval_get_key(ldp_msg_names, msg_type));

            session->stats.message_rx++;
            switch(msg_type) {
                case LDP_MESSAGE_TYPE_NOTIFICATION:
                    break;
                case LDP_MESSAGE_TYPE_INITIALIZATION:
                    break;
                case LDP_MESSAGE_TYPE_KEEPALIVE:
                    session->stats.keepalive_rx++;
                    break;
                case LDP_MESSAGE_TYPE_ADDRESS:
                case LDP_MESSAGE_TYPE_ADDRESS_WITHDRAW:
                case LDP_MESSAGE_TYPE_LABEL_MAPPING:
                case LDP_MESSAGE_TYPE_LABEL_REQUEST:
                case LDP_MESSAGE_TYPE_LABEL_WITHDRAW:
                case LDP_MESSAGE_TYPE_LABEL_RELEASE:
                case LDP_MESSAGE_TYPE_ABORT_REQUEST:
                    break;
                default:
                    break;
            }
        }

        /* Reset hold timer */
        //ldp_restart_hold_timer(session, session->instance->config->hold_time);

        /* Progress pointer to next LDP PDU. */
        buffer->start_idx += length;
    }
    ldp_rebase_buffer(buffer);
}

void 
ldp_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    ldp_session_s *session = (ldp_session_s*)arg;
    io_buffer_t *buffer = &session->read_buf;
    if(buf) {
        if(buffer->idx+len > buffer->size) {
            LOG(ERROR, "LDP (%s - %s) receive error (read buffer exhausted)\n",
                format_ipv4_address(&session->local.ipv4_address),
                format_ipv4_address(&session->peer.ipv4_address));

#if 0
            if(!session->status_code) {
                peer->status_code = 0x00000019; /* Cease */
                session->error_subcode = 8; /* Out of resources */
            }
#endif
            //ldp_session_close(session);
            return;
        }
        memcpy(buffer->data+buffer->idx, buf, len);
        buffer->idx+=len;
    } else {
        ldp_read(session);
    }
}

