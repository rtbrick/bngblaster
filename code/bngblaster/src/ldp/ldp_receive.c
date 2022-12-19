
/*
 * BNG Blaster (BBL) - LDP Receive Functions
 *
 * Christian Giese, November 2022
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

struct keyval_ ldp_status_names[] = {
    { LDP_STATUS_SUCCESS,                   "success" },
    { LDP_STATUS_BAD_IDENTIFIER,            "bad LDP identifier" },
    { LDP_STATUS_BAD_VERSION,               "bad protocol version" },
    { LDP_STATUS_BAD_PDU_LEN,               "bad PDU length" },
    { LDP_STATUS_UNKNOWN_MSG_TYPE,          "unknown message type" },
    { LDP_STATUS_BAD_MSG_LEN,               "bad message length" },
    { LDP_STATUS_UNKNOWN_TLV_TYPE,          "unknown TLV type" },
    { LDP_STATUS_BAD_TLV_LEN,               "bad TLV length" },
    { LDP_STATUS_BAD_TLV_VALUE,             "bad TLV value" },
    { LDP_STATUS_HOLD_TIMER_EXPIRED,        "hold timer expired" },
    { LDP_STATUS_KEEPALIVE_TIMER_EXPIRED,   "keepalive timer expired" },
    { LDP_STATUS_SHUTDOWN,                  "shutdown" },
    { LDP_STATUS_INTERNAL_ERROR,            "internal error" },
    { 0, NULL}
};

static void 
ldp_decode_error(ldp_session_s *session)
{
    LOG(LDP, "LDP (%s - %s) invalid PDU received\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));

    session->decode_error = true;
    if(!session->error_code) {
        session->error_code = LDP_STATUS_INTERNAL_ERROR|LDP_STATUS_FATAL_ERROR;
    }
    ldp_session_close(session);
}

static bool
ldp_notification(ldp_session_s *session, uint8_t *start, uint16_t length)
{
    uint8_t *tlv_start = start;
    uint16_t tlv_type;
    uint16_t tlv_length;
    uint32_t status_code = UINT32_MAX;
    bool e_bit = false;
    bool f_bit = false;

    /* Read all TLV's. */
    while(length >= LDP_TLV_LEN_MIN) {
        tlv_type = read_be_uint(tlv_start, 2) & 0x3FFF;
        tlv_length = read_be_uint(tlv_start+2, 2);
        if(tlv_length+LDP_TLV_LEN_MIN > length) {
            return false;
        }
        switch(tlv_type) {
            case LDP_TLV_TYPE_STATUS:
                if(tlv_length < LDP_STATUS_LEN_MIN) {
                    return false;
                }
                status_code = read_be_uint(tlv_start+LDP_TLV_LEN_MIN, 4);
                e_bit = status_code & LDP_STATUS_FATAL_ERROR;
                f_bit = status_code & LDP_STATUS_FORWARD;
                status_code &= 0x3FFFFFFF;
                break;
            default:
                break;
        }
        length -= (tlv_length+LDP_TLV_LEN_MIN);
        tlv_start += (tlv_length+LDP_TLV_LEN_MIN);
    }

    LOG(LDP, "LDP (%s - %s) received %s notification with status code %u (%s)%s\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
        (e_bit ? "fatal error" : "advisory"),
        status_code, keyval_get_key(ldp_status_names, status_code), 
        (f_bit ? " wit forwarding bit set" : ""));

    return true;
}

static bool
ldp_label_mapping(ldp_session_s *session, uint8_t *start, uint16_t length)
{
    uint8_t *tlv_start = start;
    uint16_t tlv_type;
    uint16_t tlv_length;

    uint8_t prefix_length;
    uint8_t prefix_bytes;

    uint8_t *fec_element;
    uint16_t fec_length;
    uint16_t fec_afi;
    uint32_t label;

    ipv4_prefix ipv4prefix;

    /* Read all TLV's. */
    while(length >= LDP_TLV_LEN_MIN) {
        tlv_type = read_be_uint(tlv_start, 2) & 0x3FFF;
        tlv_length = read_be_uint(tlv_start+2, 2);
        if(tlv_length+LDP_TLV_LEN_MIN > length) {
            return false;
        }
        switch(tlv_type) {
            case LDP_TLV_TYPE_FEC:
                if(tlv_length < LDP_FEC_LEN_MIN) {
                    return false;
                }
                fec_element = tlv_start+LDP_TLV_LEN_MIN;
                fec_length = tlv_length;
                if(*fec_element != LDP_FEC_ELEMENT_TYPE_PREFIX) {
                    return false;
                }
                break;
            case LDP_TLV_TYPE_GENERIC_LABEL:
                if(tlv_length < sizeof(label)) {
                    return false;
                }
                label = read_be_uint(tlv_start+LDP_TLV_LEN_MIN, sizeof(label));
                break;
            default:
                break;
        }
        length -= (tlv_length+LDP_TLV_LEN_MIN);
        tlv_start += (tlv_length+LDP_TLV_LEN_MIN);
    }

    /* Read all FEC elements. */
    while(fec_length >= LDP_FEC_LEN_MIN) {
        fec_afi = read_be_uint(fec_element+1, 2);
        prefix_length = *(fec_element+3);
        prefix_bytes = BITS_TO_BYTES(prefix_length);
        if(prefix_bytes+LDP_FEC_LEN_MIN > fec_length) {
            return false;
        }
        if(fec_afi == IANA_AFI_IPV4) {
            ipv4prefix.len = prefix_length;
            ipv4prefix.address = 0;
            memcpy((uint8_t*)&ipv4prefix.address, fec_element+LDP_FEC_LEN_MIN, prefix_bytes);
            LOG(DEBUG, "LDP (%s - %s) add %s via label %u\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
                format_ipv4_prefix(&ipv4prefix), label);

            ldb_db_add_ipv4(session, &ipv4prefix, label);
        }
        fec_length -= (prefix_bytes+LDP_FEC_LEN_MIN);
        fec_element += (prefix_bytes+LDP_FEC_LEN_MIN);
    }
    return true;
}

static bool
ldp_initialization(ldp_session_s *session, uint8_t *start, uint16_t length)
{
    uint8_t *tlv_start = start;
    uint16_t tlv_type;
    uint16_t tlv_length;

    while(length > LDP_TLV_LEN_MIN) {
        tlv_type = read_be_uint(tlv_start, 2) & 0x3FFF;
        tlv_length = read_be_uint(tlv_start+2, 2);
        if(tlv_length+LDP_TLV_LEN_MIN > length) {
            return false;
        }
        switch(tlv_type) {
            case LDP_TLV_TYPE_COMMON_SESSION_PARAMETERS:
                if(tlv_length < 14) {
                    return false;
                }
                session->peer.keepalive_time = read_be_uint(tlv_start+6, 2);
                session->peer.max_pdu_len = read_be_uint(tlv_start+10, 2);
                break;
            default:
                break;
        }
        length -= (tlv_length+LDP_TLV_LEN_MIN);
        tlv_start += (tlv_length+LDP_TLV_LEN_MIN);
    }
    ldp_session_fsm(session, LDP_EVENT_RX_INITIALIZED);
    return true;
}

/*
 * When there is only little data left and
 * the buffer start is close to buffer end,
 * then 'rebase' the buffer by copying
 * the tail data to the buffer head.
 */
static void
ldp_rebase_read_buffer(io_buffer_t *buffer)
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
    uint32_t msg_id;

    while(!session->decode_error) {
        pdu_start = buffer->data+buffer->start_idx;
        size = buffer->idx - buffer->start_idx;

        /* Minimum PDU size */
        if(size < LDP_MIN_PDU_LEN) {
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
            ldp_decode_error(session);
            return;
        }

        /* Full message on the wire to consume? */
        length = pdu_length+4;
        if(length > size) {
            break;
        }
        session->stats.pdu_rx++;

        /* Read LDP Identifier. */
        lsr_id = *(uint32_t*)(pdu_start+4);
        label_space_id = read_be_uint(pdu_start+8, 2);

        if(lsr_id != session->peer.lsr_id || 
           label_space_id != session->peer.label_space_id) {
            ldp_decode_error(session);
            return;
        }

        pdu_length -= LDP_IDENTIFIER_LEN;
        msg_start = pdu_start+LDP_MIN_PDU_LEN;
        while(pdu_length >= LDP_MIN_MSG_LEN) {
            session->stats.message_rx++;

            msg_type = read_be_uint(msg_start, 2);
            msg_length = read_be_uint(msg_start+2, 2);
            msg_id = read_be_uint(msg_start+4, 4);
            if(msg_length+4 > pdu_length) {
                ldp_decode_error(session);
                return;
            }

            LOG(DEBUG, "LDP (%s - %s) read %s message (%u)\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
                keyval_get_key(ldp_msg_names, msg_type), msg_id);

            ldp_session_restart_keepalive_timeout(session);

            switch(msg_type) {
                case LDP_MESSAGE_TYPE_NOTIFICATION:
                    if(!ldp_notification(session, msg_start+8, msg_length-4)) {
                        ldp_decode_error(session);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_INITIALIZATION:
                    if(!ldp_initialization(session, msg_start+8, msg_length-4)) {
                        ldp_decode_error(session);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_KEEPALIVE:
                    session->stats.keepalive_rx++;
                    ldp_session_fsm(session, LDP_EVENT_RX_KEEPALIVE);
                    break;
                case LDP_MESSAGE_TYPE_LABEL_MAPPING:
                    if(!ldp_label_mapping(session, msg_start+8, msg_length-4)) {
                        ldp_decode_error(session);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_ADDRESS:
                case LDP_MESSAGE_TYPE_ADDRESS_WITHDRAW:
                case LDP_MESSAGE_TYPE_LABEL_REQUEST:
                case LDP_MESSAGE_TYPE_LABEL_WITHDRAW:
                case LDP_MESSAGE_TYPE_LABEL_RELEASE:
                case LDP_MESSAGE_TYPE_ABORT_REQUEST:
                    break;
                default:
                    break;
            }
            pdu_length -= (msg_length+4);
            msg_start += (msg_length+4);
        }

        /* Progress pointer to next LDP PDU. */
        buffer->start_idx += length;
    }
    ldp_rebase_read_buffer(buffer);
}

void 
ldp_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    ldp_session_s *session = (ldp_session_s*)arg;
    io_buffer_t *buffer = &session->read_buf;

    if(buf) {
        if(buffer->idx+len > buffer->size) {
            LOG(ERROR, "LDP (%s - %s) receive error (read buffer exhausted)\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
            if(!session->error_code) {
                session->error_code = LDP_STATUS_INTERNAL_ERROR|LDP_STATUS_FATAL_ERROR;
            }
            ldp_session_close(session);
            return;
        }
        memcpy(buffer->data+buffer->idx, buf, len);
        buffer->idx+=len;
    } else {
        ldp_read(session);
    }
}