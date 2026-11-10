
/*
 * BNG Blaster (BBL) - LDP Receive Functions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
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
    { LDP_STATUS_MISSING_MSG_PARAMS,        "missing message parameters" },
    { LDP_STATUS_SESSION_REJECTED_NO_HELLO, "session rejected/no hello" },
    { LDP_STATUS_INTERNAL_ERROR,            "internal error" },
    { 0, NULL}
};

/**
 * Close the session with a fatal error notification, the status
 * code is kept if already set by the decoder (RFC 5036 section 3.9).
 */
static void 
ldp_fatal_error(ldp_session_s *session, const char* message, uint32_t status_code)
{
    LOG(LDP, "LDP (%s - %s) %s\n",
        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
        message);

    session->decode_error = true;
    if(!session->error_code) {
        session->error_code = status_code|LDP_STATUS_FATAL_ERROR;
    }
    ldp_session_close(session);
}

/* Messages are accepted from initialization until the session closes. */
static bool
ldp_session_receiving(ldp_session_s *session)
{
    return session->state >= LDP_INITIALIZED && session->state <= LDP_OPERATIONAL;
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
        (f_bit ? " with forwarding bit set" : ""));

    if(e_bit) {
        /* The session is closed without notification (RFC 5036 section 3.5.1). */
        ldp_session_close_received(session);
    }
    return true;
}

/*
 * Label mapping or label withdraw message (RFC 5036 section 3.5.7 and 3.5.10).
 * The label TLV is optional for label withdraw messages, where all labels of
 * the FEC are withdrawn if not present. A wildcard FEC withdraws all labels
 * learned from the session.
 */
static bool
ldp_label_message(ldp_session_s *session, uint8_t *start, uint16_t length, bool withdraw)
{
    uint8_t *tlv_start = start;
    uint16_t tlv_type = 0;
    uint16_t tlv_length = 0;

    uint8_t prefix_length = 0;
    uint8_t prefix_bytes = 0;

    uint8_t *fec_element = NULL;
    uint16_t fec_length = 0;
    uint16_t fec_afi = 0;
    uint32_t label = 0;
    bool label_present = false;

    ipv4_prefix ipv4prefix;
    ipv6_prefix ipv6prefix;

    /* Read all TLV's. */
    while(length >= LDP_TLV_LEN_MIN) {
        tlv_type = read_be_uint(tlv_start, 2) & 0x3FFF;
        tlv_length = read_be_uint(tlv_start+2, 2);
        if(tlv_length+LDP_TLV_LEN_MIN > length) {
            return false;
        }
        switch(tlv_type) {
            case LDP_TLV_TYPE_FEC:
                if(tlv_length < 1) {
                    return false;
                }
                fec_element = tlv_start+LDP_TLV_LEN_MIN;
                fec_length = tlv_length;
                /* The wildcard FEC element is the type only (RFC 5036 section 3.4.1.1). */
                if(*fec_element == LDP_FEC_ELEMENT_TYPE_WILDCARD) {
                    break;
                }
                if(*fec_element == LDP_FEC_ELEMENT_TYPE_PREFIX && tlv_length < LDP_FEC_LEN_MIN) {
                    return false;
                }
                if(*fec_element != LDP_FEC_ELEMENT_TYPE_PREFIX) {
                    /* Unknown FEC (e.g. PWid FEC 128 over targeted
                     * sessions) is not a fatal error (RFC 5036). */
                    LOG(LDP, "LDP (%s - %s) ignore label message with FEC element type %u\n",
                        ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                        ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
                        *fec_element);
                    return true;
                }
                break;
            case LDP_TLV_TYPE_GENERIC_LABEL:
                if(tlv_length < sizeof(label)) {
                    return false;
                }
                label = read_be_uint(tlv_start+LDP_TLV_LEN_MIN, sizeof(label));
                label_present = true;
                break;
            default:
                break;
        }
        length -= (tlv_length+LDP_TLV_LEN_MIN);
        tlv_start += (tlv_length+LDP_TLV_LEN_MIN);
    }

    if(!fec_element) {
        return true;
    }
    if(label_present && label > LDP_LABEL_MAX) {
        LOG(LDP, "LDP (%s - %s) ignore label message with invalid label %u\n",
            ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
            ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
            label);
        return true;
    }
    if(*fec_element == LDP_FEC_ELEMENT_TYPE_WILDCARD) {
        if(withdraw) {
            LOG(LDP, "LDP (%s - %s) withdraw all labels (wildcard FEC)\n",
                ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
            ldb_db_withdraw_session(session, label, !label_present);
        }
        return true;
    }
    if(!withdraw && !label_present) {
        /* The label TLV is mandatory (RFC 5036 section 3.5.7),
         * label TLVs other than generic labels are not supported. */
        LOG(LDP, "LDP (%s - %s) ignore label mapping without generic label\n",
            ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
            ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id));
        return true;
    }

    /* Read all FEC elements. */
    while(fec_length >= LDP_FEC_LEN_MIN && *fec_element == LDP_FEC_ELEMENT_TYPE_PREFIX) {
        fec_afi = read_be_uint(fec_element+1, 2);
        prefix_length = *(fec_element+3);
        prefix_bytes = BITS_TO_BYTES(prefix_length);
        if(prefix_bytes+LDP_FEC_LEN_MIN > fec_length) {
            LOG_NOARG(DEBUG, "ldp_label_mapping E5\n");
            return false;
        }
        switch(fec_afi) {
            case IANA_AFI_IPV4:
                if(prefix_length > (IPV4_ADDR_LEN*8)) {
                    LOG_NOARG(DEBUG, "ldp_label_mapping E6\n");
                    return false;
                }
                ipv4prefix.len = prefix_length;
                ipv4prefix.address = 0;
                memcpy((uint8_t*)&ipv4prefix.address, fec_element+LDP_FEC_LEN_MIN, prefix_bytes);
                LOG(DEBUG, "LDP (%s - %s) %s %s via label %u\n",
                    ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                    ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
                    withdraw ? "withdraw" : "add", format_ipv4_prefix(&ipv4prefix), label);
                if(withdraw) {
                    ldb_db_withdraw_ipv4(session, &ipv4prefix, label, !label_present);
                } else {
                    ldb_db_add_ipv4(session, &ipv4prefix, label);
                }
                break;
            case IANA_AFI_IPV6:
                if(prefix_length > (IPV6_ADDR_LEN*8)) {
                    LOG_NOARG(DEBUG, "ldp_label_mapping E7\n");
                    return false;
                }
                ipv6prefix.len = prefix_length;
                memset(&ipv6prefix.address, 0x0, sizeof(ipv6addr_t));
                memcpy((uint8_t*)&ipv6prefix.address, fec_element+LDP_FEC_LEN_MIN, prefix_bytes);
                LOG(DEBUG, "LDP (%s - %s) %s %s via label %u\n",
                    ldp_id_to_str(session->local.lsr_id, session->local.label_space_id),
                    ldp_id_to_str(session->peer.lsr_id, session->peer.label_space_id),
                    withdraw ? "withdraw" : "add", format_ipv6_prefix(&ipv6prefix), label);
                if(withdraw) {
                    ldb_db_withdraw_ipv6(session, &ipv6prefix, label, !label_present);
                } else {
                    ldb_db_add_ipv6(session, &ipv6prefix, label);
                }
                break;
            default:
                break;
        }
        fec_length -= (prefix_bytes+LDP_FEC_LEN_MIN);
        fec_element += (prefix_bytes+LDP_FEC_LEN_MIN);
    }
    return true;
}

/*
 * Initialization message (RFC 5036 section 3.5.3), the Common Session
 * Parameters TLV is mandatory and must have protocol version 1, a
 * keepalive time other than zero and the own LDP identifier as receiver
 * (otherwise Session Rejected/No Hello, RFC 5036 section 2.5.3).
 */
static bool
ldp_initialization(ldp_session_s *session, uint8_t *start, uint16_t length)
{
    uint8_t *tlv_start = start;
    uint16_t tlv_type;
    uint16_t tlv_length;
    bool common = false;

    while(length >= LDP_TLV_LEN_MIN) {
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
                if(read_be_uint(tlv_start+4, 2) != 1) {
                    session->error_code = LDP_STATUS_BAD_VERSION|LDP_STATUS_FATAL_ERROR;
                    return false;
                }
                if(read_be_uint(tlv_start+6, 2) == 0) {
                    session->error_code = LDP_STATUS_BAD_TLV_VALUE|LDP_STATUS_FATAL_ERROR;
                    return false;
                }
                if(*(uint32_t*)(tlv_start+12) != session->local.lsr_id ||
                   read_be_uint(tlv_start+16, 2) != session->local.label_space_id) {
                    session->error_code = LDP_STATUS_SESSION_REJECTED_NO_HELLO|LDP_STATUS_FATAL_ERROR;
                    return false;
                }
                session->peer.keepalive_time = read_be_uint(tlv_start+6, 2);
                session->peer.max_pdu_len = read_be_uint(tlv_start+10, 2);
                common = true;
                break;
            default:
                break;
        }
        length -= (tlv_length+LDP_TLV_LEN_MIN);
        tlv_start += (tlv_length+LDP_TLV_LEN_MIN);
    }
    if(!common) {
        session->error_code = LDP_STATUS_MISSING_MSG_PARAMS|LDP_STATUS_FATAL_ERROR;
        return false;
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
        memmove(buffer->data, buffer->data+buffer->start_idx, size);
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

    while(!session->decode_error && ldp_session_receiving(session)) {
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

        if(pdu_version != 1) {
            ldp_fatal_error(session, "invalid PDU received (version)", LDP_STATUS_BAD_VERSION);
            return;
        }
        if(pdu_length < LDP_IDENTIFIER_LEN || 
           pdu_length > session->max_pdu_len) {
            ldp_fatal_error(session, "invalid PDU received (length)", LDP_STATUS_BAD_PDU_LEN);
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
            ldp_fatal_error(session, "invalid PDU received (wrong label space)", LDP_STATUS_BAD_IDENTIFIER);
            return;
        }

        pdu_length -= LDP_IDENTIFIER_LEN;
        msg_start = pdu_start+LDP_MIN_PDU_LEN;
        while(pdu_length >= LDP_MIN_MSG_LEN) {
            session->stats.message_rx++;

            msg_type = read_be_uint(msg_start, 2);
            msg_length = read_be_uint(msg_start+2, 2);
            msg_id = read_be_uint(msg_start+4, 4);
            /* The message length includes the mandatory message ID. */
            if(msg_length < 4 || msg_length+4 > pdu_length) {
                ldp_fatal_error(session, "invalid PDU received (message length)", LDP_STATUS_BAD_MSG_LEN);
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
                        ldp_fatal_error(session, "invalid PDU received (notification message)", LDP_STATUS_BAD_TLV_LEN);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_INITIALIZATION:
                    if(!ldp_initialization(session, msg_start+8, msg_length-4)) {
                        ldp_fatal_error(session, "invalid PDU received (initialization message)", LDP_STATUS_BAD_TLV_LEN);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_KEEPALIVE:
                    session->stats.keepalive_rx++;
                    ldp_session_fsm(session, LDP_EVENT_RX_KEEPALIVE);
                    break;
                case LDP_MESSAGE_TYPE_LABEL_MAPPING:
                    if(session->state != LDP_OPERATIONAL) {
                        /* Only initialization and keepalive are expected
                         * before operational (RFC 5036 section 2.5.4). */
                        break;
                    }
                    if(!ldp_label_message(session, msg_start+8, msg_length-4, false)) {
                        ldp_fatal_error(session, "invalid PDU received (label mapping message)", LDP_STATUS_BAD_TLV_LEN);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_LABEL_WITHDRAW:
                    if(session->state != LDP_OPERATIONAL) {
                        break;
                    }
                    if(!ldp_label_message(session, msg_start+8, msg_length-4, true)) {
                        ldp_fatal_error(session, "invalid PDU received (label withdraw message)", LDP_STATUS_BAD_TLV_LEN);
                        return;
                    }
                    break;
                case LDP_MESSAGE_TYPE_ADDRESS:
                case LDP_MESSAGE_TYPE_ADDRESS_WITHDRAW:
                case LDP_MESSAGE_TYPE_LABEL_REQUEST:
                case LDP_MESSAGE_TYPE_LABEL_RELEASE:
                case LDP_MESSAGE_TYPE_ABORT_REQUEST:
                    break;
                default:
                    break;
            }
            pdu_length -= (msg_length+4);
            msg_start += (msg_length+4);
            if(session->decode_error || !ldp_session_receiving(session)) {
                /* Session closed by the message (e.g. notification). */
                return;
            }
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