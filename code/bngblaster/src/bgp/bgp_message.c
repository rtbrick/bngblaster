/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

static void
push_as4_capability(io_buffer_t *buffer, uint32_t as) {
    uint32_t cap_idx, length;

    push_be_uint(buffer, 1, 2); /* CAP code */
    push_be_uint(buffer, 1, 0); /* CAP length. To be updated later... */
    cap_idx = buffer->idx;

    /* AS capability */
    push_be_uint(buffer, 1, 65);
    push_be_uint(buffer, 1, 4); /* length to encode my AS4 */
    push_be_uint(buffer, 4, as); /* my AS */

    /* Calculate capability length field */
    length = buffer->idx - cap_idx;
    write_be_uint(buffer->data+cap_idx-1, 1, length); /* update CAP length */
}

static void
push_mp_capability(io_buffer_t *buffer, uint16_t afi, uint8_t safi) {
    uint32_t cap_idx, length;

    push_be_uint(buffer, 1, 2); /* CAP code */
    push_be_uint(buffer, 1, 0); /* CAP length. To be updated later... */
    cap_idx = buffer->idx;

    /* MP capability */
    push_be_uint(buffer, 1, 1); /* MP extension CAP */
    push_be_uint(buffer, 1, 4); /* Length */
    push_be_uint(buffer, 2, afi);
    push_be_uint(buffer, 1, 0); /* Reserved */
    push_be_uint(buffer, 1, safi);

    /* Calculate capability length field */
    length = buffer->idx - cap_idx;
    write_be_uint(buffer->data+cap_idx-1, 1, length); /* update CAP length */
}

void
bgp_push_open_message(bgp_session_t *session) {
    uint32_t open_start_idx, length, opt_parms_idx, opt_parms_length;
    io_buffer_t *buffer = &session->write_buf;

    if (buffer->idx > (buffer->size - BGP_MIN_MESSAGE_SIZE)) {
	    return;
    }

    open_start_idx = buffer->idx;
	push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
	push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 2, 0); /* length */
    push_be_uint(buffer, 1, BGP_MSG_OPEN); /* message type */
    push_be_uint(buffer, 1, 4); /* version 4 */
    if(session->config->local_as > 65535) {
	    push_be_uint(buffer, 2, 23456);
    } else {
        push_be_uint(buffer, 2, session->config->local_as); 
    }
    push_be_uint(buffer, 2, session->config->holdtime); /* holdtime */
    push_be_uint(buffer, 4, session->config->id); /* BGP ID */

    /* Optional parameters */
    push_be_uint(buffer, 1, 0); /* Optional Parameter length */
    opt_parms_idx = buffer->idx;

    push_as4_capability(buffer, session->config->local_as);
    push_mp_capability(buffer, 1, 1); /* ipv4 unicast */
    push_mp_capability(buffer, 2, 1); /* ipv6 unicast */
    push_mp_capability(buffer, 1, 4); /* ipv4 labeled unicast */
    push_mp_capability(buffer, 2, 4); /* ipv6 labeled unicast */

    /* Calculate optional parameters length field */
    opt_parms_length = buffer->idx - opt_parms_idx;
    write_be_uint(buffer->data+opt_parms_idx-1, 1, opt_parms_length); /* overwrite parameters length */

    /* Calculate message length field */
    length = buffer->idx - open_start_idx;
    write_be_uint(buffer->data+open_start_idx+16, 2, length); /* overwrite message length */
}

void
bgp_push_keepalive_message(bgp_session_t *session) {
    uint32_t keepalive_start_idx, length;
    io_buffer_t *buffer = &session->write_buf;

    if (buffer->idx > (buffer->size - BGP_MIN_MESSAGE_SIZE)) {
	    return;
    }

    keepalive_start_idx = buffer->idx;
    push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 2, 0); /* length */
    push_be_uint(buffer, 1, BGP_MSG_KEEPALIVE); /* message type */

    /* Calculate message length field */
    length = buffer->idx - keepalive_start_idx;
    write_be_uint(buffer->data+keepalive_start_idx+16, 2, length); /* overwrite message length */
}

void
bgp_push_notification_message(bgp_session_t *session) {
    uint32_t notification_start_idx, length;
    io_buffer_t *buffer = &session->write_buf;

    if (buffer->idx > (buffer->size - BGP_MIN_MESSAGE_SIZE)) {
	    return;
    }

    notification_start_idx = buffer->idx;
    push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 2, 0); /* length */
    push_be_uint(buffer, 1, BGP_MSG_NOTIFICATION); /* message type */
    push_be_uint(buffer, 1, session->error_code);
    push_be_uint(buffer, 1, session->error_subcode);

    /* Calculate message length field */
    length = buffer->idx - notification_start_idx;
    write_be_uint(buffer->data+notification_start_idx+16, 2, length); /* overwrite message length */
}