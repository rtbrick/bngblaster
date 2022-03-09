/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

static uint16_t
as4_capability(uint8_t *buf, uint32_t as) {
    uint16_t len;

    *buf = 2; /* cap code */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = 6; /* cap length */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = 65; /* AS4 capability */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = 4; /* length to encode my AS4 */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *(uint32_t*)buf = htobe32(as); 
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint32_t));

    return len;
}

static uint16_t
mp_capability(uint8_t *buf, uint16_t afi, uint8_t safi) {
    uint16_t len;

    *buf = 2; /* cap code */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = 6; /* cap length */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = 1; /* MP extension capability */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = 4; /* length */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *(uint16_t*)buf = htobe16(afi); 
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint16_t));
    *buf = 0; /* Reserved */
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    *buf = safi;
    BUMP_WRITE_BUFFER(buf, &len, sizeof(uint8_t));
    return len;
}

void
bgp_message_open(bgp_session_t *session) {
    uint16_t opt_parms_idx, opt_parms_length;

    uint8_t *buf = session->write_buf;
    uint16_t cap_len;

    memset(buf, 16, 0xff); /* marker */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, 16);
    *(uint16_t*)buf = 0; /* length */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint16_t));
    *buf = BGP_MSG_OPEN; /* message type */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint8_t));
    *buf = BGP_MSG_OPEN; /* version 4 */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint8_t));

    /* local AS */
    if(session->config->local_as > 65535) {
        *(uint16_t*)buf = htobe16(23456); 
    } else {
        *(uint16_t*)buf = htobe16(session->config->local_as); 
    }
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint16_t));

    *(uint16_t*)buf = htobe16(session->config->holdtime); /* holdtime */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint16_t));
    *(uint32_t*)buf = session->config->id; /* BGP ID */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint32_t));

    /* Optional parameters */
    *buf = 0; /* optional parameter length */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, sizeof(uint8_t));
    opt_parms_idx = session->write_idx;

    cap_len = as4_capability(buf, session->config->local_as);
    BUMP_WRITE_BUFFER(buf, &session->write_idx, cap_len);

    cap_len = mp_capability(buf, 1, 1); /* ipv4 unicast */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, cap_len);
    cap_len = mp_capability(buf, 2, 1); /* ipv6 unicast */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, cap_len);
    cap_len = mp_capability(buf, 1, 4); /* ipv4 labeled unicast */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, cap_len);
    cap_len = mp_capability(buf, 2, 4); /* ipv6 labeled unicast */
    BUMP_WRITE_BUFFER(buf, &session->write_idx, cap_len);

    /* Update optional parameters length field */
    opt_parms_length = session->write_idx - opt_parms_idx;
    *(session->write_buf+opt_parms_idx-1) = opt_parms_length;

    /* Update message length field */
    *(uint16_t*)(session->write_buf+16) = htobe16(session->write_idx);
}