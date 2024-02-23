/*
 * BNG Blaster (BBL) - BGP Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

static void
push_as4_capability(io_buffer_t *buffer, uint32_t as)
{
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

/* Multiprotocol Extension Capability */
static void
push_mp_capability(io_buffer_t *buffer, uint16_t afi, uint8_t safi)
{
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

/* Extended Nexthop Capability */
static void
push_en_capability(io_buffer_t *buffer, uint16_t afi, uint16_t safi, uint16_t nh_afi)
{
    uint32_t cap_idx, length;

    push_be_uint(buffer, 1, 2); /* CAP code */
    push_be_uint(buffer, 1, 0); /* CAP length. To be updated later... */
    cap_idx = buffer->idx;

    /* MP capability */
    push_be_uint(buffer, 1, 5); /* MP extension CAP */
    push_be_uint(buffer, 1, 6); /* Length */
    push_be_uint(buffer, 2, afi);
    push_be_uint(buffer, 2, safi);
    push_be_uint(buffer, 2, nh_afi);

    /* Calculate capability length field */
    length = buffer->idx - cap_idx;
    write_be_uint(buffer->data+cap_idx-1, 1, length); /* update CAP length */
}

void
bgp_push_open_message(bgp_session_s *session)
{
    uint32_t open_start_idx, length, opt_parms_idx, opt_parms_length;
    io_buffer_t *buffer = &session->write_buf;
    bgp_config_s *config = session->config;

    if(buffer->idx > (buffer->size - BGP_MIN_MESSAGE_SIZE)) {
        return;
    }

    open_start_idx = buffer->idx;
    push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 8, 0xffffffffffffffff); /* marker */
    push_be_uint(buffer, 2, 0); /* length */
    push_be_uint(buffer, 1, BGP_MSG_OPEN); /* message type */
    push_be_uint(buffer, 1, 4); /* version 4 */
    if(config->local_as > 65535) {
        push_be_uint(buffer, 2, 23456);
    } else {
        push_be_uint(buffer, 2, config->local_as); 
    }
    push_be_uint(buffer, 2, config->hold_time); /* hold-time */
    push_data(buffer, (uint8_t*)&session->config->id, 4); /* BGP ID */

    /* Optional parameters */
    push_be_uint(buffer, 1, 0); /* Optional Parameter length */
    opt_parms_idx = buffer->idx;

    push_as4_capability(buffer, config->local_as);

    if(config->family & BGP_IPV4_UC) {
        push_mp_capability(buffer, 1, 1); /* ipv4-unicast */
    }
    if(config->family & BGP_IPv6_UC) {
        push_mp_capability(buffer, 2, 1); /* ipv6-unicast */
    }
    if(config->family & BGP_IPv4_MC) {
        push_mp_capability(buffer, 1, 2); /* ipv4-multicast */
    }
    if(config->family & BGP_IPv6_MC) {
        push_mp_capability(buffer, 2, 2); /* ipv6-multicast */
    }
    if(config->family & BGP_IPv4_LU) {
        push_mp_capability(buffer, 1, 4); /* ipv4-labeled-unicast */
    }
    if(config->family & BGP_IPv6_LU) {
        push_mp_capability(buffer, 2, 4); /* ipv6-labeled-unicast */
    }
    if(config->family & BGP_IPv4_VPN_UC) {
        push_mp_capability(buffer, 1, 128); /* ipv4-vpn-unicast */
    }
    if(config->family & BGP_IPv6_VPN_UC) {
        push_mp_capability(buffer, 2, 128); /* ipv6-vpn-unicast */
    }
    if(config->family & BGP_IPv4_VPN_MC) {
        push_mp_capability(buffer, 1, 129); /* ipv4-vpn-multicast */
    }
    if(config->family & BGP_IPv6_VPN_MC) {
        push_mp_capability(buffer, 2, 129); /* ipv6-vpn-multicast */
    }
    if(config->family & BGP_IPv4_FLOW) {
        push_mp_capability(buffer, 1, 4); /* ipv4-flow */
    }
    if(config->family & BGP_IPv6_FLOW) {
        push_mp_capability(buffer, 2, 4); /* ipv6-flow */
    }
    if(config->family & BGP_EVPN) {
        push_mp_capability(buffer, 25, 70); /* EVPN */
    }

    if(config->extended_nexthop & BGP_IPV4_UC) {
        push_en_capability(buffer, 1, 1, 2);
    }
    if(config->extended_nexthop & BGP_IPv4_VPN_UC) {
        push_en_capability(buffer, 1, 128, 2);
    }

    /* Calculate optional parameters length field */
    opt_parms_length = buffer->idx - opt_parms_idx;
    write_be_uint(buffer->data+opt_parms_idx-1, 1, opt_parms_length); /* overwrite parameters length */

    /* Calculate message length field */
    length = buffer->idx - open_start_idx;
    write_be_uint(buffer->data+open_start_idx+16, 2, length); /* overwrite message length */
}

void
bgp_push_keepalive_message(bgp_session_s *session)
{
    uint32_t keepalive_start_idx, length;
    io_buffer_t *buffer = &session->write_buf;

    if(buffer->idx > (buffer->size - BGP_MIN_MESSAGE_SIZE)) {
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
bgp_push_notification_message(bgp_session_s *session)
{
    uint32_t notification_start_idx, length;
    io_buffer_t *buffer = &session->write_buf;

    if(buffer->idx > (buffer->size - BGP_MIN_MESSAGE_SIZE)) {
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