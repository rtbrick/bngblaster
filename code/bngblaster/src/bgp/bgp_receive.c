
/*
 * BNG Blaster (BBL) - BGP Message Receive Functions
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

struct keyval_ bgp_msg_names[] = {
    { BGP_MSG_OPEN,         "open" },
    { BGP_MSG_UPDATE,       "update" },
    { BGP_MSG_NOTIFICATION, "notification" },
    { BGP_MSG_KEEPALIVE,    "keepalive" },
    { 0, NULL}
};

struct keyval_ bgp_notification_error_values[] = {
    { 1, "Message Header Error" },
    { 2, "OPEN Message Error" },
    { 3, "UPDATE Message Error" },
    { 4, "Hold Timer Expired" },
    { 5, "FSM Error" },
    { 6, "Cease" },
    { 0, NULL}
};

struct keyval_ bgp_notification_msg_hdr_error_values[] = {
    { 1, "Connection Not Synchronized" },
    { 2, "Bad Message Length" },
    { 3, "Bad Message Type" },
    { 0, NULL}
};

struct keyval_ bgp_notification_open_error_values[] = {
    { 1, "Unsupported Version Number" },
    { 2, "Bad Peer AS" },
    { 3, "Bad BGP Identifier" },
    { 4, "Unsupported Optional Parameter" },
    { 6, "Unacceptable Hold Time" },
    { 0, NULL}
};

struct keyval_ bgp_notification_update_error_values[] = {
    { 1, "Malformed Attribute List" },
    { 2, "Unrecognized Well-known Attribute" },
    { 3, "Missing Well-known Attribute" },
    { 4, "Attribute Flags Error" },
    { 5, "Attribute Length Error" },
    { 6, "Invalid ORIGIN Attribute" },
    { 8, "Invalid NEXT_HOP Attribute" },
    { 9, "Optional Attribute Error" },
    { 10, "Invalid Network Field" },
    { 11, "Malformed AS_PATH" },
    { 0, NULL}
};

struct keyval_ bgp_notification_cease_error_values[] = {
    { 1, "Maximum Number of Prefixes Reached" },
    { 2, "Administrative Shutdown" },
    { 3, "Peer De-configured" },
    { 4, "Administrative Reset" },
    { 5, "Connection Rejected" },
    { 6, "Other Configuration Change" },
    { 7, "Connection Collision Resolution" },
    { 8, "Out of Resources" },
    { 0, NULL}
};

static void 
bgp_decode_error(bgp_session_s *session)
{
    LOG(BGP, "BGP (%s %s - %s) invalid message received\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str);

    if(!session->error_code) {
        session->error_code = 1; /* Message header error */
        session->error_subcode = 2; /* Bad message length */
    }
    bgp_session_close(session);
}

static bool
bgp_capability(bgp_session_s *session, uint8_t *start, uint8_t length)
{
    uint8_t cap_code, cap_length;

    if(length < 2) {
        return false;
    }
    cap_code = read_be_uint(start, 1);
    cap_length = read_be_uint(start+1, 1);
    if(cap_length+2 > length) {
        return false;
    }
    switch(cap_code) {
        case BGP_CAPABILITY_4_BYTE_AS:
            if(cap_length != 4) {
                return false;
            }
            session->peer.as = read_be_uint(start+2, 4);
            session->peer.as4 = true;
            break;
        default:
            break;
    }
    return true;
}

bool
bgp_open_parse(bgp_session_s *session, uint8_t *start, uint16_t length)
{
    uint8_t opt_length = 0;
    uint8_t opt_idx = 29;
    uint8_t opt_param_type;
    uint8_t opt_param_length;

    if(length < 29) {
        return false;
    }
    session->peer.as = read_be_uint(start+20, 2);
    session->peer.hold_time = read_be_uint(start+22, 2);
    session->peer.id = read_be_uint(start+24, 4);

    /* Decode optional parameters. */
    opt_length = read_be_uint(start+28, 1);
    if((opt_length + opt_idx) > length) {
        return false;
    }
    while((opt_idx+2) <= length) {
        opt_param_type = read_be_uint(start+opt_idx, 1);
        opt_param_length = read_be_uint(start+opt_idx+1, 1);
        opt_idx+=2;
        if(opt_idx+opt_param_length > length) {
            return false;
        }
        if(opt_param_type == BGP_CAPABILITY) {
            if(!bgp_capability(session, start+opt_idx, opt_param_length)) {
                return false;
            }
        }
        opt_idx += opt_param_length;
    }

    LOG(BGP, "BGP (%s %s - %s) open message received with peer AS: %u, hold-time: %us\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str,
        session->peer.as, session->peer.hold_time);

    return true;
}

static bool
bgp_open(bgp_session_s *session, uint8_t *start, uint16_t length)
{
    if(!bgp_open_parse(session, start, length)) {
        return false;
    }
    if(session->collision) {
        if(!bgp_session_collision_resolve(session, /*trigger_is_primary=*/true)) {
            /* session->tcpc/read_buf have already been swapped to the
             * winning (collision) connection; the caller must stop
             * processing the now-stale buffer immediately. */
            return true;
        }
    }
    bgp_session_state_change(session, BGP_OPENCONFIRM);
    return true;
}

static bool
bgp_notification(bgp_session_s *session, uint8_t *start, uint16_t length)
{
    uint8_t error_code, error_subcode;

    if(length < 21) {
        return false;
    }

    error_code = *(start+19);
    error_subcode = *(start+20);
    switch(error_code) {
        case 1: /* Message Header Error */
            LOG(BGP, "BGP (%s %s - %s) notification received with error: %s (%u), %s (%u)\n", 
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                keyval_get_key(bgp_notification_error_values, error_code), error_code,
                keyval_get_key(bgp_notification_msg_hdr_error_values, error_subcode), error_subcode);
            break;
        case 2: /* OPEN Message Error */
            LOG(BGP, "BGP (%s %s - %s) notification received with error: %s (%u), %s (%u)\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                keyval_get_key(bgp_notification_error_values, error_code), error_code,
                keyval_get_key(bgp_notification_open_error_values, error_subcode), error_subcode);
            break;
        case 3: /* Update Message Error */
            LOG(BGP, "BGP (%s %s - %s) notification received with error: %s (%u), %s (%u)\n", 
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                keyval_get_key(bgp_notification_error_values, error_code), error_code,
                keyval_get_key(bgp_notification_update_error_values, error_subcode), error_subcode);
            break;
        case 6: /* Cease */
            LOG(BGP, "BGP (%s %s - %s) notification received with error: %s (%u), %s (%u)\n", 
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                keyval_get_key(bgp_notification_error_values, error_code), error_code,
                keyval_get_key(bgp_notification_cease_error_values, error_subcode), error_subcode);
            break;
        default:
            LOG(BGP, "BGP (%s %s - %s) notification received with error: %s (%u), subcode %u\n", 
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                keyval_get_key(bgp_notification_error_values, error_code), error_code, error_subcode);
            break;
    }
    session->error_code = 0;
    bgp_session_close(session);
    return true;
}

static bool
bgp_update_error(bgp_session_s *session, uint8_t error_subcode)
{
    session->error_code = 3; /* UPDATE Message Error */
    session->error_subcode = error_subcode;
    return false;
}

static bool
bgp_update(bgp_session_s *session, uint8_t *start, uint16_t length)
{
    bgp_update_s update = {0};
    uint16_t withdrawn_len, attr_len, attr_value_len;
    uint8_t attr_flags, attr_type;
    uint8_t *attr;

    if(!session->config->learn_routes) {
        /* Nothing to learn. */
        return true;
    }

    /* Header (19), Withdrawn Routes Length (2), Withdrawn Routes,
     * Total Path Attribute Length (2), Path Attributes, NLRI */
    if(length < 23) {
        return bgp_update_error(session, 1);
    }
    withdrawn_len = read_be_uint(start+19, 2);
    if(21 + withdrawn_len + 2 > length) {
        return bgp_update_error(session, 1);
    }
    update.withdrawn = start + 21;
    update.withdrawn_len = withdrawn_len;
    attr = start + 21 + withdrawn_len;
    attr_len = read_be_uint(attr, 2);
    attr += 2;
    if(23 + withdrawn_len + attr_len > length) {
        return bgp_update_error(session, 1);
    }
    update.nlri = attr + attr_len;
    update.nlri_len = length - (23 + withdrawn_len + attr_len);

    while(attr_len) {
        if(attr_len < 3) {
            return bgp_update_error(session, 1);
        }
        attr_flags = attr[0];
        attr_type = attr[1];
        if(attr_flags & BGP_PA_FLAG_EXTENDED_LENGTH) {
            if(attr_len < 4) {
                return bgp_update_error(session, 1);
            }
            attr_value_len = read_be_uint(attr+2, 2);
            attr += 4; attr_len -= 4;
        } else {
            attr_value_len = attr[2];
            attr += 3; attr_len -= 3;
        }
        if(attr_value_len > attr_len) {
            return bgp_update_error(session, 5); /* Attribute Length Error */
        }
        switch(attr_type) {
            case BGP_PA_ORIGIN:
                if(attr_value_len != 1) return bgp_update_error(session, 5);
                update.origin = attr;
                break;
            case BGP_PA_AS_PATH:
                update.as_path = attr;
                update.as_path_len = attr_value_len;
                break;
            case BGP_PA_NEXT_HOP:
                if(attr_value_len != 4) return bgp_update_error(session, 5);
                update.next_hop = attr;
                break;
            case BGP_PA_MED:
                if(attr_value_len != 4) return bgp_update_error(session, 5);
                update.med = attr;
                break;
            case BGP_PA_LOCAL_PREF:
                if(attr_value_len != 4) return bgp_update_error(session, 5);
                update.local_pref = attr;
                break;
            case BGP_PA_COMMUNITIES:
                if(attr_value_len % 4) return bgp_update_error(session, 5);
                update.communities = attr;
                update.communities_len = attr_value_len;
                break;
            case BGP_PA_LARGE_COMMUNITIES:
                if(attr_value_len % 12) return bgp_update_error(session, 5);
                update.large_communities = attr;
                update.large_communities_len = attr_value_len;
                break;
            case BGP_PA_EXT_COMMUNITIES:
                if(attr_value_len % 8) return bgp_update_error(session, 5);
                update.ext_communities = attr;
                update.ext_communities_len = attr_value_len;
                break;
            case BGP_PA_PMSI_TUNNEL:
                update.pmsi_tunnel = attr;
                update.pmsi_tunnel_len = attr_value_len;
                break;
            case BGP_PA_MP_REACH_NLRI:
                /* AFI (2), SAFI (1), Next Hop Length (1), Next Hop, Reserved (1), NLRI */
                if(attr_value_len < 5 || attr_value_len < 5 + attr[3]) {
                    return bgp_update_error(session, 9); /* Optional Attribute Error */
                }
                update.mp_reach = attr;
                update.mp_reach_afi = read_be_uint(attr, 2);
                update.mp_reach_safi = attr[2];
                update.mp_reach_nexthop_len = attr[3];
                update.mp_reach_nexthop = attr + 4;
                update.mp_reach_nlri = attr + 5 + attr[3];
                update.mp_reach_nlri_len = attr_value_len - 5 - attr[3];
                break;
            case BGP_PA_MP_UNREACH_NLRI:
                /* AFI (2), SAFI (1), Withdrawn Routes */
                if(attr_value_len < 3) {
                    return bgp_update_error(session, 9); /* Optional Attribute Error */
                }
                update.mp_unreach = attr;
                update.mp_unreach_afi = read_be_uint(attr, 2);
                update.mp_unreach_safi = attr[2];
                update.mp_unreach_nlri = attr + 3;
                update.mp_unreach_nlri_len = attr_value_len - 3;
                break;
            default:
                break;
        }
        attr += attr_value_len; attr_len -= attr_value_len;
    }

    if(!bgp_rib_update(session, &update)) {
        return false;
    }
    if(!bgp_evpn_update(session, &update)) {
        return bgp_update_error(session, 9); /* Optional Attribute Error */
    }
    return true;
}

/*
 * When there is only little data left and
 * the buffer start is close to buffer end,
 * then 'rebase' the buffer by copying
 * the tail data to the buffer head.
 */
static void
bgp_rebase_read_buffer(bgp_session_s *session)
{
    uint32_t size;
    io_buffer_t *buffer = &session->read_buf;

    size = buffer->idx - buffer->start_idx;
    if(size) {
        /* Copy what is left to the buffer start. */
        memcpy(buffer->data, buffer->data+buffer->start_idx, size);
    }
    buffer->start_idx = 0;
    buffer->idx = size;
}

static void
bgp_read(bgp_session_s *session)
{
    uint32_t size;
    uint16_t length;
    uint8_t type;
    uint8_t *start;
    io_buffer_t *buffer = &session->read_buf;

    while(true) {
        start = buffer->data+buffer->start_idx;
        size = buffer->idx - buffer->start_idx;

        /* Minimum message size */
        if(size < BGP_MIN_MESSAGE_SIZE) {
            break;
        }

        length = read_be_uint(start+16, 2);
        if(length < BGP_MIN_MESSAGE_SIZE ||
            length > BGP_MAX_MESSAGE_SIZE) {
            bgp_decode_error(session);
            return;
        }

        /* Full message on the wire to consume? */
        if(length > size) {
            break;
        }

        type = *(start+18);

        session->stats.message_rx++;
        LOG(DEBUG, "BGP (%s %s - %s) read %s message\n",
            session->interface->name,
            session->local_address_str,
            session->peer_address_str,
            keyval_get_key(bgp_msg_names, type));

        switch(type) {
            case BGP_MSG_OPEN:
                if(!bgp_open(session, start, length)) {
                    bgp_decode_error(session);
                    return;
                }
                if(session->collision_promoted) {
                    /* session->tcpc/read_buf were just swapped to the
                     * connection that won collision resolution; buffer
                     * (captured above) now points at freed/stale memory,
                     * so stop processing it immediately. */
                    session->collision_promoted = false;
                    return;
                }
                break;
            case BGP_MSG_NOTIFICATION:
                if(!bgp_notification(session, start, length)) {
                    bgp_decode_error(session);
                    return;
                }
                return;
            case BGP_MSG_KEEPALIVE:
                session->stats.keepalive_rx++;
                if(session->state == BGP_OPENCONFIRM) {
                    bgp_session_state_change(session, BGP_ESTABLISHED);
                }
                break;
            case BGP_MSG_UPDATE:
                session->stats.update_rx++;
                if(session->state == BGP_ESTABLISHED &&
                   !bgp_update(session, start, length)) {
                    bgp_decode_error(session);
                    return;
                }
                break;
            default:
                break;
        }

        /* Reset hold timer */
        bgp_restart_hold_timer(session, session->config->hold_time);

        /* Progress pointer to next BGP message */
        buffer->start_idx += length;
    }
    bgp_rebase_read_buffer(session);
}

void 
bgp_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    bgp_session_s *session = (bgp_session_s*)arg;
    io_buffer_t *buffer = &session->read_buf;
    if(buf) {
        if(buffer->idx+len > buffer->size) {
            LOG(ERROR, "BGP (%s %s - %s) receive error (read buffer exhausted)\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);

            if(!session->error_code) {
                session->error_code = 6; /* Cease */
                session->error_subcode = 8; /* Out of resources */
            }
            bgp_session_close(session);
            return;
        }
        memcpy(buffer->data+buffer->idx, buf, len);
        buffer->idx+=len;
    } else {
        bgp_read(session);
    }
}