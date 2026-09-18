/*
 * BNG Blaster (BBL) - BGP Connection Collision Detection (RFC 4271 6.8)
 *
 * When both BGP speakers actively connect to each other (the common case,
 * since BGP now both listens and connects), two independent TCP connections
 * to the same peer can exist briefly. This module holds the second one in
 * a lightweight "collision" struct - just enough to send our own OPEN and
 * parse the peer's, reusing bgp_open_parse() - until a valid OPEN resolves
 * which connection to keep, per RFC 4271 6.8's BGP Identifier comparison.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

#define BGP_COLLISION_BUF_SIZE BGP_MAX_MESSAGE_SIZE

static void bgp_collision_receive_cb(void *arg, uint8_t *buf, uint16_t len);
static void bgp_collision_error_cb(void *arg, err_t err);
static void bgp_session_collision_teardown(bgp_session_s *session);
static void bgp_session_collision_promote(bgp_session_s *session, bool trigger_is_primary);

/**
 * bgp_session_close_tcpc_with_notification
 *
 * Send a BGP NOTIFICATION on a standalone TCP connection and close it.
 * Used to tear down a losing collision leg, a displaced old primary, or a
 * rejected extra connection attempt, without touching any other connection.
 * Takes ownership of tcpc (closes and frees it).
 *
 * @param tcpc TCP connection to close (may be NULL, in which case this is a no-op)
 * @param error_code BGP NOTIFICATION error code
 * @param error_subcode BGP NOTIFICATION error sub-code
 */
void
bgp_session_close_tcpc_with_notification(bbl_tcp_ctx_s *tcpc, uint8_t error_code, uint8_t error_subcode)
{
    uint8_t buf[BGP_MIN_MESSAGE_SIZE + 2];
    io_buffer_t notification = {0};

    if(!tcpc) {
        return;
    }

    notification.data = buf;
    notification.size = sizeof(buf);
    bgp_push_notification_message_buf(&notification, error_code, error_subcode);
    /* bbl_tcp_send() hands the pointer straight to lwIP's tcp_write() and
     * lwIP keeps referencing it until the data is acknowledged, so this
     * stack buffer MUST be copied. */
    tcpc->tx.flags = TCP_WRITE_FLAG_COPY;
    bbl_tcp_send(tcpc, notification.data, notification.idx);
    /* Deferred: this is reached from inside the connection's own callbacks,
     * where closing/freeing in place would leave lwIP (and bbl_tcp) using
     * freed memory. Deferring also gives the NOTIFICATION a chance to go
     * out before the connection is closed. */
    bbl_tcp_ctx_free_deferred(tcpc);
}

/**
 * bgp_session_collision_free
 *
 * Free session->collision (if any), closing its TCP connection.
 *
 * @param session BGP session
 */
void
bgp_session_collision_free(bgp_session_s *session)
{
    bgp_collision_s *collision = session->collision;
    if(!collision) {
        return;
    }
    session->collision = NULL;
    /* Deferred: commonly reached from the collision leg's own receive or
     * error callback. */
    bbl_tcp_ctx_free_deferred(collision->tcpc);
    free(collision->read_buf.data);
    free(collision->write_buf.data);
    free(collision);
}

/**
 * bgp_session_new_connection
 *
 * Dispatcher called whenever a TCP connection becomes available for a BGP
 * session - either our own active connect completing (bgp_connected_cb) or
 * an inbound connection being accepted (bgp_accepted_cb). Adopts it as the
 * primary connection if none exists yet, starts RFC 4271 6.8 collision
 * detection if one already does, or rejects a third/fourth attempt outright.
 *
 * The caller keeps ownership of `tcpc` when this returns false, so it can
 * reject the connection in whatever way suits its callback contract.
 *
 * @param session BGP session
 * @param tcpc newly available TCP connection
 * @param active true if this connection is our own active connect, false if accepted
 * @return true if the connection was taken over, false if it must be rejected
 */
bool
bgp_session_new_connection(bgp_session_s *session, bbl_tcp_ctx_s *tcpc, bool active)
{
    bgp_collision_s *collision;

    if(!tcpc) {
        return false;
    }
    if(session->state == BGP_ESTABLISHED) {
        /* RFC 4271 6.8: "a connection collision with an existing BGP
         * connection that is in the Established state causes unconditional
         * closing of the newly created connection". */
        LOG(BGP, "BGP (%s %s - %s) rejecting connection attempt (session already established)\n",
            session->interface->name,
            session->local_address_str,
            session->peer_address_str);
        return false;
    }
    if(!session->tcpc || session->state < BGP_OPENSENT) {
        /* No usable connection yet: adopt this one directly (today's
         * behavior). Discard any earlier, still-incomplete attempt. */
        if(session->tcpc) {
            bbl_tcp_ctx_free_deferred(session->tcpc);
        }
        session->tcpc = tcpc;
        session->active = active;
        tcpc->arg = session;
        tcpc->receive_cb = bgp_receive_cb;
        tcpc->error_cb = bgp_error_cb;
        bgp_session_reset_read_buffer(session);
        bgp_session_reset_write_buffer(session);
        bgp_session_state_change(session, BGP_OPENSENT);
        return true;
    }
    if(session->collision) {
        /* A third/fourth connection attempt for this peer: reject it. */
        LOG(BGP, "BGP (%s %s - %s) rejecting extra connection attempt (collision already in progress)\n",
            session->interface->name,
            session->local_address_str,
            session->peer_address_str);
        return false;
    }

    /* Genuine collision: session->tcpc is already at OpenSent or later and
     * a second, independent connection to the same peer just appeared. */
    LOG(BGP, "BGP (%s %s - %s) connection collision detected\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str);

    collision = calloc(1, sizeof(bgp_collision_s));
    if(!collision) {
        return false;
    }
    collision->read_buf.data = malloc(BGP_COLLISION_BUF_SIZE);
    collision->write_buf.data = malloc(BGP_COLLISION_BUF_SIZE);
    if(!collision->read_buf.data || !collision->write_buf.data) {
        free(collision->read_buf.data);
        free(collision->write_buf.data);
        free(collision);
        return false;
    }
    collision->tcpc = tcpc;
    collision->active = active;
    collision->read_buf.size = BGP_COLLISION_BUF_SIZE;
    collision->write_buf.size = BGP_COLLISION_BUF_SIZE;
    session->collision = collision;

    tcpc->arg = session;
    tcpc->receive_cb = bgp_collision_receive_cb;
    tcpc->error_cb = bgp_collision_error_cb;

    bgp_push_open_message_buf(&session->collision->write_buf, session->config);
    /* Copy into lwIP: the collision write buffer is freed as soon as the
     * collision is resolved, which can happen before this OPEN has been
     * acknowledged (lwIP would otherwise still reference it). */
    tcpc->tx.flags = TCP_WRITE_FLAG_COPY;
    bbl_tcp_send(tcpc, session->collision->write_buf.data, session->collision->write_buf.idx);
    return true;
}

static void
bgp_collision_error_cb(void *arg, err_t err)
{
    bgp_session_s *session = (bgp_session_s*)arg;
    UNUSED(err);

    LOG(BGP, "BGP (%s %s - %s) collision connection TCP error, discarding\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str);

    bgp_session_collision_free(session);
}

static void
bgp_collision_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    bgp_session_s *session = (bgp_session_s*)arg;
    bgp_collision_s *collision = session->collision;
    io_buffer_t *buffer;
    uint32_t size;
    uint16_t length;
    uint8_t type;
    uint8_t *start;

    if(!collision) {
        /* Already resolved (freed) by the other leg's own receive/error
         * callback racing ahead of this one. */
        return;
    }
    buffer = &collision->read_buf;

    if(buf) {
        if(buffer->idx + len > buffer->size) {
            bgp_session_close_tcpc_with_notification(collision->tcpc, 6, 8);
            collision->tcpc = NULL;
            bgp_session_collision_free(session);
            return;
        }
        memcpy(buffer->data + buffer->idx, buf, len);
        buffer->idx += len;
        return;
    }

    /* NULL,0 marks "read finished for now". Mirrors bgp_read()'s own
     * length handling exactly, since bgp_open_parse() trusts the length
     * it is handed rather than re-deriving it from the wire. */
    start = buffer->data + buffer->start_idx;
    size = buffer->idx - buffer->start_idx;
    if(size < BGP_MIN_MESSAGE_SIZE) {
        return; /* wait for more bytes */
    }
    length = read_be_uint(start+16, 2);
    if(length < BGP_MIN_MESSAGE_SIZE || length > BGP_MAX_MESSAGE_SIZE) {
        bgp_session_collision_free(session);
        return;
    }
    if(length > size) {
        return; /* wait for the rest of the message */
    }
    type = *(start+18);
    if(type != BGP_MSG_OPEN) {
        /* NOTIFICATION, or any FSM violation (KEEPALIVE/UPDATE first) on
         * this leg: the peer abandoned it, give up on it. */
        bgp_session_collision_free(session);
        return;
    }
    if(!bgp_open_parse(session, start, length)) {
        bgp_session_collision_free(session);
        return;
    }
    bgp_session_collision_resolve(session, /*trigger_is_primary=*/false);
}

/**
 * bgp_session_collision_resolve
 *
 * The RFC 4271 6.8 algorithm: compares BGP Identifiers to decide whether
 * the primary (session->tcpc) or the collision leg survives, then tears
 * down or promotes accordingly.
 *
 * config->id is a raw network-byte-order value (from inet_pton); peer.id is
 * already host byte order (populated via read_be_uint() in bgp_open_parse()) -
 * only the former needs be32toh() before the numeric comparison.
 *
 * @param session BGP session
 * @param trigger_is_primary true if session->tcpc (not the collision leg)
 *                            is the connection that just delivered the OPEN
 *                            that triggered this resolution
 * @return true if the primary (session->tcpc) survives
 */
bool
bgp_session_collision_resolve(bgp_session_s *session, bool trigger_is_primary)
{
    uint32_t local_id;
    uint32_t peer_id;
    bool primary_survives;

    if(!session->collision) {
        /* Already resolved by the other leg. */
        return true;
    }

    local_id = be32toh(session->config->id);
    peer_id = session->peer.id;

    if(local_id == peer_id) {
        LOG(BGP, "BGP (%s %s - %s) collision resolution: duplicate BGP Identifier, keeping existing connection\n",
            session->interface->name,
            session->local_address_str,
            session->peer_address_str);
        primary_survives = true;
    } else if(trigger_is_primary) {
        /* The collision leg is "existing", the primary is "new" (it just
         * delivered this OPEN): local ID lower -> new (primary) wins. */
        primary_survives = (local_id < peer_id);
    } else {
        /* Mirror image: primary is "existing", collision leg is "new". */
        primary_survives = (local_id > peer_id);
    }

    if(primary_survives) {
        bgp_session_collision_teardown(session);
    } else {
        bgp_session_collision_promote(session, trigger_is_primary);
    }
    return primary_survives;
}

static void
bgp_session_collision_teardown(bgp_session_s *session)
{
    LOG(BGP, "BGP (%s %s - %s) collision resolution: keeping existing connection\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str);

    bgp_session_close_tcpc_with_notification(session->collision->tcpc, 6, 7);
    session->collision->tcpc = NULL;
    bgp_session_collision_free(session);

    /* The surviving connection deliberately stays in its current state. Per
     * RFC 4271 each connection runs its own FSM: the OPEN that resolved this
     * collision arrived on the leg we just closed, so the survivor must wait
     * for the peer's OPEN on its own connection before moving to
     * OpenConfirm. Advancing it here would make us send a KEEPALIVE for an
     * OPEN never exchanged on that connection, and the peer's real OPEN
     * would then arrive in the wrong state (FSM error). */
}

static void
bgp_session_collision_promote(bgp_session_s *session, bool trigger_is_primary)
{
    bgp_collision_s *collision = session->collision;
    bbl_tcp_ctx_s *old_primary = session->tcpc;
    uint32_t leftover;

    LOG(BGP, "BGP (%s %s - %s) collision resolution: switching to the other connection\n",
        session->interface->name,
        session->local_address_str,
        session->peer_address_str);

    bgp_session_close_tcpc_with_notification(old_primary, 6, 7);

    session->tcpc = collision->tcpc;
    session->active = collision->active;
    collision->tcpc->arg = session;
    collision->tcpc->receive_cb = bgp_receive_cb;
    collision->tcpc->error_cb = bgp_error_cb;

    /* This tcpc may still be mid-send of its own OPEN (from
     * bgp_session_new_connection(), written via collision->write_buf,
     * about to be freed below) when it is attached to the ongoing FSM
     * for the first time. That send used TCP_WRITE_FLAG_COPY, so lwIP
     * already holds its own copy and does not care about our tx
     * bookkeeping - but without resetting it here, bgp_session_send()
     * would see tcpc->tx.buf pointing at a different (and, once
     * bgp_session_collision_free() runs, freed) buffer than
     * session->write_buf, and bbl_tcp_send() would refuse to queue the
     * KEEPALIVE at all while state is still SENDING. That silently
     * drops our KEEPALIVE and leaves the peer hanging in OpenConfirm,
     * even though our own state machine (which does not check whether
     * the send actually succeeded) proceeds straight to Established. */
    session->tcpc->state = BBL_TCP_STATE_IDLE;
    session->tcpc->tx.buf = NULL;
    session->tcpc->tx.len = 0;
    session->tcpc->tx.offset = 0;

    bgp_session_reset_write_buffer(session);

    /* Carry over any bytes buffered past the OPEN we just parsed (rare
     * pipelining, e.g. an immediate KEEPALIVE arriving in the same segment). */
    leftover = collision->read_buf.idx - collision->read_buf.start_idx;
    if(leftover > session->read_buf.size) {
        leftover = 0; /* pathological; drop rather than overflow */
    }
    if(leftover) {
        memcpy(session->read_buf.data, collision->read_buf.data + collision->read_buf.start_idx, leftover);
    }
    session->read_buf.idx = leftover;
    session->read_buf.start_idx = 0;

    /* Ownership of the tcpc has moved to session->tcpc. */
    collision->tcpc = NULL;
    bgp_session_collision_free(session);

    bgp_session_state_change(session, BGP_OPENCONFIRM);

    if(trigger_is_primary) {
        /* Called from within bgp_open()'s processing of the old primary's
         * (now-stale) buffer: signal the caller to stop immediately rather
         * than falling through to arithmetic on a buffer that no longer
         * corresponds to session->tcpc. */
        session->collision_promoted = true;
    } else if(leftover) {
        /* Bytes already sitting in the winning buffer: process them now. */
        bgp_receive_cb(session, NULL, 0);
    }
}
