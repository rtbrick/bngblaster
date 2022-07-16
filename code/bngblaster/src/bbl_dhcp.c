/*
 * BNG Blaster (BBL) - DHCP
 *
 * Christian Giese, April 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_dhcp.h"
#include "bbl_session.h"

/**
 * bbl_dhcp_stop
 *
 * This function stops the DHCP negotiation.
 *
 * @param session session
 */
void
bbl_dhcp_stop(bbl_session_s *session) {
    bbl_interface_s *interface = session->interface;
    bbl_ctx_s *ctx = interface->ctx;

    LOG(DHCP, "DHCP (ID: %u) Stop DHCP\n", session->session_id);

    /* Reset session IP configuration */
    session->ip_address = 0;
    session->ip_netmask = 0;
    session->peer_ip_address = 0;
    session->dns1 = 0;
    session->dns2 = 0;

    /* Stop session traffic */
    timer_del(session->timer_session_traffic_ipv4);

    /* Stop multicast ... */
    timer_del(session->timer_igmp);
    timer_del(session->timer_zapping);
    session->zapping_joined_group = NULL;
    session->zapping_leaved_group = NULL;
    session->zapping_count = 0;
    session->zapping_view_start_time.tv_sec = 0;
    session->zapping_view_start_time.tv_nsec = 0;

    /* Reset DHCP */
    timer_del(session->timer_dhcp_retry);
    timer_del(session->timer_dhcp_t1);
    timer_del(session->timer_dhcp_t2);
    session->dhcp_address = 0;
    session->dhcp_lease_time = 0;
    session->dhcp_t1 = 0;
    session->dhcp_t2 = 0;
    session->dhcp_server = 0;
    session->dhcp_server_identifier = 0;
    memset(&session->dhcp_server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
    session->dhcp_lease_timestamp.tv_sec = 0;
    session->dhcp_lease_timestamp.tv_nsec = 0;
    session->dhcp_request_timestamp.tv_sec = 0;
    session->dhcp_request_timestamp.tv_nsec = 0;
    if(session->dhcp_host_name) {
        free(session->dhcp_host_name);
        session->dhcp_host_name = NULL;
    }
    if(session->dhcp_domain_name) {
        free(session->dhcp_domain_name);
        session->dhcp_domain_name = NULL;
    }

    if(session->dhcp_established && ctx->dhcp_established) {
        ctx->dhcp_established--;
    }
    session->dhcp_established = false;
    if(session->dhcp_requested && ctx->dhcp_requested) {
        ctx->dhcp_requested--;
    }
    session->dhcp_requested = false;
}

/**
 * bbl_dhcp_start
 *
 * This function starts the DHCP negotiation.
 *
 * @param session session
 */
void
bbl_dhcp_start(bbl_session_s *session) {

    if(!session->dhcp_requested) {
        session->dhcp_requested = true;
        session->interface->ctx->dhcp_requested++;

        /* Init DHCP */
        session->dhcp_state = BBL_DHCP_SELECTING;
        session->dhcp_xid = rand();
        session->dhcp_retry = 0;
        session->send_requests |= BBL_SEND_DHCP_REQUEST;

        LOG(DHCP, "DHCP (ID: %u) Start DHCP\n", session->session_id);
    }
}

/**
 * bbl_dhcp_restart
 *
 * This function restarts the DHCP negotiation.
 *
 * @param session session
 */
void
bbl_dhcp_restart(bbl_session_s *session) {
    bbl_dhcp_stop(session);
    bbl_dhcp_start(session);
    bbl_session_tx_qnode_insert(session);
}

void
bbl_dhcp_t1(timer_s *timer) {
    bbl_session_s *session = timer->data;
    if(session->dhcp_state == BBL_DHCP_BOUND) {
        session->dhcp_xid = rand();
        session->dhcp_request_timestamp.tv_sec = 0;
        session->dhcp_request_timestamp.tv_nsec = 0;
        session->dhcp_state = BBL_DHCP_RENEWING;
        session->dhcp_retry = 0;
        session->send_requests |= BBL_SEND_DHCP_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_dhcp_t2(timer_s *timer) {
    bbl_session_s *session = timer->data;
    LOG(DHCP, "DHCP (ID: %u) Lease expired\n", session->session_id);
    bbl_dhcp_restart(session);
}

/**
 * bbl_dhcp_rx
 *
 * DHCP packet receive handler for IPoE sessions.
 *
 * @param eth ethernet packet received
 * @param dhcp dhcp header of received packet
 * @param session session
 */
void
bbl_dhcp_rx(bbl_ethernet_header_t *eth, bbl_dhcp_t *dhcp, bbl_session_s *session) {

    bbl_interface_s *interface = session->interface;
    bbl_ctx_s *ctx = interface->ctx;
    bbl_access_traffic_statistics_s *access_stats = &ctx->access_statistics[session->session_id-1];

    /* Ignore packets received in wrong state */
    if(session->dhcp_state == BBL_DHCP_INIT) {
        return;
    }

    /* Ignore packets with wrong transaction identifier! */
    if(dhcp->header->xid != session->dhcp_xid) {
        return;
    }

    switch(dhcp->type) {
        case DHCP_MESSAGE_OFFER:
            access_stats->dhcp_rx_offer++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-Offer received\n", session->session_id);
            break;
        case DHCP_MESSAGE_ACK:
            access_stats->dhcp_rx_ack++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-ACK received\n", session->session_id);
            break;
        case DHCP_MESSAGE_NAK:
            access_stats->dhcp_rx_nak++;
            LOG(DHCP, "DHCP (ID: %u) DHCP-NAK received\n", session->session_id);
            break;
        default:
            /* Not expected ... */
            return;
    }

    switch(session->dhcp_state) {
        case BBL_DHCP_SELECTING:
            if(dhcp->type == DHCP_MESSAGE_OFFER) {
                session->dhcp_state = BBL_DHCP_REQUESTING;
                session->dhcp_address = dhcp->header->yiaddr;
                session->dhcp_server = dhcp->header->siaddr;
                session->dhcp_server_identifier = dhcp->server_identifier;
                memcpy(session->dhcp_server_mac, eth->src, ETH_ADDR_LEN);
                session->dhcp_lease_time = dhcp->lease_time;
                session->dhcp_lease_timestamp.tv_sec = eth->timestamp.tv_sec;
                session->dhcp_lease_timestamp.tv_nsec = eth->timestamp.tv_nsec;
                if(!(session->dhcp_address && session->dhcp_server_identifier && session->dhcp_lease_time)) {
                    LOG(ERROR, "DHCP (ID: %u) Invalid DHCP-Offer!\n", session->session_id);
                    bbl_dhcp_restart(session);
                    return;
                }
                timer_add(&ctx->timer_root, &session->timer_dhcp_t2, "DHCP T2", session->dhcp_lease_time, 0, session, &bbl_dhcp_t2);
                session->dhcp_retry = 0;
                session->send_requests |= BBL_SEND_DHCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
            break;
        case BBL_DHCP_REQUESTING:
            if(dhcp->type == DHCP_MESSAGE_ACK) {
                session->dhcp_address = dhcp->header->yiaddr;
                session->dhcp_server = dhcp->header->siaddr;
                session->dhcp_server_identifier = dhcp->server_identifier;
                session->dhcp_lease_time = dhcp->lease_time;
                session->dhcp_lease_timestamp.tv_sec = eth->timestamp.tv_sec;
                session->dhcp_lease_timestamp.tv_nsec = eth->timestamp.tv_nsec;
                if(!(session->dhcp_address && session->dhcp_server_identifier && session->dhcp_lease_time)) {
                    LOG(ERROR, "DHCP (ID: %u) Invalid DHCP-ACK!\n", session->session_id);
                    bbl_dhcp_restart(session);
                    return;
                }
                /* Update session ... */
                if(session->dhcp_address != session->ip_address) {
                    LOG(IP, "IPv4 (ID: %u) address %s\n", session->session_id,
                        format_ipv4_address(&session->dhcp_address));
                }
                session->ip_address = session->dhcp_address;
                if(dhcp->option_netmask) {
                    session->ip_netmask = dhcp->netmask;
                }
                if(dhcp->option_router && dhcp->router) {
                    session->peer_ip_address = dhcp->router;
                } else {
                    /* Can't proceed without router-option received! */
                    LOG(ERROR, "DHCP (ID: %u) Missing router-option in DHCP-ACK!\n", session->session_id);
                    bbl_dhcp_restart(session);
                    return;
                }
                if(dhcp->option_dns1) {
                    session->dns1 = dhcp->dns1;
                }
                if(dhcp->option_dns2) {
                    session->dns2 = dhcp->dns2;
                }
                if(dhcp->option_host_name) {
                    if(session->dhcp_host_name) {
                        free(session->dhcp_host_name);
                    }
                    session->dhcp_host_name = calloc(1, dhcp->host_name_len +1);
                    strncpy(session->dhcp_host_name, dhcp->host_name, dhcp->host_name_len);
                }
                if(dhcp->option_domain_name) {
                    if(session->dhcp_domain_name) {
                        free(session->dhcp_domain_name);
                    }
                    session->dhcp_domain_name = calloc(1, dhcp->domain_name_len +1);
                    strncpy(session->dhcp_domain_name, dhcp->domain_name, dhcp->domain_name_len);
                }
                session->dhcp_t1 = 0.5 * session->dhcp_lease_time; if(!session->dhcp_t1) session->dhcp_t1 = 1;
                session->dhcp_t2 = 0.875 * session->dhcp_lease_time; if(!session->dhcp_t2) session->dhcp_t2 = 1;

                session->send_requests &= ~BBL_SEND_DHCP_REQUEST;
                if(!session->dhcp_established) {
                    session->dhcp_established = true;
                    ctx->dhcp_established++;
                    if(ctx->dhcp_established > ctx->dhcp_established_max) {
                        ctx->dhcp_established_max = ctx->dhcp_established;
                    }
                }
                session->dhcp_state = BBL_DHCP_BOUND;
                timer_add(&ctx->timer_root, &session->timer_dhcp_t1, "DHCP T1", session->dhcp_t1, 0, session, &bbl_dhcp_t1);
                timer_add(&ctx->timer_root, &session->timer_dhcp_t2, "DHCP T2", session->dhcp_t2, 0, session, &bbl_dhcp_t2);
                session->send_requests |= BBL_SEND_ARP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            } else if (dhcp->type == DHCP_MESSAGE_NAK) {
                bbl_dhcp_restart(session);
            }
            break;
        case BBL_DHCP_RENEWING:
            if(dhcp->type == DHCP_MESSAGE_ACK) {
                session->dhcp_state = BBL_DHCP_BOUND;
                session->dhcp_address = dhcp->header->yiaddr;
                session->dhcp_server = dhcp->header->siaddr;
                session->dhcp_server_identifier = dhcp->server_identifier;
                session->dhcp_lease_time = dhcp->lease_time;
                session->dhcp_lease_timestamp.tv_sec = eth->timestamp.tv_sec;
                session->dhcp_lease_timestamp.tv_nsec = eth->timestamp.tv_nsec;
                if(!(session->dhcp_address && session->dhcp_server_identifier && session->dhcp_lease_time)) {
                    LOG(ERROR, "DHCP (ID: %u) Invalid DHCP-ACK!\n", session->session_id);
                    bbl_dhcp_restart(session);
                    return;
                }
                session->dhcp_t1 = 0.5 * session->dhcp_lease_time; if(!session->dhcp_t1) session->dhcp_t1 = 1;
                session->dhcp_t2 = 0.875 * session->dhcp_lease_time; if(!session->dhcp_t2) session->dhcp_t2 = 1;
                timer_add(&ctx->timer_root, &session->timer_dhcp_t1, "DHCP T1", session->dhcp_t1, 0, session, &bbl_dhcp_t1);
                timer_add(&ctx->timer_root, &session->timer_dhcp_t2, "DHCP T2", session->dhcp_t2, 0, session, &bbl_dhcp_t2);
                session->send_requests |= BBL_SEND_ARP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            } else if (dhcp->type == DHCP_MESSAGE_NAK) {
                bbl_dhcp_restart(session);
            }
            break;
        default:
            break;
    }
    return;
}
