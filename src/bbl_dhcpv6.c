/*
 * BNG Blaster (BBL) - DHCPv6
 *
 * Christian Giese, May 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_dhcpv6.h"
#include "bbl_session.h"
#include "bbl_session_traffic.h"
#include "bbl_rx.h"

/**
 * bbl_dhcpv6_stop
 *
 * This function stops the DHCPv6 negotiation.
 *
 * @param session session
 */
void
bbl_dhcpv6_stop(bbl_session_s *session) {
    bbl_interface_s *interface = session->interface;
    bbl_ctx_s *ctx = interface->ctx;

    LOG(DHCP, "DHCP (ID: %u) Stop DHCPv6\n", session->session_id);

    /* Reset session IP configuration */
    if(session->access_type == ACCESS_TYPE_IPOE) {
        session->ipv6_prefix.len = 0;
        memset(session->ipv6_address, 0x0, IPV6_ADDR_LEN);
        timer_del(session->timer_session_traffic_ipv6);
    }
    session->delegated_ipv6_prefix.len = 0;
    memset(session->delegated_ipv6_address, 0x0, IPV6_ADDR_LEN);
    timer_del(session->timer_session_traffic_ipv6pd);

    /* Reset DHCPv6 */
    timer_del(session->timer_dhcpv6);
    timer_del(session->timer_dhcpv6_t1);
    timer_del(session->timer_dhcpv6_t2);
    session->dhcpv6_state = BBL_DHCP_INIT;
    session->dhcpv6_ia_na_option_len = 0;
    session->dhcpv6_ia_pd_option_len = 0;
    session->dhcpv6_t1 = 0;
    session->dhcpv6_t2 = 0;
    memset(session->dhcpv6_dns1, 0x0, IPV6_ADDR_LEN);
    memset(session->dhcpv6_dns2, 0x0, IPV6_ADDR_LEN);
    memset(session->dhcpv6_server_duid, 0x0, DHCPV6_BUFFER);
    session->dhcpv6_server_duid_len = 0;
    session->dhcpv6_lease_time = 0;
    session->dhcpv6_lease_timestamp.tv_sec = 0;
    session->dhcpv6_lease_timestamp.tv_nsec = 0;
    session->dhcpv6_request_timestamp.tv_sec = 0;
    session->dhcpv6_request_timestamp.tv_nsec = 0;
    if(session->dhcpv6_established && ctx->dhcpv6_established) {
        ctx->dhcpv6_established--;
    }
    session->dhcpv6_established = false;
    if(session->dhcpv6_requested && ctx->dhcpv6_requested) {
        ctx->dhcpv6_requested--;
    }
    session->dhcpv6_requested = false;
}

/**
 * bbl_dhcpv6_start
 *
 * This function starts the DHCPv6 negotiation.
 *
 * @param session session
 */
void
bbl_dhcpv6_start(bbl_session_s *session) {

    if(!session->dhcpv6_requested) {
        session->dhcpv6_requested = true;
        session->interface->ctx->dhcpv6_requested++;

        /* Init DHCPv6 */
        session->dhcpv6_state = BBL_DHCP_SELECTING;
        session->dhcpv6_xid = rand() & 0xffffff;

        if(session->access_type == ACCESS_TYPE_IPOE) {
            session->dhcpv6_ia_na_iaid = rand();
            if(!session->dhcpv6_ia_na_iaid) session->dhcpv6_ia_na_iaid = 1;
        }
        
        session->dhcpv6_ia_pd_iaid = rand();
        if(session->dhcpv6_ia_pd_iaid == session->dhcpv6_ia_na_iaid) {
            session->dhcpv6_ia_pd_iaid = session->dhcpv6_ia_na_iaid + 1;
        }
        if(!session->dhcpv6_ia_pd_iaid) session->dhcpv6_ia_na_iaid = 2;
        session->dhcpv6_retry = 0;
        session->send_requests |= BBL_SEND_DHCPV6_REQUEST;

        LOG(DHCP, "DHCPv6 (ID: %u) Start DHCPv6\n", session->session_id);
    }
}

/**
 * bbl_dhcpv6_restart
 *
 * This function restarts the DHCPv6 negotiation.
 *
 * @param session session
 */
void
bbl_dhcpv6_restart(bbl_session_s *session) {
    bbl_dhcpv6_stop(session);
    bbl_dhcpv6_start(session);
    bbl_session_tx_qnode_insert(session);
}

void
bbl_dhcpv6_t1(timer_s *timer) {
    bbl_session_s *session = timer->data;
    if(session->dhcpv6_state == BBL_DHCP_BOUND) {
        session->dhcpv6_xid = rand() & 0xffffff;
        session->dhcpv6_request_timestamp.tv_sec = 0;
        session->dhcpv6_request_timestamp.tv_nsec = 0;
        session->dhcpv6_state = BBL_DHCP_RENEWING;
        session->dhcpv6_retry = 0;
        session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_dhcpv6_t2(timer_s *timer) {
    bbl_session_s *session = timer->data;
    LOG(DHCP, "DHCPv6 (ID: %u) Lease expired\n", session->session_id);
    bbl_dhcpv6_restart(session);
}

/**
 * bbl_dhcpv6_rx
 *
 * DHCPv6 packet receive handler for PPPoE and IPoE sessions.
 *
 * @param eth ethernet packet received
 * @param dhcpv6 dhcpv6 header of received packet
 * @param session session
 */
void
bbl_dhcpv6_rx(bbl_ethernet_header_t *eth, bbl_dhcpv6_t *dhcpv6, bbl_session_s *session) {

    bbl_interface_s *interface = session->interface;
    bbl_ctx_s *ctx = interface->ctx;

    /* Ignore packets received in wrong state */
    if(session->dhcpv6_state == BBL_DHCP_INIT) {
        return;
    }

    /* Ignore packets with wrong transaction identifier */
    if(dhcpv6->xid != session->dhcpv6_xid) {
        return;
    }

    if(dhcpv6->server_duid_len && dhcpv6->server_duid_len < DHCPV6_BUFFER) {
        memcpy(session->dhcpv6_server_duid, dhcpv6->server_duid, dhcpv6->server_duid_len);
        session->dhcpv6_server_duid_len = dhcpv6->server_duid_len;
    }
    if(dhcpv6->ia_na_option_len && dhcpv6->ia_na_option_len < DHCPV6_BUFFER) {
        memcpy(session->dhcpv6_ia_na_option, dhcpv6->ia_na_option, dhcpv6->ia_na_option_len);
        session->dhcpv6_ia_na_option_len = dhcpv6->ia_na_option_len;
    }
    if(dhcpv6->ia_pd_option_len && dhcpv6->ia_pd_option_len < DHCPV6_BUFFER) {
        memcpy(session->dhcpv6_ia_pd_option, dhcpv6->ia_pd_option, dhcpv6->ia_pd_option_len);
        session->dhcpv6_ia_pd_option_len = dhcpv6->ia_pd_option_len;
    }

    if(dhcpv6->type == DHCPV6_MESSAGE_REPLY) {
        LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Reply received\n", session->session_id);
        session->stats.dhcpv6_rx_reply++;
        /* Handle DHCPv6 teardown */
        if(session->dhcpv6_state == BBL_DHCP_RELEASE) {
            session->dhcpv6_state = session->dhcpv6_state == BBL_DHCP_INIT;
            if(session->session_state == BBL_TERMINATING) {
                bbl_session_clear(ctx, session);
            }
            return;
        } 
        /* Establish DHCPv6 */
        if(!session->dhcpv6_established) {
            session->dhcpv6_established = true;
            ctx->dhcpv6_established++;
            if(ctx->dhcpv6_established > ctx->dhcpv6_established_max) {
                ctx->dhcpv6_established_max = ctx->dhcpv6_established;
            }
            if(dhcpv6->dns1) {
                memcpy(&session->dhcpv6_dns1, dhcpv6->dns1, IPV6_ADDR_LEN);
                if(dhcpv6->dns2) {
                    memcpy(&session->dhcpv6_dns2, dhcpv6->dns2, IPV6_ADDR_LEN);
                }
            }
            if(session->access_type == ACCESS_TYPE_IPOE && dhcpv6->ia_na_address) {
                /* IA_NA */
                if(dhcpv6->ia_na_valid_lifetime) session->dhcpv6_lease_time = dhcpv6->ia_na_valid_lifetime;
                if(dhcpv6->ia_na_t1) session->dhcpv6_t1 = dhcpv6->ia_na_t1;
                if(dhcpv6->ia_na_t2) session->dhcpv6_t2 = dhcpv6->ia_na_t2;
                memcpy(&session->ipv6_address, dhcpv6->ia_na_address, sizeof(ipv6addr_t));
                memcpy(&session->ipv6_prefix.address, dhcpv6->ia_na_address, sizeof(ipv6addr_t));
                session->ipv6_prefix.len = 128;
                LOG(IP, "IPv6 (ID: %u) DHCPv6 IA_NA address %s/128\n", session->session_id,
                    format_ipv6_address(&session->ipv6_address));
            }
            if(dhcpv6->ia_pd_prefix && dhcpv6->ia_pd_prefix->len) {
                /* IA_PD */
                if(dhcpv6->ia_pd_valid_lifetime) session->dhcpv6_lease_time = dhcpv6->ia_pd_valid_lifetime;
                if(dhcpv6->ia_pd_t1) session->dhcpv6_t1 = dhcpv6->ia_pd_t1;
                if(dhcpv6->ia_pd_t2) session->dhcpv6_t2 = dhcpv6->ia_pd_t2;
                memcpy(&session->delegated_ipv6_prefix, dhcpv6->ia_pd_prefix, sizeof(ipv6_prefix));
                *(uint64_t*)&session->delegated_ipv6_address[0] = *(uint64_t*)session->delegated_ipv6_prefix.address;
                session->delegated_ipv6_address[15] = 0x01;
                LOG(IP, "IPv6 (ID: %u) DHCPv6 IA_PD prefix %s/%d\n", session->session_id,
                    format_ipv6_address(&session->delegated_ipv6_prefix.address), session->delegated_ipv6_prefix.len);
            }
        }
        session->send_requests &= ~BBL_SEND_DHCPV6_REQUEST;
        session->dhcpv6_lease_timestamp.tv_sec = eth->timestamp.tv_sec;
        session->dhcpv6_lease_timestamp.tv_nsec = eth->timestamp.tv_nsec;
        session->dhcpv6_state = BBL_DHCP_BOUND;
        if(session->dhcpv6_t1) {
            timer_add(&ctx->timer_root, &session->timer_dhcpv6_t1, "DHCPv6 T1", session->dhcpv6_t1, 0, session, &bbl_dhcpv6_t1);
        }
        if(session->dhcpv6_t2) {
            timer_add(&ctx->timer_root, &session->timer_dhcpv6_t2, "DHCPv6 T2", session->dhcpv6_t2, 0, session, &bbl_dhcpv6_t2);
        }
        bbl_rx_established_ipoe(eth, interface, session);
        session->send_requests |= BBL_SEND_ICMPV6_RS;
        bbl_session_tx_qnode_insert(session);
    } else if(dhcpv6->type == DHCPV6_MESSAGE_ADVERTISE) {
        LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Advertise received\n", session->session_id);
        session->stats.dhcpv6_rx_advertise++;
        session->dhcpv6_state = BBL_DHCP_REQUESTING;
        session->dhcpv6_retry = 0;
        session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}