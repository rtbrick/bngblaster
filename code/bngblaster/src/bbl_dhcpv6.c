/*
 * BNG Blaster (BBL) - DHCPv6
 *
 * Christian Giese, May 2021
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_dhcpv6.h"
#include "bbl_session.h"
#include "bbl_rx.h"

const char*
bbl_dhcpv6_status_code_string(uint16_t status_code)
{
    switch(status_code) {
        case DHCPV6_STATUS_CODE_SUCCESS: return "Success";
        case DHCPV6_STATUS_CODE_UNSPECFAIL: return "UnspecFail";
        case DHCPV6_STATUS_CODE_NOADDRSAVAIL: return "NoAddrsAvail";
        case DHCPV6_STATUS_CODE_NOBINDING: return "NoBinding";
        case DHCPV6_STATUS_CODE_NOTONLINK: return "NotOnLink";
        case DHCPV6_STATUS_CODE_USEMULTICAST: return "UseMulticast";
        case DHCPV6_STATUS_CODE_NOPREFIXAVAIL: return "NoPrefixAvail";
        default: return "unkown";
    }
}

/**
 * bbl_dhcpv6_stop
 *
 * This function stops the DHCPv6 negotiation.
 *
 * @param session session
 */
void
bbl_dhcpv6_stop(bbl_session_s *session)
{
    if(session->dhcpv6_state == BBL_DHCP_DISABLED) {
        return;
    }

    LOG(DHCP, "DHCP (ID: %u) Stop DHCPv6\n", session->session_id);

    /* Reset session IP configuration */
    if(session->access_type == ACCESS_TYPE_IPOE) {
        session->ipv6_prefix.len = 0;
        memset(session->ipv6_address, 0x0, IPV6_ADDR_LEN);
        ENABLE_ENDPOINT(session->endpoint.ipv6);
    }
    session->delegated_ipv6_prefix.len = 0;
    memset(session->delegated_ipv6_address, 0x0, IPV6_ADDR_LEN);
    ENABLE_ENDPOINT(session->endpoint.ipv6pd);
    /* Reset DHCPv6 */
    timer_del(session->timer_dhcpv6);
    timer_del(session->timer_dhcpv6_t1);
    timer_del(session->timer_dhcpv6_t2);
    session->version++;
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
    if(session->dhcpv6_established && g_ctx->dhcpv6_established) {
        g_ctx->dhcpv6_established--;
    }
    session->dhcpv6_established = false;
    if(session->dhcpv6_requested && g_ctx->dhcpv6_requested) {
        g_ctx->dhcpv6_requested--;
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
bbl_dhcpv6_start(bbl_session_s *session)
{
    static uint32_t g_dhcpv6_iaid = 1;
    if(g_dhcpv6_iaid > UINT32_MAX-10) {
        g_dhcpv6_iaid = 1;
    }

    if(!session->dhcpv6_requested) {
        session->dhcpv6_requested = true;
        g_ctx->dhcpv6_requested++;

        /* Init DHCPv6 */
        session->dhcpv6_state = BBL_DHCP_SELECTING;
        session->dhcpv6_xid = rand() & 0xffffff;

        if(g_ctx->config.dhcpv6_ia_na && 
           session->access_type == ACCESS_TYPE_IPOE) {
            session->dhcpv6_ia_na_iaid = g_dhcpv6_iaid++;
        }
        if(g_ctx->config.dhcpv6_ia_pd) {
            session->dhcpv6_ia_pd_iaid = g_dhcpv6_iaid++;
        }

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
bbl_dhcpv6_restart(bbl_session_s *session)
{
    bbl_dhcpv6_stop(session);
    bbl_dhcpv6_start(session);
    bbl_session_tx_qnode_insert(session);
}

void
bbl_dhcpv6_s1(timer_s *timer)
{
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
bbl_dhcpv6_s2(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    LOG(DHCP, "DHCPv6 (ID: %u) Lease expired\n", session->session_id);
    bbl_dhcpv6_restart(session);
}

static bool
bbl_dhcpv6_validate_ia(bbl_session_s *session, bbl_dhcpv6_s *dhcpv6)
{
    if(dhcpv6->ia_na_status_code) {
        LOG(DHCP, "DHCPv6 (ID: %u) IA_NA received with status code %u (%s)\n", 
            session->session_id, dhcpv6->ia_na_status_code, 
            bbl_dhcpv6_status_code_string(dhcpv6->ia_na_status_code));
        return false;
    }

    if(session->dhcpv6_ia_na_iaid && !dhcpv6->ia_na_address) {
        LOG(DHCP, "DHCPv6 (ID: %u) missing IA_NA address\n", session->session_id);
        return false;
    }

    if(dhcpv6->ia_pd_status_code) {
        LOG(DHCP, "DHCPv6 (ID: %u) IA_PD received with status code %u (%s)\n", 
            session->session_id, dhcpv6->ia_pd_status_code, 
            bbl_dhcpv6_status_code_string(dhcpv6->ia_pd_status_code));
        return false;
    }

    if(session->dhcpv6_ia_pd_iaid && !(dhcpv6->ia_pd_prefix && dhcpv6->ia_pd_prefix->len)) {
        LOG(DHCP, "DHCPv6 (ID: %u) missing IA_PD prefix\n", session->session_id);
        return false;
    }

    return true;
}

/**
 * bbl_dhcpv6_rx
 *
 * DHCPv6 packet receive handler for PPPoE and IPoE sessions.
 *
 * @param session session
 * @param eth ethernet packet received
 * @param dhcpv6 dhcpv6 header of received packet
 */
void
bbl_dhcpv6_rx(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_dhcpv6_s *dhcpv6)
{
    bbl_access_interface_s *interface = session->access_interface;

    /* Ignore packets received in wrong state */
    if(session->dhcpv6_state <= BBL_DHCP_INIT) {
        return;
    }

    if(dhcpv6->type == DHCPV6_MESSAGE_RELAY_REPL) {
        if(!dhcpv6->relay_message) {
            /* Invalid packet received */
            return;
        }
        dhcpv6 = dhcpv6->relay_message;
    }

    /* Ignore packets with wrong transaction identifier */
    if(dhcpv6->xid != session->dhcpv6_xid) {
        return;
    }

    if(dhcpv6->server_duid_len && dhcpv6->server_duid_len < DHCPV6_BUFFER) {
        memcpy(session->dhcpv6_server_duid, dhcpv6->server_duid, dhcpv6->server_duid_len);
        session->dhcpv6_server_duid_len = dhcpv6->server_duid_len;
    }
    if(dhcpv6->ia_na_address && dhcpv6->ia_na_option_len && dhcpv6->ia_na_option_len < DHCPV6_BUFFER) {
        memcpy(session->dhcpv6_ia_na_option, dhcpv6->ia_na_option, dhcpv6->ia_na_option_len);
        session->dhcpv6_ia_na_option_len = dhcpv6->ia_na_option_len;
    }
    if(dhcpv6->ia_pd_prefix && dhcpv6->ia_pd_prefix->len && dhcpv6->ia_pd_option_len && dhcpv6->ia_pd_option_len < DHCPV6_BUFFER) {
        memcpy(session->dhcpv6_ia_pd_option, dhcpv6->ia_pd_option, dhcpv6->ia_pd_option_len);
        session->dhcpv6_ia_pd_option_len = dhcpv6->ia_pd_option_len;
    }

    if(dhcpv6->type == DHCPV6_MESSAGE_REPLY) {
        LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Reply received\n", session->session_id);
        session->stats.dhcpv6_rx_reply++;

        /* Handle DHCPv6 teardown */
        if(session->dhcpv6_state == BBL_DHCP_RELEASE) {
            session->dhcpv6_state = BBL_DHCP_INIT;
            if(session->session_state == BBL_TERMINATING) {
                bbl_session_clear(session);
            }
            return;
        }

        /* Validate DHCPv6 IA */
        if(!bbl_dhcpv6_validate_ia(session, dhcpv6)) {
            return;
        }

        /* Establish DHCPv6 */
        if(!session->dhcpv6_established) {
            session->dhcpv6_established = true;
            g_ctx->dhcpv6_established++;
            if(g_ctx->dhcpv6_established > g_ctx->dhcpv6_established_max) {
                g_ctx->dhcpv6_established_max = g_ctx->dhcpv6_established;
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
                session->version++;
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
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    ACTIVATE_ENDPOINT(session->endpoint.ipv6pd);
                }
                session->version++;
                LOG(IP, "IPv6 (ID: %u) DHCPv6 IA_PD prefix %s/%d\n", session->session_id,
                    format_ipv6_address(&session->delegated_ipv6_prefix.address), session->delegated_ipv6_prefix.len);
            }
        }
        session->send_requests &= ~BBL_SEND_DHCPV6_REQUEST;
        session->dhcpv6_lease_timestamp.tv_sec = eth->timestamp.tv_sec;
        session->dhcpv6_lease_timestamp.tv_nsec = eth->timestamp.tv_nsec;
        session->dhcpv6_state = BBL_DHCP_BOUND;
        if(session->dhcpv6_t1) {
            timer_add(&g_ctx->timer_root, &session->timer_dhcpv6_t1, "DHCPv6 T1", 
                      session->dhcpv6_t1, 0, session, &bbl_dhcpv6_s1);
        }
        if(session->dhcpv6_t2) {
            timer_add(&g_ctx->timer_root, &session->timer_dhcpv6_t2, "DHCPv6 T2", 
                      session->dhcpv6_t2, 0, session, &bbl_dhcpv6_s2);
        }
        if(session->access_type == ACCESS_TYPE_IPOE) {
            bbl_access_rx_established_ipoe(interface, session, eth);
            session->send_requests |= BBL_SEND_ICMPV6_RS;
            bbl_session_tx_qnode_insert(session);
        }
    } else if(dhcpv6->type == DHCPV6_MESSAGE_ADVERTISE) {
        LOG(DHCP, "DHCPv6 (ID: %u) DHCPv6-Advertise received\n", session->session_id);
        session->stats.dhcpv6_rx_advertise++;

        /* Validate DHCPv6 IA */
        if(!bbl_dhcpv6_validate_ia(session, dhcpv6)) {
            return;
        }

        session->dhcpv6_state = BBL_DHCP_REQUESTING;
        session->dhcpv6_retry = 0;
        session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
        bbl_session_tx_qnode_insert(session);
    }
}