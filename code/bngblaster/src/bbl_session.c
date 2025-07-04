/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_stats.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

extern volatile bool g_teardown;
extern volatile bool g_monkey;

static void
bbl_session_traffic_enable(bool enabled, bbl_session_s *session, uint8_t direction)
{
    bbl_stream_s *stream = session->streams.head;
    while(stream) {
        if(stream->session_traffic && stream->direction & direction) {
            stream->enabled = enabled;
        }
        stream = stream->session_next;
    }
}

const char *
session_state_string(uint32_t state)
{
    switch(state) {
        case BBL_IDLE: return "Idle";
        case BBL_IPOE_SETUP: return "IPoE Setup";
        case BBL_PPPOE_INIT: return "PPPoE Init";
        case BBL_PPPOE_REQUEST: return "PPPoE Request";
        case BBL_PPP_LINK: return "PPP Link";
        case BBL_PPP_AUTH: return "PPP Authentication";
        case BBL_PPP_NETWORK: return "PPP Network";
        case BBL_ESTABLISHED: return "Established";
        case BBL_PPP_TERMINATING: return "PPP Terminating";
        case BBL_TERMINATING: return "Terminating";
        case BBL_TERMINATED: return "Terminated";
        default: return "N/A";
    }
}

const char *
ppp_state_string(uint32_t state)
{
    switch(state) {
        case BBL_PPP_DISABLED: return "Disabled";
        case BBL_PPP_REJECTED: return "Rejected";
        case BBL_PPP_CLOSED: return "Closed";
        case BBL_PPP_INIT: return "Init";
        case BBL_PPP_LOCAL_ACK: return "Local-Ack";
        case BBL_PPP_PEER_ACK: return "Peer-Ack";
        case BBL_PPP_OPENED: return "Opened";
        case BBL_PPP_TERMINATE: return "Terminate";
        default: return "N/A";
    }
}

const char *
dhcp_state_string(uint32_t state)
{
    switch(state) {
        case BBL_DHCP_DISABLED: return "Disabled";
        case BBL_DHCP_INIT: return "Init";
        case BBL_DHCP_SELECTING: return "Selecting";
        case BBL_DHCP_REQUESTING: return "Requesting";
        case BBL_DHCP_BOUND: return "Bound";
        case BBL_DHCP_RENEWING: return "Renewing";
        case BBL_DHCP_RELEASE: return "Releasing";
        default: return "N/A";
    }
}

void
bbl_session_tx_qnode_insert(bbl_session_s *session)
{
    bbl_access_interface_s *interface = session->access_interface;
    if(CIRCLEQ_NEXT(session, session_tx_qnode)) {
        return;
    }
    CIRCLEQ_INSERT_TAIL(&interface->session_tx_qhead, session, session_tx_qnode);
}

void
bbl_session_tx_qnode_remove(bbl_session_s *session)
{
    bbl_access_interface_s *interface = session->access_interface;
    CIRCLEQ_REMOVE(&interface->session_tx_qhead, session, session_tx_qnode);
    CIRCLEQ_NEXT(session, session_tx_qnode) = NULL;
    CIRCLEQ_PREV(session, session_tx_qnode) = NULL;
}

void
bbl_session_ncp_open(bbl_session_s *session, bool ipcp) {
    if(session->session_state == BBL_ESTABLISHED ||
       session->session_state == BBL_PPP_NETWORK) {
        if(ipcp) {
            if(session->ipcp_state == BBL_PPP_CLOSED) {
                session->ipcp_state = BBL_PPP_INIT;
                session->ipcp_request_code = PPP_CODE_CONF_REQUEST;
                session->send_requests |= BBL_SEND_IPCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
        } else {
            /* ip6cp */
            if(session->ip6cp_state == BBL_PPP_CLOSED) {
                session->ip6cp_state = BBL_PPP_INIT;
                session->ip6cp_request_code = PPP_CODE_CONF_REQUEST;
                session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
        }
    }
}

void
bbl_session_ncp_close(bbl_session_s *session, bool ipcp) {
    if(session->session_state == BBL_ESTABLISHED ||
       session->session_state == BBL_PPP_NETWORK) {
        if(ipcp) {
            if(session->ipcp_state == BBL_PPP_OPENED) {
                session->ipcp_state = BBL_PPP_TERMINATE;
                session->ipcp_request_code = PPP_CODE_TERM_REQUEST;
                session->send_requests |= BBL_SEND_IPCP_REQUEST;
                session->ip_address = 0;
                session->peer_ip_address = 0;
                session->dns1 = 0;
                session->dns2 = 0;
                bbl_session_tx_qnode_insert(session);
            }
        } else { /* ip6cp */
            if(session->ip6cp_state == BBL_PPP_OPENED) {
                session->ip6cp_state = BBL_PPP_TERMINATE;
                session->ip6cp_request_code = PPP_CODE_TERM_REQUEST;
                session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                /* Stop IPv6 */
                session->ipv6_prefix.len = 0;
                session->icmpv6_ra_received = false;
                memset(session->ipv6_dns1, 0x0, IPV6_ADDR_LEN);
                memset(session->ipv6_dns2, 0x0, IPV6_ADDR_LEN);
                /* Stop DHCPv6 */
                bbl_dhcpv6_stop(session);
                bbl_session_tx_qnode_insert(session);
            }
        }
    }
}

void
bbl_session_rate_job(timer_s *timer) {
    bbl_session_s *session = timer->data;
    bbl_compute_avg_rate(&session->stats.rate_packets_tx, session->stats.packets_tx);
    bbl_compute_avg_rate(&session->stats.rate_packets_rx, session->stats.packets_rx);
    bbl_compute_avg_rate(&session->stats.rate_bytes_tx, session->stats.bytes_tx);
    bbl_compute_avg_rate(&session->stats.rate_bytes_rx, session->stats.bytes_rx);
}

static void
bbl_session_monkey_pppoe(bbl_session_s *session) {
    switch(rand() % 256) {
        case 10:
            /* Clear session. */ 
            bbl_session_clear(session);
            break;
        case 20:
            /* Toggle IPCP */
            if(session->ipcp_state == BBL_PPP_OPENED) {
                bbl_session_ncp_close(session, true);
            } else {
                bbl_session_ncp_open(session, true);
            }
            break;
        case 30:
            /* Toggle IP6CP */
            if(session->ip6cp_state == BBL_PPP_OPENED) {
                bbl_session_ncp_close(session, false);
            } else {
                bbl_session_ncp_open(session, false);
            }
            break;
        case 40:
            /* Send random terminate request */
            session->lcp_request_code = PPP_CODE_TERM_REQUEST;
            session->lcp_options_len = 0;
            session->send_requests |= BBL_SEND_LCP_REQUEST;
            bbl_session_tx_qnode_insert(session);
            break;
        case 50:
            /* Terminate session without PADT */
            bbl_session_update_state(session, BBL_TERMINATED);
            break;
        case 60:
            /* Terminate session with PADT */
            bbl_session_update_state(session, BBL_TERMINATING);
            session->lcp_state = BBL_PPP_CLOSED;
            if(session->ipcp_state > BBL_PPP_DISABLED) {
                session->ipcp_state = BBL_PPP_CLOSED;
            }
            if(session->ip6cp_state > BBL_PPP_DISABLED) {
                session->ip6cp_state = BBL_PPP_CLOSED;
            }
            session->send_requests = BBL_SEND_DISCOVERY;
            bbl_session_tx_qnode_insert(session);
        default:
            break;
    }
}

static void
bbl_session_monkey_ipoe(bbl_session_s *session) {
    switch(rand() % 256) {
        case 10:
            /* Clear session. */ 
            bbl_session_clear(session);
            break;
        case 20:
            /* Release DHCP */
            if(!(session->dhcp_state == BBL_DHCP_DISABLED || 
                 session->dhcp_state == BBL_DHCP_RELEASE)) {

                session->dhcp_state = BBL_DHCP_RELEASE;
                session->dhcp_xid = rand();
                session->dhcp_request_timestamp.tv_sec = 0;
                session->dhcp_request_timestamp.tv_nsec = 0;
                session->dhcp_retry = 0;
                session->send_requests |= BBL_SEND_DHCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
            break;
        case 30:
            /* Release DHCPv6 */
            if(!(session->dhcpv6_state == BBL_DHCP_DISABLED || 
                 session->dhcpv6_state == BBL_DHCP_RELEASE)) {

                session->dhcpv6_state = BBL_DHCP_RELEASE;
                session->dhcpv6_xid = rand() & 0xffffff;
                session->dhcpv6_request_timestamp.tv_sec = 0;
                session->dhcpv6_request_timestamp.tv_nsec = 0;
                session->dhcpv6_retry = 0;
                session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
            break;
        case 40:
            /* Restart DHCPv4 */
            if(session->dhcp_state != BBL_DHCP_DISABLED) {
                bbl_dhcp_restart(session);
            }
            break;
        case 50:
            /* Restart DHCPv6 */
            if(session->dhcpv6_state != BBL_DHCP_DISABLED) {
                bbl_dhcpv6_restart(session);
            }
            break;
        default:
            break;
    }
}

void
bbl_session_monkey_job(timer_s *timer) {
    bbl_session_s *session = timer->data;

    if(g_teardown || !g_monkey) {
        return;
    }

    switch(session->session_state) {
        case BBL_IDLE:
        case BBL_TERMINATED:
            return;
        default:
            break;
    }

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        bbl_session_monkey_pppoe(session);
    } else if(session->access_type == ACCESS_TYPE_IPOE) {
        bbl_session_monkey_ipoe(session);
    }
}

/**
 * bbl_session_get
 *
 * @param session_id session-id
 * @return session or NULL if session not found
 */
bbl_session_s *
bbl_session_get(uint32_t session_id)
{
    if(session_id > g_ctx->sessions || session_id < 1) {
        return NULL;
    }
    return &g_ctx->session_list[session_id-1];
}

void
bbl_session_free(bbl_session_s *session) 
{
    if(session->username) {
        free(session->username);
        session->username = NULL;
    }
    if(session->password) {
        free(session->password);
        session->password = NULL;
    }
    if(session->agent_circuit_id) {
        free(session->agent_circuit_id);
        session->agent_circuit_id = NULL;
    }
    if(session->agent_remote_id) {
        free(session->agent_remote_id);
        session->agent_remote_id = NULL;
    }
    if(session->access_aggregation_circuit_id) {
        free(session->access_aggregation_circuit_id);
        session->access_aggregation_circuit_id = NULL;
    }
    if(session->dhcp_vendor_class_id) {
        free(session->dhcp_vendor_class_id);
        session->dhcp_vendor_class_id = NULL;
    }
    if(session->cfm) {
        free(session->cfm);
        session->cfm = NULL;
    }

    if(session->pppoe_ac_cookie) {
        free(session->pppoe_ac_cookie);
        session->pppoe_ac_cookie = NULL;
    }
    session->pppoe_ac_cookie_len = 0;
    
    if(!g_ctx->config.pppoe_service_name) {
        if(session->pppoe_service_name) {
            free(session->pppoe_service_name);
            session->pppoe_service_name = NULL;
        }
        session->pppoe_service_name_len = 0;
    }

    if(session->reply_message) {
        free(session->reply_message);
        session->reply_message = NULL;
    }
    
    if(session->connections_status_message) {
        free(session->connections_status_message);
        session->connections_status_message = NULL;
    }
}

/**
 * bbl_session_reset
 * 
 * Reset session for reconnect.
 * 
 * @param session session
 */
static void
bbl_session_reset(bbl_session_s *session) {    
    memset(&session->server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
    session->version++;

    session->reconnect_delay = 0;
    session->reconnect_disabled = false;
    timer_del(session->timer_reconnect);

    session->pppoe_retries = 0;
    session->lcp_retries = 0;
    session->lcp_options_len = 0;
    session->lcp_response_code = 0;
    session->lcp_request_code = 0;
    session->auth_protocol = 0;
    session->auth_retries = 0;
    session->ipcp_retries = 0;
    session->ipcp_request_dns1 = g_ctx->config.ipcp_request_dns1;
    session->ipcp_request_dns2 = g_ctx->config.ipcp_request_dns2;
    session->ip6cp_retries = 0;

    session->pppoe_session_id = 0;
    if(session->pppoe_ac_cookie) {
        free(session->pppoe_ac_cookie);
        session->pppoe_ac_cookie = NULL;
    }
    session->pppoe_ac_cookie_len = 0;
    if(!g_ctx->config.pppoe_service_name) {
        if(session->pppoe_service_name) {
            free(session->pppoe_service_name);
            session->pppoe_service_name = NULL;
        }
        session->pppoe_service_name_len = 0;
    }
    session->mru = session->access_config->ppp_mru;
    session->peer_mru = 0;
    session->peer_magic_number = 0;
    session->ip_address = 0;
    session->peer_ip_address = 0;
    session->dns1 = 0;
    session->dns2 = 0;
    session->ipv6_prefix.len = 0;
    session->delegated_ipv6_prefix.len = 0;
    session->arp_resolved = false;
    session->icmpv6_ra_received = false;
    if(session->dhcpv6_state > BBL_DHCP_DISABLED) {
        session->dhcpv6_state = BBL_DHCP_INIT;
    }
    session->dhcpv6_requested = false;
    session->dhcpv6_established = false;
    session->dhcpv6_ia_na_option_len = 0;
    session->dhcpv6_ia_pd_option_len = 0;
    memset(session->ipv6_address, 0x0, IPV6_ADDR_LEN);
    memset(session->delegated_ipv6_address, 0x0, IPV6_ADDR_LEN);
    memset(session->ipv6_dns1, 0x0, IPV6_ADDR_LEN);
    memset(session->ipv6_dns2, 0x0, IPV6_ADDR_LEN);
    memset(session->dhcpv6_dns1, 0x0, IPV6_ADDR_LEN);
    memset(session->dhcpv6_dns2, 0x0, IPV6_ADDR_LEN);
    session->zapping_joined_group = NULL;
    session->zapping_leaved_group = NULL;
    session->zapping_count = 0;
    session->zapping_view_start_time.tv_sec = 0;
    session->zapping_view_start_time.tv_nsec = 0;

    if(session->reply_message) {
        free(session->reply_message);
        session->reply_message = NULL;
    }
    if(session->connections_status_message) {
        free(session->connections_status_message);
        session->connections_status_message = NULL;
    }

    /* L2TP */
    session->l2tp = false;
    if(session->l2tp_session &&
       session->l2tp_session->pppoe_session == session) {
        session->l2tp_session->pppoe_session = NULL;
    }
    session->l2tp_session = NULL;

    /* Session traffic */
    if(g_ctx->stats.session_traffic_flows_verified >= session->session_traffic.flows_verified) {
        g_ctx->stats.session_traffic_flows_verified -= session->session_traffic.flows_verified;
    }
    session->session_traffic.flows_verified = 0;

    ENABLE_ENDPOINT(session->endpoint.ipv4);
    ENABLE_ENDPOINT(session->endpoint.ipv6);
    ENABLE_ENDPOINT(session->endpoint.ipv6pd);

    bbl_stream_reset(session->session_traffic.ipv4_up);
    bbl_stream_reset(session->session_traffic.ipv4_down);
    bbl_stream_reset(session->session_traffic.ipv6_up);
    bbl_stream_reset(session->session_traffic.ipv6_down);
    bbl_stream_reset(session->session_traffic.ipv6pd_up);
    bbl_stream_reset(session->session_traffic.ipv6pd_down);

    /* Reset session stats */
    session->stats.igmp_rx = 0;
    session->stats.igmp_tx = 0;
    session->stats.min_join_delay = 0;
    session->stats.avg_join_delay = 0;
    session->stats.max_join_delay = 0;
    session->stats.min_leave_delay = 0;
    session->stats.avg_leave_delay = 0;
    session->stats.max_leave_delay = 0;
    session->stats.mc_old_rx_after_first_new = 0;
    session->stats.mc_rx = 0;
    session->stats.mc_loss = 0;
    session->stats.mc_not_received = 0;
    session->stats.icmp_rx = 0;
    session->stats.icmp_tx = 0;
    session->stats.icmpv6_rx = 0;
    session->stats.icmpv6_tx = 0;
}

static bool
bbl_session_start(bbl_session_s *session)
{
    if(g_teardown || session->session_state != BBL_TERMINATED) {
        return false;
    }

    /* Reset session */    
    session->session_state = BBL_IDLE;
    bbl_session_reset(session);
    if(g_ctx->sessions_terminated) {
        g_ctx->sessions_terminated--;
    }
    /* Put on idle list */
    CIRCLEQ_INSERT_TAIL(&g_ctx->sessions_idle_qhead, session, session_idle_qnode);
    return true;
}

void
bbl_session_reconnect_job(timer_s *timer) {
    bbl_session_s *session = timer->data;
    bbl_session_start(session);
}

/**
 * bbl_session_update_state
 *
 * This function allows to change the state of a session including
 * the required action caused by state changes.
 *
 * @param ctx global context
 * @param session session
 * @param state new session state
 */
void
bbl_session_update_state(bbl_session_s *session, session_state_t new_state)
{
    session_state_t old_state = session->session_state;

    if(old_state != new_state) {
        /* State has changed ... */
        session->session_state = new_state;
        session->version++;
        assert(session->session_state > BBL_IDLE && session->session_state < BBL_MAX);

        if(old_state == BBL_ESTABLISHED) {
            /* Decrement sessions established if old state is established. */
            if(g_ctx->sessions_established) {
                g_ctx->sessions_established--;
                g_ctx->timestamp_established.tv_sec = 0;
            }
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                ENABLE_ENDPOINT(session->endpoint.ipv4);
                ENABLE_ENDPOINT(session->endpoint.ipv6);
                ENABLE_ENDPOINT(session->endpoint.ipv6pd);
            }
            bbl_tun_session_down(session);
        }
        
        /* Update outstanding session count. */
        if(old_state > BBL_IDLE && old_state < BBL_ESTABLISHED && new_state >= BBL_ESTABLISHED) {
            assert(g_ctx->sessions_outstanding);
            if(g_ctx->sessions_outstanding) g_ctx->sessions_outstanding--;
        }
        
        if(new_state == BBL_ESTABLISHED) {
            /* Increment sessions established if new state is established. */
            g_ctx->sessions_established++;
            assert(g_ctx->sessions_established <= g_ctx->sessions);
            if(g_ctx->sessions_established > g_ctx->sessions_established_max) g_ctx->sessions_established_max = g_ctx->sessions_established;
            if(g_ctx->sessions_established == g_ctx->sessions) {
                LOG_NOARG(INFO, "ALL SESSIONS ESTABLISHED\n");
                clock_gettime(CLOCK_MONOTONIC, &g_ctx->timestamp_established);
            }
            bbl_tun_session_up(session);
        } else if(new_state == BBL_PPP_TERMINATING) {
            if(session->ipcp_state > BBL_PPP_DISABLED) {
                session->ipcp_state = BBL_PPP_CLOSED;
            }
            if(session->ip6cp_state > BBL_PPP_DISABLED) {
                session->ip6cp_state = BBL_PPP_CLOSED;
            }
            ENABLE_ENDPOINT(session->endpoint.ipv4);
            ENABLE_ENDPOINT(session->endpoint.ipv6);
            ENABLE_ENDPOINT(session->endpoint.ipv6pd);
        } else if(new_state == BBL_TERMINATED) {
            /* Increment sessions terminated if new state is terminated */
            g_ctx->sessions_terminated++;
            assert(g_ctx->sessions_terminated <= g_ctx->sessions);
            if(session->dhcp_established) {
                session->dhcp_established = false;
                g_ctx->dhcp_established--;
            }
            if(session->dhcp_requested) {
                session->dhcp_requested = false;
                g_ctx->dhcp_requested--;
            }
            if(session->dhcpv6_established) {
                session->dhcpv6_established = false;
                g_ctx->dhcpv6_established--;
            }
            if(session->dhcpv6_requested) {
                session->dhcpv6_requested = false;
                g_ctx->dhcpv6_requested--;
            }
            /* Stop all session timers */
            timer_del(session->timer_arp);
            timer_del(session->timer_padi);
            timer_del(session->timer_padr);
            timer_del(session->timer_lcp);
            timer_del(session->timer_lcp_echo);
            timer_del(session->timer_auth);
            timer_del(session->timer_ipcp);
            timer_del(session->timer_ip6cp);
            timer_del(session->timer_dhcp_retry);
            timer_del(session->timer_dhcp_t1);
            timer_del(session->timer_dhcp_t2);
            timer_del(session->timer_dhcpv6);
            timer_del(session->timer_dhcpv6_t1);
            timer_del(session->timer_dhcpv6_t2);
            timer_del(session->timer_igmp);
            timer_del(session->timer_zapping);
            timer_del(session->timer_icmpv6);
            timer_del(session->timer_session);
            timer_del(session->timer_reconnect);

            /* Reset all states */
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                session->lcp_state = BBL_PPP_CLOSED;
                if(session->ipcp_state > BBL_PPP_DISABLED) {
                    session->ipcp_state = BBL_PPP_CLOSED;
                }
                if(session->ip6cp_state > BBL_PPP_DISABLED) {
                    session->ip6cp_state = BBL_PPP_CLOSED;
                }
            }
            ENABLE_ENDPOINT(session->endpoint.ipv4);
            ENABLE_ENDPOINT(session->endpoint.ipv6);
            ENABLE_ENDPOINT(session->endpoint.ipv6pd);
            
            /* Cleanup A10NSP session */
            bbl_a10nsp_session_free(session);

            if(g_teardown) {
                if(g_ctx->sessions_terminated == g_ctx->sessions) {
                    LOG_NOARG(INFO, "ALL SESSIONS TERMINATED\n");
                }
            } else {
                /* Increment flap counter */
                session->stats.flapped++;
                g_ctx->sessions_flapped++;

                /* Reconnect */
                if(!session->reconnect_disabled && 
                   ((session->access_type == ACCESS_TYPE_PPPOE && g_ctx->config.pppoe_reconnect) || 
                    (session->access_type == ACCESS_TYPE_IPOE && g_ctx->config.sessions_reconnect))) {
                    if(!session->reconnect_delay) {
                        session->reconnect_delay = 1;
                    }
                    timer_add(&g_ctx->timer_root, &session->timer_reconnect, "RECONNECT", 
                              session->reconnect_delay, 0, session, &bbl_session_reconnect_job);
                }
            }
        }
    }
}

/**
 * bbl_session_clear
 *
 * This function terminates a session gracefully.
 *
 * @param session session
 */
void
bbl_session_clear(bbl_session_s *session)
{
    session_state_t new_state = BBL_TERMINATED;

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        switch(session->session_state) {
            case BBL_IDLE:
            case BBL_PPPOE_INIT:
                bbl_session_update_state(session, BBL_TERMINATED);
                break;
            case BBL_PPPOE_REQUEST:
            case BBL_PPP_LINK:
                bbl_session_update_state(session, BBL_TERMINATING);
                session->lcp_state = BBL_PPP_CLOSED;
                if(session->ipcp_state > BBL_PPP_DISABLED) {
                    session->ipcp_state = BBL_PPP_CLOSED;
                }
                if(session->ip6cp_state > BBL_PPP_DISABLED) {
                    session->ip6cp_state = BBL_PPP_CLOSED;
                }
                session->send_requests = BBL_SEND_DISCOVERY;
                bbl_session_tx_qnode_insert(session);
                break;
            case BBL_PPP_AUTH:
            case BBL_PPP_NETWORK:
            case BBL_ESTABLISHED:
            case BBL_PPP_TERMINATING:
                bbl_session_update_state(session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->lcp_state = BBL_PPP_TERMINATE;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
            case BBL_TERMINATING:
            case BBL_TERMINATED:
                break;
            default:
                bbl_session_update_state(session, BBL_TERMINATED);
                break;
        }
    } else {
        switch(session->dhcp_state) {
            case BBL_DHCP_SELECTING:
                session->dhcp_state = BBL_DHCP_INIT;
                break;
            case BBL_DHCP_REQUESTING:
            case BBL_DHCP_BOUND:
            case BBL_DHCP_RENEWING:
                new_state = BBL_TERMINATING;
                session->dhcp_state = BBL_DHCP_RELEASE;
                session->dhcp_xid = rand();
                session->dhcp_request_timestamp.tv_sec = 0;
                session->dhcp_request_timestamp.tv_nsec = 0;
                session->dhcp_retry = 0;
                session->send_requests |= BBL_SEND_DHCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
            case BBL_DHCP_RELEASE:
                new_state = BBL_TERMINATING;
                break;
            default:
                break;
        }
        switch(session->dhcpv6_state) {
            case BBL_DHCP_SELECTING:
                session->dhcpv6_state = BBL_DHCP_INIT;
                break;
            case BBL_DHCP_REQUESTING:
            case BBL_DHCP_BOUND:
            case BBL_DHCP_RENEWING:
                new_state = BBL_TERMINATING;
                session->dhcpv6_state = BBL_DHCP_RELEASE;
                session->dhcpv6_xid = rand() & 0xffffff;
                session->dhcpv6_request_timestamp.tv_sec = 0;
                session->dhcpv6_request_timestamp.tv_nsec = 0;
                session->dhcpv6_retry = 0;
                session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
            case BBL_DHCP_RELEASE:
                new_state = BBL_TERMINATING;
                break;
            default:
                break;
        }
        bbl_session_update_state(session, new_state);
    }
}

static void
update_strings(char **target, const char *source, uint32_t *i, bbl_access_config_s *access_config)
{
    static char snum1[32];
    static char snum2[32];
    static char si1[32];
    static char si2[32];
    static char vlan1[32];
    static char vlan2[32];

    char *s;

    if(i && access_config) {
        /* Init iterator */
        snprintf(snum1, sizeof(snum1), "%d", *i);
        snprintf(snum2, sizeof(snum2), "%d", access_config->sessions);
        snprintf(si1, sizeof(si1), "%d", access_config->i1);
        access_config->i1 += access_config->i1_step;
        snprintf(si2, sizeof(si2), "%d", access_config->i2);
        access_config->i2 += access_config->i2_step;
        snprintf(vlan1, sizeof(si2), "%d", access_config->access_outer_vlan);
        snprintf(vlan2, sizeof(si2), "%d", access_config->access_inner_vlan);
    }
    if(target && source) {
        s = replace_substring(source, "{session-global}", snum1);
        s = replace_substring(s, "{session}", snum2);
        s = replace_substring(s, "{i1}", si1);
        s = replace_substring(s, "{i2}", si2);
        s = replace_substring(s, "{outer-vlan}", vlan1);
        s = replace_substring(s, "{inner-vlan}", vlan2);
        if(s) *target = strdup(s);
    }
}

bool
bbl_sessions_init()
{
    bbl_session_s *session;
    bbl_access_config_s *access_config;
    bbl_access_line_profile_s *access_line_profile;
    dict_insert_result result;
    void **search;

    uint32_t i = 1;  /* BNG Blaster internal session identifier */

    /* The variable t counts how many sessions are created in one
     * loop over all access configurations and is reset to zero
     * every time we start from first access profile. If the variable
     * is still zero after processing last access profile means
     * that all VLAN ranges are exhausted. */
    int t = 0;

    /* Init list of sessions */
    g_ctx->session_list = calloc(g_ctx->config.sessions, sizeof(bbl_session_s));
    access_config = g_ctx->config.access_config;

    /* For equal distribution of sessions over access configurations
     * and outer VLAN's, we loop first over all configurations and
     * second over VLAN ranges as per configuration. */
    while(i <= g_ctx->config.sessions) {
        if(access_config->exhausted) goto NEXT;
        if(access_config->sessions_max && access_config->sessions >= access_config->sessions_max) {
            access_config->exhausted = true;
            goto NEXT;
        }
        if(access_config->vlan_mode == VLAN_MODE_N1) {
            if(access_config->access_outer_vlan_min) {
                access_config->access_outer_vlan = access_config->access_outer_vlan_min;
            } else {
                access_config->access_outer_vlan = access_config->access_outer_vlan_max;
            }
            if(access_config->access_inner_vlan_min) {
                access_config->access_inner_vlan = access_config->access_inner_vlan_min;
            } else {
                access_config->access_inner_vlan = access_config->access_inner_vlan_max;
            }
        } else {
            if(access_config->access_outer_vlan == 0) {
                /* The outer VLAN is initial 0 */
                access_config->access_outer_vlan = access_config->access_outer_vlan_min;
                access_config->access_inner_vlan = access_config->access_inner_vlan_min;
            } else {
                if(g_ctx->config.iterate_outer_vlan && access_config->access_outer_vlan_step) {
                    /* Iterate over outer VLAN first and inner VLAN second */
                    access_config->access_outer_vlan += access_config->access_outer_vlan_step;
                    if(access_config->access_outer_vlan > access_config->access_outer_vlan_max) {
                        access_config->access_outer_vlan = access_config->access_outer_vlan_min;
                        access_config->access_inner_vlan += access_config->access_inner_vlan_step;
                    }
                } else {
                    /* Iterate over inner VLAN first and outer VLAN second (default) */
                    if(access_config->access_inner_vlan_step) {
                        access_config->access_inner_vlan += access_config->access_inner_vlan_step;
                        if(access_config->access_inner_vlan > access_config->access_inner_vlan_max) {
                            access_config->access_inner_vlan = access_config->access_inner_vlan_min;
                            access_config->access_outer_vlan += access_config->access_outer_vlan_step;
                        }
                    } else {
                        access_config->access_outer_vlan += access_config->access_outer_vlan_step;
                    }
                }
            }
            if(access_config->access_outer_vlan == 0) {
                /* This is required to handle untagged interfaces */
                access_config->exhausted = true;
            }
            if(access_config->access_outer_vlan > access_config->access_outer_vlan_max ||
               access_config->access_inner_vlan > access_config->access_inner_vlan_max) {
                /* VLAN range exhausted */
                access_config->exhausted = true;
                goto NEXT;
            }
        }
        t++;
        access_config->sessions++;
        session = &g_ctx->session_list[i-1];
        memset(&session->server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
        memset(&session->dhcp_server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
        session->session_id = i; /* BNG Blaster internal session identifier */
        session->session_group_id = access_config->session_group_id;
        session->access_type = access_config->access_type;
        session->access_interface = access_config->access_interface;
        session->network_interface = bbl_network_interface_get(access_config->network_interface);
        session->vlan_key.ifindex = access_config->access_interface->ifindex;
        session->vlan_key.outer_vlan_id= access_config->access_outer_vlan;
        session->vlan_key.inner_vlan_id = access_config->access_inner_vlan;
        session->access_third_vlan = access_config->access_third_vlan;
        session->access_config = access_config;

        /* Set client OUI to locally administered */
        session->client_mac[0] = 0x02;
        session->client_mac[1] = 0x00;
        session->client_mac[2] = g_ctx->config.mac_modifier;
        /* Use session identifier for remaining bytes */
        session->client_mac[3] = i>>16;
        session->client_mac[4] = i>>8;
        session->client_mac[5] = i;

        /* Derive IP6CP interface identifier from MAC (EUI-64) */
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[0] = session->client_mac[0];
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[1] = session->client_mac[1];
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[2] = session->client_mac[2];
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[3] = 0xFF;
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[4] = 0xFE;
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[5] = session->client_mac[3];
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[6] = session->client_mac[4];
        ((uint8_t *)&session->ip6cp_ipv6_identifier)[7] = session->client_mac[5];

        /* Init link-local IPv6 address */
        session->link_local_ipv6_address[0] = 0xfe;
        session->link_local_ipv6_address[1] = 0x80;
        session->link_local_ipv6_address[8] = 0xff;
        session->link_local_ipv6_address[9] = 0xff;
        session->link_local_ipv6_address[10] = 0xff;
        session->link_local_ipv6_address[11] = 0xff;
        session->link_local_ipv6_address[12] = 0xff;
        session->link_local_ipv6_address[13] = session->client_mac[3];
        session->link_local_ipv6_address[14] = session->client_mac[4];
        session->link_local_ipv6_address[15] = session->client_mac[5];

        /* Set DHCPv6 DUID */
        session->dhcpv6_duid[1] = 3;
        session->dhcpv6_duid[3] = 1;
        memcpy(&session->dhcpv6_duid[4], session->client_mac, ETH_ADDR_LEN);

        /* Init string variables/iterators */
        update_strings(NULL, NULL, &i, access_config);

        /* Update username */
        update_strings(&session->username, access_config->username, NULL, NULL);

        /* Update password */
        update_strings(&session->password, access_config->password, NULL, NULL);

        /* Update ACI */
        update_strings(&session->agent_circuit_id, access_config->agent_circuit_id, NULL, NULL);

        /* Update ARI */
        update_strings(&session->agent_remote_id, access_config->agent_remote_id, NULL, NULL);

        /* Update Access-Aggregation-Circuit-ID */
        update_strings(&session->access_aggregation_circuit_id, access_config->access_aggregation_circuit_id, NULL, NULL);

        /* Update Vendor Class ID */
        update_strings(&session->dhcp_vendor_class_id, access_config->dhcp_vendor_class_id, NULL, NULL);

        /* Update CFM */
        if(access_config->cfm_cc) {
            session->cfm = calloc(1, sizeof(bbl_cfm_session_s));
            session->cfm->cfm_cc = true;
            if(access_config->cfm_seq) session->cfm->cfm_seq = 1;
            session->cfm->cfm_level = access_config->cfm_level;
            session->cfm->cfm_ma_id = access_config->cfm_ma_id;
            update_strings(&session->cfm->cfm_ma_name, access_config->cfm_ma_name, NULL, NULL);
            session->cfm->session = session;
        }

        /* Update access rates ... */
        session->rate_up = access_config->rate_up;
        session->rate_down = access_config->rate_down;
        session->dsl_type = access_config->dsl_type;
        if(access_config->access_line_profile_id) {
            access_line_profile = g_ctx->config.access_line_profile;
            while(access_line_profile) {
                if(access_line_profile->access_line_profile_id == access_config->access_line_profile_id) {
                    session->access_line_profile = access_line_profile;
                    if(session->rate_up == 0) {
                        session->rate_up = access_line_profile->act_up;
                    }
                    if(session->rate_down == 0) {
                        session->rate_down = access_line_profile->act_down;
                    }
                    if(session->dsl_type == 0) {
                        session->dsl_type = access_line_profile->dsl_type;
                    }
                    break;
                }
                access_line_profile = access_line_profile->next;
            }
        }

        /* IGMP */
        session->igmp_autostart = access_config->igmp_autostart;
        session->igmp_version = access_config->igmp_version;
        session->igmp_robustness = 2; /* init robustness with 2 */
        session->zapping_group_max = be32toh(g_ctx->config.igmp_group) + ((g_ctx->config.igmp_group_count - 1) * be32toh(g_ctx->config.igmp_group_iter));

        /* Set access type specific values */
        if(session->access_type == ACCESS_TYPE_PPPOE) {
            session->mru = access_config->ppp_mru;
            session->magic_number = htobe32(i);
            session->lcp_state = BBL_PPP_CLOSED;
            if(access_config->ipv4_enable && access_config->ipcp_enable) {
                session->ipcp_state = BBL_PPP_CLOSED;
                session->ipcp_request_dns1 = g_ctx->config.ipcp_request_dns1;
                session->ipcp_request_dns2 = g_ctx->config.ipcp_request_dns2;
                session->endpoint.ipv4 = ENDPOINT_ENABLED;
            }
            if(access_config->ipv6_enable && access_config->ip6cp_enable) {
                session->ip6cp_state = BBL_PPP_CLOSED;
                session->endpoint.ipv6 = ENDPOINT_ENABLED;
                if(access_config->dhcpv6_enable) {
                    session->dhcpv6_state = BBL_DHCP_INIT;
                    session->endpoint.ipv6pd = ENDPOINT_ENABLED;
                }
            }
            if(g_ctx->config.pppoe_service_name) {
                session->pppoe_service_name = (uint8_t*)g_ctx->config.pppoe_service_name;
                session->pppoe_service_name_len = strlen(g_ctx->config.pppoe_service_name);
            }
            if(g_ctx->config.pppoe_host_uniq) {
                session->pppoe_host_uniq = htobe64(i);
            }
        } else if(session->access_type == ACCESS_TYPE_IPOE) {
            if(access_config->ipv4_enable) {
                session->endpoint.ipv4 = ENDPOINT_ENABLED;
                if(access_config->static_ip && access_config->static_gateway) {
                    session->ip_address = access_config->static_ip;
                    session->peer_ip_address = access_config->static_gateway;
                    access_config->static_ip = htobe32(be32toh(access_config->static_ip) + be32toh(access_config->static_ip_iter));
                    access_config->static_gateway = htobe32(be32toh(access_config->static_gateway) + be32toh(access_config->static_gateway_iter));
                } else if(access_config->dhcp_enable) {
                    session->dhcp_state = BBL_DHCP_INIT;
                } else {
                    session->endpoint.ipv4 = ENDPOINT_DISABLED;
                }
            }
            if(access_config->ipv6_enable) {
                session->endpoint.ipv6 = ENDPOINT_ENABLED;
                if(ipv6_addr_not_zero(&access_config->static_ip6_ll)) {
                    memcpy(&session->link_local_ipv6_address, &access_config->static_ip6_ll, sizeof(ipv6addr_t));
                }
                if(access_config->dhcpv6_enable) {
                    session->dhcpv6_state = BBL_DHCP_INIT;
                    session->endpoint.ipv6pd = ENDPOINT_ENABLED;
                }
            }
        }
        session->access_interface = access_config->access_interface;
        session->network_interface = bbl_network_interface_get(access_config->network_interface);
        
        if(g_ctx->config.sessions_autostart) {
            session->session_state = BBL_IDLE;
            CIRCLEQ_INSERT_TAIL(&g_ctx->sessions_idle_qhead, session, session_idle_qnode);
        } else {
            session->session_state = BBL_TERMINATED;
            g_ctx->sessions_terminated++;
        }

        g_ctx->sessions++;
        if(session->access_type == ACCESS_TYPE_PPPOE) {
            g_ctx->sessions_pppoe++;
        } else {
            g_ctx->sessions_ipoe++;
        }

        if(access_config->vlan_mode == VLAN_MODE_11) {
            result = dict_insert(g_ctx->vlan_session_dict, &session->vlan_key);
            if(result.inserted) {
                *result.datum_ptr = session;
            } else {
                LOG(ERROR, "Failed to create session %u due to VLAN conflict!\n", i);
                return false;
            }
        } else {
            search = dict_search(g_ctx->vlan_session_dict, &session->vlan_key);
            if(search) {
                if(*search) {
                    LOG(ERROR, "Failed to create session %u due to VLAN conflict!\n", i);
                    return false;
                }
            } else {
                result = dict_insert(g_ctx->vlan_session_dict, &session->vlan_key);
                if(result.inserted) {
                    *result.datum_ptr = NULL;
                }
            }
        }

        /* Streams */
        session->streams.group_id = access_config->stream_group_id;
        if(!bbl_stream_session_init(session)) {
            LOG_NOARG(ERROR, "Failed to create session traffic stream!\n");
            return false;
        }
        bbl_session_traffic_enable(access_config->session_traffic_autostart, session, BBL_DIRECTION_BOTH);

        if(!bbl_tcp_session_init(session)) {
            LOG_NOARG(ERROR, "Failed to create session TCP interface!\n");
            return false;
        }

        if(!bbl_icmp_client_session_init(session)) {
            LOG_NOARG(ERROR, "Failed to create session ICMP client!\n");
            return false;
        }

        if(!bbl_arp_client_session_init(session)) {
            LOG_NOARG(ERROR, "Failed to create session ARP client!\n");
            return false;
        }

        if(!bbl_http_client_session_init(session)) {
            LOG_NOARG(ERROR, "Failed to create session HTTP client!\n");
            return false;
        }

        if(!bbl_tun_session_init(session)) {
            LOG_NOARG(ERROR, "Failed to create session TUN interface!\n");
            return false;
        }

        timer_add_periodic(&g_ctx->timer_root, &session->timer_rate, "Rate Computation", 1, 0, session, &bbl_session_rate_job);

        if(access_config->monkey) {
            timer_add_periodic(&g_ctx->timer_root, &session->timer_monkey, "MONKEY", 1, 1337, session, &bbl_session_monkey_job);
        }

        LOG(DEBUG, "Session %u created (%s.%u:%u group %u)\n", i, 
            access_config->access_interface->name, 
            access_config->access_outer_vlan, 
            access_config->access_inner_vlan,
            access_config->session_group_id);

        i++;
NEXT:
        if(access_config->next) {
            access_config = access_config->next;
        } else {
            if(t) {
                t = 0;
                access_config = g_ctx->config.access_config;
            } else {
                LOG_NOARG(ERROR, "Failed to create sessions because VLAN ranges exhausted!\n");
                return false;
            }

        }
    }
    return true;
}

const char *
bbl_session_substate_pppoe(bbl_session_s *session)
{
    UNUSED(session);
    return NULL;
}

const char *
bbl_session_substate_ipoe(bbl_session_s *session)
{
    if(session->access_config->ipv4_enable) {
        if(session->dhcp_state > BBL_DHCP_DISABLED && session->dhcp_state < BBL_DHCP_BOUND) {
            return "DHCPv4 pending";
        }
        if(!session->arp_resolved) {
            return "ARP not resolved";
        }
    }
    if(session->access_config->ipv6_enable) {
        if (session->dhcpv6_state > BBL_DHCP_DISABLED && session->dhcpv6_state < BBL_DHCP_BOUND) {
            return "DHCPv6 pending";
        }
        if(!session->icmpv6_ra_received) {
            return "Wait for ICMPv6 RA";
        }
    }
    return NULL;
}

json_t *
bbl_session_json(bbl_session_s *session)
{
    json_t *root = NULL;
    json_t *session_traffic = NULL;
    json_t *a10nsp_session = NULL;
    json_t *l2tp_session = NULL;

    bbl_stream_s *stream;

    struct timespec now;

    const char *ipv4 = NULL;
    const char *ipv4_netmask = NULL;
    const char *ipv4_gw = NULL;
    const char *dns1 = NULL;
    const char *dns2 = NULL;
    const char *ipv6 = NULL;
    const char *ipv6pd = NULL;
    const char *ipv6_dns1 = NULL;
    const char *ipv6_dns2 = NULL;
    const char *dhcpv6_dns1 = NULL;
    const char *dhcpv6_dns2 = NULL;

    uint32_t seconds = 0;
    uint32_t dhcp_lease_expire = 0;
    uint32_t dhcp_lease_expire_t1 = 0;
    uint32_t dhcp_lease_expire_t2 = 0;
    uint32_t dhcpv6_lease_expire = 0;
    uint32_t dhcpv6_lease_expire_t1 = 0;
    uint32_t dhcpv6_lease_expire_t2 = 0;

    if(!session) {
        return NULL;
    }

    if(session->ip_address) {
        ipv4 = format_ipv4_address(&session->ip_address);
    }
    if(session->ip_netmask) {
        ipv4_netmask = format_ipv4_address(&session->ip_netmask);
    }
    if(session->peer_ip_address) {
        ipv4_gw = format_ipv4_address(&session->peer_ip_address);
    }
    if(session->dns1) {
        dns1 = format_ipv4_address(&session->dns1);
    }
    if(session->dns2) {
        dns2 = format_ipv4_address(&session->dns2);
    }
    if(session->ipv6_prefix.len) {
        ipv6 = format_ipv6_prefix(&session->ipv6_prefix);
    }
    if(session->delegated_ipv6_prefix.len) {
        ipv6pd = format_ipv6_prefix(&session->delegated_ipv6_prefix);
    }
    if(*(uint64_t*)session->ipv6_dns1) {
        ipv6_dns1 = format_ipv6_address(&session->ipv6_dns1);
    }
    if(*(uint64_t*)session->ipv6_dns2) {
        ipv6_dns2 = format_ipv6_address(&session->ipv6_dns2);
    }
    if(*(uint64_t*)session->dhcpv6_dns1) {
        dhcpv6_dns1 = format_ipv6_address(&session->dhcpv6_dns1);
    }
    if(*(uint64_t*)session->dhcpv6_dns2) {
        dhcpv6_dns2 = format_ipv6_address(&session->dhcpv6_dns2);
    }

    if(session->session_traffic.flows) {
        session_traffic = json_pack("{si si}",
            "total-flows", session->session_traffic.flows,
            "verified-flows", session->session_traffic.flows_verified);
        if(session->session_traffic.ipv4_down) {
            stream = session->session_traffic.ipv4_down;
            json_object_set_new(session_traffic, "downstream-ipv4-flow-id", json_integer(stream->flow_id));
            json_object_set_new(session_traffic, "downstream-ipv4-tx-packets", json_integer(stream->tx_packets - stream->reset_packets_tx));
            json_object_set_new(session_traffic, "downstream-ipv4-rx-packets", json_integer(stream->rx_packets - stream->reset_packets_rx));
            json_object_set_new(session_traffic, "downstream-ipv4-rx-first-seq", json_integer(stream->rx_first_seq));
            json_object_set_new(session_traffic, "downstream-ipv4-loss", json_integer(stream->rx_loss - stream->reset_loss));
            json_object_set_new(session_traffic, "downstream-ipv4-wrong-session", json_integer(stream->rx_wrong_session));
        }
        if(session->session_traffic.ipv4_up) {
            stream = session->session_traffic.ipv4_up;
            json_object_set_new(session_traffic, "upstream-ipv4-flow-id", json_integer(stream->flow_id));
            json_object_set_new(session_traffic, "upstream-ipv4-tx-packets", json_integer(stream->tx_packets - stream->reset_packets_tx));
            json_object_set_new(session_traffic, "upstream-ipv4-rx-packets", json_integer(stream->rx_packets - stream->reset_packets_rx));
            json_object_set_new(session_traffic, "upstream-ipv4-rx-first-seq", json_integer(stream->rx_first_seq));
            json_object_set_new(session_traffic, "upstream-ipv4-loss", json_integer(stream->rx_loss - stream->reset_loss));
            json_object_set_new(session_traffic, "upstream-ipv4-wrong-session", json_integer(stream->rx_wrong_session));
        }
        if(session->session_traffic.ipv6_down) {
            stream = session->session_traffic.ipv6_down;
            json_object_set_new(session_traffic, "downstream-ipv6-flow-id", json_integer(stream->flow_id));
            json_object_set_new(session_traffic, "downstream-ipv6-tx-packets", json_integer(stream->tx_packets - stream->reset_packets_tx));
            json_object_set_new(session_traffic, "downstream-ipv6-rx-packets", json_integer(stream->rx_packets - stream->reset_packets_rx));
            json_object_set_new(session_traffic, "downstream-ipv6-rx-first-seq", json_integer(stream->rx_first_seq));
            json_object_set_new(session_traffic, "downstream-ipv6-loss", json_integer(stream->rx_loss - stream->reset_loss));
            json_object_set_new(session_traffic, "downstream-ipv6-wrong-session", json_integer(stream->rx_wrong_session));
        }
        if(session->session_traffic.ipv6_up) {
            stream = session->session_traffic.ipv6_up;
            json_object_set_new(session_traffic, "upstream-ipv6-flow-id", json_integer(stream->flow_id));
            json_object_set_new(session_traffic, "upstream-ipv6-tx-packets", json_integer(stream->tx_packets - stream->reset_packets_tx));
            json_object_set_new(session_traffic, "upstream-ipv6-rx-packets", json_integer(stream->rx_packets - stream->reset_packets_rx));
            json_object_set_new(session_traffic, "upstream-ipv6-rx-first-seq", json_integer(stream->rx_first_seq));
            json_object_set_new(session_traffic, "upstream-ipv6-loss", json_integer(stream->rx_loss - stream->reset_loss));
            json_object_set_new(session_traffic, "upstream-ipv6-wrong-session", json_integer(stream->rx_wrong_session));
        }
        if(session->session_traffic.ipv6pd_down) {
            stream = session->session_traffic.ipv6pd_down;
            json_object_set_new(session_traffic, "downstream-ipv6pd-flow-id", json_integer(stream->flow_id));
            json_object_set_new(session_traffic, "downstream-ipv6pd-tx-packets", json_integer(stream->tx_packets - stream->reset_packets_tx));
            json_object_set_new(session_traffic, "downstream-ipv6pd-rx-packets", json_integer(stream->rx_packets - stream->reset_packets_rx));
            json_object_set_new(session_traffic, "downstream-ipv6pd-rx-first-seq", json_integer(stream->rx_first_seq));
            json_object_set_new(session_traffic, "downstream-ipv6pd-loss", json_integer(stream->rx_loss - stream->reset_loss));
            json_object_set_new(session_traffic, "downstream-ipv6pd-wrong-session", json_integer(stream->rx_wrong_session));
        }
        if(session->session_traffic.ipv6pd_up) {
            stream = session->session_traffic.ipv6pd_up;
            json_object_set_new(session_traffic, "upstream-ipv6pd-flow-id", json_integer(stream->flow_id));
            json_object_set_new(session_traffic, "upstream-ipv6pd-tx-packets", json_integer(stream->tx_packets - stream->reset_packets_tx));
            json_object_set_new(session_traffic, "upstream-ipv6pd-rx-packets", json_integer(stream->rx_packets - stream->reset_packets_rx));
            json_object_set_new(session_traffic, "upstream-ipv6pd-rx-first-seq", json_integer(stream->rx_first_seq));
            json_object_set_new(session_traffic, "upstream-ipv6pd-loss", json_integer(stream->rx_loss - stream->reset_loss));
            json_object_set_new(session_traffic, "upstream-ipv6pd-wrong-session", json_integer(stream->rx_wrong_session));
        }
    }
    if(session->a10nsp_session) {
        a10nsp_session = json_pack("{ss si sb sb ss* ss* ss* ss* ss* ss* sI sI}",
            "interface", session->a10nsp_session->a10nsp_interface->name,
            "s-vlan", session->a10nsp_session->s_vlan,
            "qinq-send", session->a10nsp_session->a10nsp_interface->qinq,
            "qinq-received", session->a10nsp_session->qinq_received,
            "pppoe-aci", session->a10nsp_session->pppoe_aci,
            "pppoe-ari", session->a10nsp_session->pppoe_ari,
            "dhcp-aci", session->a10nsp_session->dhcp_aci,
            "dhcp-ari", session->a10nsp_session->dhcp_ari,
            "dhcpv6-aci", session->a10nsp_session->dhcpv6_aci,
            "dhcpv6-ari", session->a10nsp_session->dhcpv6_ari,
            "tx-packets", session->a10nsp_session->stats.packets_tx,
            "rx-packets", session->a10nsp_session->stats.packets_rx);
    }
    if(session->l2tp_session) {
        l2tp_session = l2tp_session_json(session->l2tp_session);
    }

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        root = json_pack("{ss si ss ss* si si ss si si ss ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* sI sI si sI sI sI sI sI sI si si si si si si so* so* so*}",
            "type", "pppoe",
            "session-id", session->session_id,
            "session-state", session_state_string(session->session_state),
            "session-substate", bbl_session_substate_pppoe(session),
            "session-version", session->version,
            "flapped", session->stats.flapped,
            "interface", session->access_interface->name,
            "outer-vlan", session->vlan_key.outer_vlan_id,
            "inner-vlan", session->vlan_key.inner_vlan_id,
            "mac", format_mac_address(session->client_mac),
            "username", session->username,
            "agent-circuit-id", session->agent_circuit_id,
            "agent-remote-id", session->agent_remote_id,
            "reply-message", session->reply_message,
            "connection-status-message", session->connections_status_message,
            "lcp-state", ppp_state_string(session->lcp_state),
            "ipcp-state", ppp_state_string(session->ipcp_state),
            "ip6cp-state", ppp_state_string(session->ip6cp_state),
            "ipv4-address", ipv4,
            "ipv4-dns1", dns1,
            "ipv4-dns2", dns2,
            "ipv6-prefix", ipv6,
            "ipv6-delegated-prefix", ipv6pd,
            "ipv6-dns1", ipv6_dns1,
            "ipv6-dns2", ipv6_dns2,
            "dhcpv6-state", dhcp_state_string(session->dhcpv6_state),
            "dhcpv6-dns1", dhcpv6_dns1,
            "dhcpv6-dns2", dhcpv6_dns2,
            "tx-packets", session->stats.packets_tx,
            "rx-packets", session->stats.packets_rx,
            "rx-fragmented-packets", session->stats.ipv4_fragmented_rx,
            "tx-bytes", session->stats.bytes_tx,
            "rx-bytes", session->stats.bytes_rx,
            "tx-accounting-packets", session->stats.accounting_packets_tx,
            "rx-accounting-packets", session->stats.accounting_packets_rx,
            "tx-accounting-bytes", session->stats.accounting_bytes_tx,
            "rx-accounting-bytes", session->stats.accounting_bytes_rx,
            "tx-igmp", session->stats.igmp_tx,
            "rx-igmp", session->stats.igmp_rx,
            "tx-icmp", session->stats.icmp_tx,
            "rx-icmp", session->stats.icmp_rx,
            "tx-icmpv6", session->stats.icmpv6_tx,
            "rx-icmpv6", session->stats.icmpv6_rx,
            "session-traffic", session_traffic,
            "a10nsp", a10nsp_session,
            "l2tp", l2tp_session);

    } else {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if(session->dhcp_lease_timestamp.tv_sec && now.tv_sec > session->dhcp_lease_timestamp.tv_sec) {
            seconds = now.tv_sec - session->dhcp_lease_timestamp.tv_sec;
        }
        if(seconds <= session->dhcp_lease_time) dhcp_lease_expire = session->dhcp_lease_time - seconds;
        if(seconds <= session->dhcp_t1) dhcp_lease_expire_t1 = session->dhcp_t1 - seconds;
        if(seconds <= session->dhcp_t2) dhcp_lease_expire_t2 = session->dhcp_t2 - seconds;

        if(session->dhcpv6_lease_timestamp.tv_sec && now.tv_sec > session->dhcpv6_lease_timestamp.tv_sec) {
            seconds = now.tv_sec - session->dhcpv6_lease_timestamp.tv_sec;
        }
        if(seconds <= session->dhcpv6_lease_time) dhcpv6_lease_expire = session->dhcpv6_lease_time - seconds;
        if(seconds <= session->dhcpv6_t1) dhcpv6_lease_expire_t1 = session->dhcpv6_t1 - seconds;
        if(seconds <= session->dhcpv6_t2) dhcpv6_lease_expire_t2 = session->dhcpv6_t2 - seconds;

        root = json_pack("{ss si ss ss* si si ss si si ss ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* si si si si si si si si si si si si ss* si si si si si si si si si si si si ss* ss* sI sI si sI sI sI sI sI sI si si si si si si si si so* so*}",
            "type", "ipoe",
            "session-id", session->session_id,
            "session-state", session_state_string(session->session_state),
            "session-substate", bbl_session_substate_ipoe(session),
            "session-version", session->version,
            "flapped", session->stats.flapped,
            "interface", session->access_interface->name,
            "outer-vlan", session->vlan_key.outer_vlan_id,
            "inner-vlan", session->vlan_key.inner_vlan_id,
            "mac", format_mac_address(session->client_mac),
            "agent-circuit-id", session->agent_circuit_id,
            "agent-remote-id", session->agent_remote_id,
            "ipv4-address", ipv4,
            "ipv4-netmask", ipv4_netmask,
            "ipv4-gateway", ipv4_gw,
            "ipv4-dns1", dns1,
            "ipv4-dns2", dns2,
            "ipv6-prefix", ipv6,
            "ipv6-delegated-prefix", ipv6pd,
            "ipv6-dns1", ipv6_dns1,
            "ipv6-dns2", ipv6_dns2,
            "dhcp-state", dhcp_state_string(session->dhcp_state),
            "dhcp-server", format_ipv4_address(&session->dhcp_server_identifier),
            "dhcp-vendor-class-id", session->dhcp_vendor_class_id,
            "dhcp-lease-time", session->dhcp_lease_time,
            "dhcp-lease-expire", dhcp_lease_expire,
            "dhcp-lease-expire-t1", dhcp_lease_expire_t1,
            "dhcp-lease-expire-t2", dhcp_lease_expire_t2,
            "dhcp-tx", session->stats.dhcp_tx,
            "dhcp-rx", session->stats.dhcp_rx,
            "dhcp-tx-discover", session->stats.dhcp_tx_discover,
            "dhcp-rx-offer", session->stats.dhcp_rx_offer,
            "dhcp-tx-request", session->stats.dhcp_tx_request,
            "dhcp-rx-ack", session->stats.dhcp_rx_ack,
            "dhcp-rx-nak", session->stats.dhcp_rx_nak,
            "dhcp-tx-release", session->stats.dhcp_tx_release,
            "dhcpv6-state", dhcp_state_string(session->dhcpv6_state),
            "dhcpv6-lease-time", session->dhcpv6_lease_time,
            "dhcpv6-lease-expire", dhcpv6_lease_expire,
            "dhcpv6-lease-expire-t1", dhcpv6_lease_expire_t1,
            "dhcpv6-lease-expire-t2", dhcpv6_lease_expire_t2,
            "dhcpv6-tx", session->stats.dhcpv6_tx,
            "dhcpv6-rx", session->stats.dhcpv6_rx,
            "dhcpv6-tx-solicit", session->stats.dhcpv6_tx_solicit,
            "dhcpv6-rx-advertise", session->stats.dhcpv6_rx_advertise,
            "dhcpv6-tx-request", session->stats.dhcpv6_tx_request,
            "dhcpv6-rx-reply", session->stats.dhcpv6_rx_reply,
            "dhcpv6-tx-renew", session->stats.dhcpv6_tx_renew,
            "dhcpv6-tx-release", session->stats.dhcpv6_tx_release,
            "dhcpv6-dns1", dhcpv6_dns1,
            "dhcpv6-dns2", dhcpv6_dns2,
            "tx-packets", session->stats.packets_tx,
            "rx-packets", session->stats.packets_rx,
            "rx-fragmented-packets", session->stats.ipv4_fragmented_rx,
            "tx-bytes", session->stats.bytes_tx,
            "rx-bytes", session->stats.bytes_rx,
            "tx-accounting-packets", session->stats.accounting_packets_tx,
            "rx-accounting-packets", session->stats.accounting_packets_rx,
            "tx-accounting-bytes", session->stats.accounting_bytes_tx,
            "rx-accounting-bytes", session->stats.accounting_bytes_rx,
            "tx-arp", session->stats.arp_tx,
            "rx-arp", session->stats.arp_rx,
            "tx-igmp", session->stats.igmp_tx,
            "rx-igmp", session->stats.igmp_rx,
            "tx-icmp", session->stats.icmp_tx,
            "rx-icmp", session->stats.icmp_rx,
            "tx-icmpv6", session->stats.icmpv6_tx,
            "rx-icmpv6", session->stats.icmpv6_rx,
            "session-traffic", session_traffic,
            "a10nsp", a10nsp_session);
    }
    if(!root) {
        if(a10nsp_session) json_decref(a10nsp_session);
        if(session_traffic) json_decref(session_traffic);
    }
    return root;
}

/* Control Socket Commands */

int
bbl_session_ctrl_pending(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *json_session, *json_sessions;

    bbl_session_s *session;
    uint32_t i;

    json_sessions = json_array();

    /* Iterate over all sessions */
    for(i = 0; i < g_ctx->sessions; i++) {
        session = &g_ctx->session_list[i];
        if(!session) continue;
        
        if(session->session_state != BBL_ESTABLISHED || 
           session->session_traffic.flows != session->session_traffic.flows_verified) {
            json_session = json_pack("{si ss si si}",
                                     "session-id", session->session_id,
                                     "session-state", session_state_string(session->session_state),
                                     "session-traffic-flows", session->session_traffic.flows,
                                     "session-traffic-flows-verified", session->session_traffic.flows_verified);
            json_array_append_new(json_sessions, json_session);
        }
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "sessions-pending", json_sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(json_sessions);
    }
    return result;
}

int
bbl_session_ctrl_counters(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root = json_pack("{ss si s{si si si si si si si si si si si si si si si sf sf sf sf si si si si}}",
                             "status", "ok",
                             "code", 200,
                             "session-counters",
                             "sessions", g_ctx->config.sessions,
                             "sessions-pppoe", g_ctx->sessions_pppoe,
                             "sessions-ipoe", g_ctx->sessions_ipoe,
                             "sessions-established", g_ctx->sessions_established,
                             "sessions-established-max", g_ctx->sessions_established_max,
                             "sessions-outstanding", g_ctx->sessions_outstanding,
                             "sessions-terminated", g_ctx->sessions_terminated,
                             "sessions-flapped", g_ctx->sessions_flapped,
                             "dhcp-sessions", g_ctx->dhcp_requested,
                             "dhcp-sessions-established", g_ctx->dhcp_established,
                             "dhcp-sessions-established-max", g_ctx->dhcp_established_max,
                             "dhcpv6-sessions", g_ctx->dhcpv6_requested,
                             "dhcpv6-sessions-established", g_ctx->dhcpv6_established,
                             "dhcpv6-sessions-established-max", g_ctx->dhcpv6_established_max,
                             "setup-time", g_ctx->stats.setup_time,
                             "setup-rate", g_ctx->stats.cps,
                             "setup-rate-min", g_ctx->stats.cps_min,
                             "setup-rate-avg", g_ctx->stats.cps_avg,
                             "setup-rate-max", g_ctx->stats.cps_max,
                             "session-traffic-flows", g_ctx->stats.session_traffic_flows,
                             "session-traffic-flows-verified", g_ctx->stats.session_traffic_flows_verified,
                             "stream-traffic-flows", g_ctx->stats.stream_traffic_flows,
                             "stream-traffic-flows-verified", g_ctx->stats.stream_traffic_flows_verified
                            );

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

int
bbl_session_ctrl_info(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root;
    json_t *session_json;
    bbl_session_s *session;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(session_id);
    if(session) {
        session_json = bbl_session_json(session);
        if(!session_json) {
            return bbl_ctrl_status(fd, "error", 500, "internal error");
        }

        root = json_pack("{ss si so*}",
                         "status", "ok",
                         "code", 200,
                         "session-info", session_json);

        if(root) {
            result = json_dumpfd(root, fd, 0);
            json_decref(root);
        } else {
            result = bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(session_json);
        }
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

static int
bbl_session_ctrl_stop_restart(int fd, uint32_t session_id, json_t *arguments, bool restart)
{
    bbl_session_s *session;
    uint32_t i;

    int session_group_id = -1;
    int reconnect_delay = 0;

    if(json_unpack(arguments, "{s:i}", "session-group-id", &session_group_id) == 0) {
        if(session_group_id < 0 || session_group_id > UINT16_MAX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid session-group-id");
        }
    }

    if(restart) {
        json_unpack(arguments, "{s:i}", "reconnect-delay", &reconnect_delay);
        if(reconnect_delay < 0) {
            return bbl_ctrl_status(fd, "error", 400, "invalid reconnect-delay");
        }
    }

    if(session_id) {
        /* Stop/start single matching session ... */
        session = bbl_session_get(session_id);
        if(session) {
            if(restart) {
                if(session->session_state == BBL_TERMINATED) {
                    bbl_session_start(session);
                } else {
                    session->reconnect_disabled = false;
                    session->reconnect_delay = reconnect_delay;
                    bbl_session_clear(session);
                }
            } else {
                session->reconnect_disabled = true;
                bbl_session_clear(session);
            }
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Stop/start all sessions ... */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                if(session_group_id >= 0 && session->session_group_id != session_group_id) {
                    /* Skip sessions with wrong session-group-id if present. */
                    continue;
                }
                if(restart) {
                    if(session->session_state == BBL_TERMINATED) {
                        bbl_session_start(session);
                    } else {
                        session->reconnect_disabled = false;
                        session->reconnect_delay = reconnect_delay;
                        bbl_session_clear(session);
                    }
                } else {
                    session->reconnect_disabled = true;
                    bbl_session_clear(session);
                }
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_session_ctrl_stop(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_stop_restart(fd, session_id, arguments, false);
}

int
bbl_session_ctrl_restart(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_stop_restart(fd, session_id, arguments, true);
}

int
bbl_session_ctrl_start(int fd, uint32_t session_id, json_t *arguments)
{
    bbl_session_s *session;
    uint32_t i;

    int session_group_id = -1;

    if(json_unpack(arguments, "{s:i}", "session-group-id", &session_group_id) == 0) {
        if(session_group_id < 0 || session_group_id > UINT16_MAX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid session-group-id");
        }
    }

    if(g_teardown) {
        return bbl_ctrl_status(fd, "error", 405, "teardown in progress");
    }

    if(session_id) {
        /* Start single session ... */
        session = bbl_session_get(session_id);
        if(session) {
            if(!bbl_session_start(session)) {
                return bbl_ctrl_status(fd, "error", 405, "wrong session state");
            }
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Start all sessions ... */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session_group_id >= 0 && session->session_group_id != session_group_id) {
                /* Skip sessions with wrong session-group-id if present. */
                continue;
            }
            bbl_session_start(session);
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

static int
bbl_session_ctrl_ncp_open_close(int fd, uint32_t session_id, json_t *arguments, bool open, bool ipcp)
{
    bbl_session_s *session;
    uint32_t i;

    int session_group_id = -1;

    if(json_unpack(arguments, "{s:i}", "session-group-id", &session_group_id) == 0) {
        if(session_group_id < 0 || session_group_id > UINT16_MAX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid session-group-id");
        }
    }

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                if(open) {
                    bbl_session_ncp_open(session, ipcp);
                } else {
                    bbl_session_ncp_close(session, ipcp);
                }
            } else {
                return bbl_ctrl_status(fd, "warning", 400, "matching session is not of type pppoe");
            }
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session_group_id >= 0 && session->session_group_id != session_group_id) {
                /* Skip sessions with wrong session-group-id if present. */
                continue;
            }
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                if(open) {
                    bbl_session_ncp_open(session, ipcp);
                } else {
                    bbl_session_ncp_close(session, ipcp);
                }
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_session_ctrl_ipcp_open(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_ncp_open_close(fd, session_id, arguments, true, true);
}

int
bbl_session_ctrl_ipcp_close(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_ncp_open_close(fd, session_id, arguments, false, true);
}

int
bbl_session_ctrl_ip6cp_open(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_ncp_open_close(fd, session_id, arguments, true, false);
}

int
bbl_session_ctrl_ip6cp_close(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_ncp_open_close(fd, session_id, arguments, false, false);
}

static int
bbl_session_ctrl_lcp_echo_request(int fd, uint32_t session_id, json_t *arguments, bool ignore)
{
    bbl_session_s *session;
    uint32_t i;

    int session_group_id = -1;

    if(json_unpack(arguments, "{s:i}", "session-group-id", &session_group_id) == 0) {
        if(session_group_id < 0 || session_group_id > UINT16_MAX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid session-group-id");
        }
    }

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                session->lcp_echo_request_ignore = ignore;
            } else {
                return bbl_ctrl_status(fd, "warning", 400, "matching session is not of type pppoe");
            }
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session_group_id >= 0 && session->session_group_id != session_group_id) {
                /* Skip sessions with wrong session-group-id if present. */
                continue;
            }
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                session->lcp_echo_request_ignore = ignore;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_session_ctrl_lcp_echo_request_ignore(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_lcp_echo_request(fd, session_id, arguments, true);
}

int
bbl_session_ctrl_lcp_echo_request_accept(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_lcp_echo_request(fd, session_id, arguments, false);
}

static int
bbl_session_ctrl_traffic(int fd, uint32_t session_id, json_t *arguments, bool enabled)
{
    bbl_session_s *session;
    const char *s = NULL;
    uint32_t i;
    uint8_t direction = BBL_DIRECTION_BOTH;

    int session_group_id = -1;
    if(json_unpack(arguments, "{s:i}", "session-group-id", &session_group_id) == 0) {
        if(session_group_id < 0 || session_group_id > UINT16_MAX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid session-group-id");
        }
    }
    if(json_unpack(arguments, "{s:s}", "direction", &s) == 0) {
        if(strcmp(s, "upstream") == 0) {
            direction = BBL_DIRECTION_UP;
        } else if(strcmp(s, "downstream") == 0) {
            direction = BBL_DIRECTION_DOWN;
        } else if(strcmp(s, "both") == 0) {
            direction = BBL_DIRECTION_BOTH;
        } else {
            return bbl_ctrl_status(fd, "error", 400, "invalid direction");
        }
    }

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            bbl_session_traffic_enable(enabled, session, direction);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                if((session_group_id < 0) || session->session_group_id == session_group_id) {
                    bbl_session_traffic_enable(enabled, session, direction);
                }
            }
        }
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_session_ctrl_traffic_start(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_traffic(fd, session_id, arguments, true);
}

int
bbl_session_ctrl_traffic_stop(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_session_ctrl_traffic(fd, session_id, arguments, false);
}

int
bbl_session_ctrl_traffic_reset(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    bbl_session_s *session;
    uint32_t i;

    int session_group_id = -1;

    if(json_unpack(arguments, "{s:i}", "session-group-id", &session_group_id) == 0) {
        if(session_group_id < 0 || session_group_id > UINT16_MAX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid session-group-id");
        }
    }

    /* Iterate over all sessions */
    for(i = 0; i < g_ctx->sessions; i++) {
        session = &g_ctx->session_list[i];
        if(session) {
            if(session_group_id >= 0 && session->session_group_id != session_group_id) {
                /* Skip sessions with wrong session-group-id if present. */
                continue;
            }
            if(g_ctx->stats.session_traffic_flows_verified >= session->session_traffic.flows_verified) {
                g_ctx->stats.session_traffic_flows_verified -= session->session_traffic.flows_verified;
            }
            session->session_traffic.flows_verified = 0;
            bbl_stream_reset(session->session_traffic.ipv4_up);
            bbl_stream_reset(session->session_traffic.ipv4_down);
            bbl_stream_reset(session->session_traffic.ipv6_up);
            bbl_stream_reset(session->session_traffic.ipv6_down);
            bbl_stream_reset(session->session_traffic.ipv6pd_up);
            bbl_stream_reset(session->session_traffic.ipv6pd_down);
        }
    }   
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_session_ctrl_traffic_stats(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root = json_pack("{ss si s{si si}}",
                             "status", "ok",
                             "code", 200,
                             "session-traffic",
                             "total-flows", g_ctx->stats.session_traffic_flows,
                             "verified-flows", g_ctx->stats.session_traffic_flows_verified);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}