

/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_session.h"

extern volatile bool g_teardown;

/** 
 * bbl_session_update_state 
 *
 * This function allows to change the state of a session including
 * the required action caused by state changes. 
 * 
 * @param ctx global context
 * @param session_id session-id
 * @return session or NULL if session not found
 */

bbl_session_s *
bbl_session_get(bbl_ctx_s *ctx, uint32_t session_id)
{
    if(session_id > ctx->sessions || session_id < 1) {
        return NULL;
    }
    return ctx->session_list[session_id-1];
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
bbl_session_update_state(bbl_ctx_s *ctx, bbl_session_s *session, session_state_t state)
{
    if(session->session_state != state) {
        /* State has changed ... */
        if(session->session_state == BBL_ESTABLISHED && ctx->sessions_established) {
            /* Decrement sessions established if old state is established. */
            ctx->sessions_established--;
            if(session->dhcpv6_received) {
                ctx->dhcpv6_established--;
            }
            if(session->dhcpv6_requested) {
                ctx->dhcpv6_requested--;
            }
        } else if(state == BBL_ESTABLISHED) {
            /* Increment sessions established and decrement outstanding
             * if new state is established. */
            ctx->sessions_established++;
            if(ctx->sessions_established > ctx->sessions_established_max) ctx->sessions_established_max = ctx->sessions_established;
            if(ctx->sessions_outstanding) ctx->sessions_outstanding--;
        }
        if(state == BBL_PPP_TERMINATING) {
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;
        }
        if(state == BBL_TERMINATED) {
            /* Stop all session tiemrs */
            timer_del(session->timer_arp);
            timer_del(session->timer_padi);
            timer_del(session->timer_padr);
            timer_del(session->timer_lcp);
            timer_del(session->timer_lcp_echo);
            timer_del(session->timer_auth);
            timer_del(session->timer_ipcp);
            timer_del(session->timer_ip6cp);
            timer_del(session->timer_dhcpv6);
            timer_del(session->timer_igmp);
            timer_del(session->timer_zapping);
            timer_del(session->timer_icmpv6);
            timer_del(session->timer_session);
            timer_del(session->timer_session_traffic_ipv4);
            timer_del(session->timer_session_traffic_ipv6);
            timer_del(session->timer_session_traffic_ipv6pd);

            /* Reset all states */
            session->lcp_state = BBL_PPP_CLOSED;
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;

            /* Increment sessions terminated if new state is terminated. */
            if(g_teardown) {
                ctx->sessions_terminated++;
            } else {
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    if(ctx->config.pppoe_reconnect) {
                        state = BBL_IDLE;
                        CIRCLEQ_INSERT_TAIL(&ctx->sessions_idle_qhead, session, session_idle_qnode);
                        memset(&session->server_mac, 0xff, ETH_ADDR_LEN); // init with broadcast MAC
                        session->pppoe_session_id = 0;
                        if(session->pppoe_ac_cookie) {
                            free(session->pppoe_ac_cookie);
                            session->pppoe_ac_cookie = NULL;
                        }
                        session->pppoe_ac_cookie_len = 0;
                        if(!session->interface->ctx->config.pppoe_service_name) {
                            if(session->pppoe_service_name) {
                                free(session->pppoe_service_name);
                                session->pppoe_service_name = NULL;
                            }
                            session->pppoe_service_name_len = 0;
                        }
                        session->ip_address = 0;
                        session->peer_ip_address = 0;
                        session->dns1 = 0;
                        session->dns2 = 0;
                        session->ipv6_prefix.len = 0;
                        session->delegated_ipv6_prefix.len = 0;
                        session->icmpv6_ra_received = false;
                        memset(session->ipv6_dns1, 0x0, IPV6_ADDR_LEN);
                        memset(session->ipv6_dns2, 0x0, IPV6_ADDR_LEN);
                        session->dhcpv6_requested = false;
                        session->dhcpv6_received = false;
                        session->dhcpv6_type = DHCPV6_MESSAGE_SOLICIT;
                        session->dhcpv6_ia_pd_option_len = 0;
                        memset(session->dhcpv6_dns1, 0x0, IPV6_ADDR_LEN);
                        memset(session->dhcpv6_dns2, 0x0, IPV6_ADDR_LEN);
                        session->zapping_joined_group = NULL;
                        session->zapping_leaved_group = NULL;
                        session->zapping_count = 0;
                        session->zapping_view_start_time.tv_sec = 0;
                        session->zapping_view_start_time.tv_nsec = 0;
                        session->stats.flapped++;
                        ctx->sessions_flapped++;
                    } else {
                        ctx->sessions_terminated++;
                    }
                } else {
                    /* IPoE */
                    ctx->sessions_terminated++;
                }
            }
        }
        session->session_state = state;
    }
}

/** 
 * bbl_session_clear 
 *
 * This function terminates a session gracefully. 
 * 
 * @param ctx global context
 * @param session session
 */
void
bbl_session_clear(bbl_ctx_s *ctx, bbl_session_s *session)
{
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        switch(session->session_state) {
            case BBL_IDLE:
                bbl_session_update_state(ctx, session, BBL_TERMINATED);
                break;
            case BBL_PPPOE_INIT:
            case BBL_PPPOE_REQUEST:
            case BBL_PPP_LINK:
                bbl_session_update_state(ctx, session, BBL_TERMINATING);
                session->send_requests = BBL_SEND_DISCOVERY;
                bbl_session_tx_qnode_insert(session);
                break;
            case BBL_PPP_AUTH:
            case BBL_PPP_NETWORK:
            case BBL_ESTABLISHED:
            case BBL_PPP_TERMINATING:
                bbl_session_update_state(ctx, session, BBL_PPP_TERMINATING);
                session->lcp_request_code = PPP_CODE_TERM_REQUEST;
                session->lcp_options_len = 0;
                session->send_requests |= BBL_SEND_LCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
                break;
            default:
                break;
        }
    } else {
        bbl_session_update_state(ctx, session, BBL_TERMINATED);
    }
}
