

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

bool
bbl_sessions_init(bbl_ctx_s *ctx)
{
    bbl_session_s *session;
    bbl_access_config_s *access_config;
    
    dict_insert_result result;

    uint32_t i = 1;  /* BNG Blaster internal session identifier */

    char *s;
    char snum1[32];
    char snum2[32];

    /* The variable t counts how many sessions are created in one 
     * loop over all access configurations and is reset to zero
     * every time we start from first access profile. If the variable 
     * is still zero after processing last access profile means 
     * that all VLAN ranges are exhausted. */
    int t = 0;
    
    
    /* Init list of sessions */
    ctx->session_list = calloc(ctx->config.sessions, sizeof(session));    
    access_config = ctx->config.access_config;

    /* For equal distribution of sessions over access configurations 
     * and outer VLAN's, we loop first over all configurations and
     * second over VLAN ranges as per configration. */
    while(i <= ctx->config.sessions) {
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
            if(access_config->exhausted) goto Next;
            if(access_config->access_outer_vlan == 0) {
                /* The outer VLAN is initial 0 */
                access_config->access_outer_vlan = access_config->access_outer_vlan_min;
                access_config->access_inner_vlan = access_config->access_inner_vlan_min;
            } else {
                if(ctx->config.iterate_outer_vlan) {
                    /* Iterate over outer VLAN first and inner VLAN second */
                    access_config->access_outer_vlan++;
                    if(access_config->access_outer_vlan > access_config->access_outer_vlan_max) {
                        access_config->access_outer_vlan = access_config->access_outer_vlan_min;
                        access_config->access_inner_vlan++;
                    }
                } else {
                    /* Iterate over inner VLAN first and outer VLAN second (default) */
                    access_config->access_inner_vlan++;
                    if(access_config->access_inner_vlan > access_config->access_inner_vlan_max) {
                        access_config->access_inner_vlan = access_config->access_inner_vlan_min;
                        access_config->access_outer_vlan++;
                    }
                }
            }
            if(access_config->access_outer_vlan == 0) {
                /* This is required to handle untagged interafaces */
                access_config->exhausted = true;
            }
            if(access_config->access_outer_vlan > access_config->access_outer_vlan_max || 
            access_config->access_inner_vlan > access_config->access_inner_vlan_max) {
                /* VLAN range exhausted */
                access_config->exhausted = true;
                goto Next;
            }
        }
        t++;
        access_config->sessions++;
        session = calloc(1, sizeof(bbl_session_s));
        if (!session) {
            LOG(ERROR, "Failed to allocate memory for session %u!\n", i);
            return false;
        }
        memset(&session->server_mac, 0xff, ETH_ADDR_LEN); // init with broadcast MAC
        session->session_id = i; // BNG Blaster internal session identifier
        session->access_type = access_config->access_type;
        session->vlan_key.ifindex = access_config->access_if->ifindex;
        session->vlan_key.outer_vlan_id= access_config->access_outer_vlan;
        session->vlan_key.inner_vlan_id = access_config->access_inner_vlan;
        session->access_third_vlan = access_config->access_third_vlan;
        session->access_config = access_config;

        /* Set client OUI to locally administered */
        session->client_mac[0] = 0x02;
        session->client_mac[1] = 0x00;
        session->client_mac[2] = 0x00;
        /* Use session identifier for remaining bytes */
        session->client_mac[3] = i>>16;
        session->client_mac[4] = i>>8;
        session->client_mac[5] = i;

        /* Set DHCPv6 DUID */
        session->duid[1] = 3;
        session->duid[3] = 1;
        memcpy(&session->duid[4], session->client_mac, ETH_ADDR_LEN);

        /* Populate session identifiaction attributes */
        snprintf(snum1, 6, "%d", i);
        snprintf(snum2, 6, "%d", access_config->sessions);
    
        /* Update username */
        s = replace_substring(access_config->username, "{session-global}", snum1);
        session->username = s;
        s = replace_substring(session->username, "{session}", snum2);
        session->username = strdup(s);

        /* Update password */
        s = replace_substring(access_config->password, "{session-global}", snum1);
        session->password = s;
        s = replace_substring(session->password, "{session}", snum2);
        session->password = strdup(s);

        /* Update ACI */
        s = replace_substring(access_config->agent_circuit_id, "{session-global}", snum1);
        session->agent_circuit_id = s;
        s = replace_substring(session->agent_circuit_id, "{session}", snum2);
        session->agent_circuit_id = strdup(s);

        /* Update ARI */
        s = replace_substring(access_config->agent_remote_id, "{session-global}", snum1);
        session->agent_remote_id = s;
        s = replace_substring(session->agent_remote_id, "{session}", snum2);
        session->agent_remote_id = strdup(s);
        
        /* Update access rates ... */
        session->rate_up = access_config->rate_up;
        session->rate_down = access_config->rate_down;
        session->dsl_type = access_config->dsl_type;

        /* IGMP */
        session->igmp_autostart = access_config->igmp_autostart;
        session->igmp_version = access_config->igmp_version;
        session->igmp_robustness = 2; /* init robustness with 2 */
        session->zapping_group_max = be32toh(ctx->config.igmp_group) + ((ctx->config.igmp_group_count - 1) * be32toh(ctx->config.igmp_group_iter));
        
        /* Session traffic */
        session->session_traffic = access_config->session_traffic_autostart;
    
        /* Set access type specifc values */
        if(session->access_type == ACCESS_TYPE_PPPOE) {
            session->mru = ctx->config.ppp_mru;
            session->magic_number = htobe32(i);
            if(ctx->config.pppoe_service_name) {
                session->pppoe_service_name = (uint8_t*)ctx->config.pppoe_service_name;
                session->pppoe_service_name_len = strlen(ctx->config.pppoe_service_name);
            }
            if(ctx->config.pppoe_host_uniq) {
                session->pppoe_host_uniq = htobe64(i);
            }
        } else if(session->access_type == ACCESS_TYPE_IPOE) {
            if(access_config->static_ip && access_config->static_gateway) {
                session->ip_address = access_config->static_ip;
                session->peer_ip_address = access_config->static_gateway;
                access_config->static_ip = htobe32(be32toh(access_config->static_ip) + be32toh(access_config->static_ip_iter));
                access_config->static_gateway = htobe32(be32toh(access_config->static_gateway) + be32toh(access_config->static_gateway_iter));
            }
        }
        session->interface = access_config->access_if;
        session->session_state = BBL_IDLE;
        CIRCLEQ_INSERT_TAIL(&ctx->sessions_idle_qhead, session, session_idle_qnode);
        ctx->sessions++;
        if(session->access_type == ACCESS_TYPE_PPPOE) {
            ctx->sessions_pppoe++;
        } else {
            ctx->sessions_ipoe++;
        }
        /* Add session to list */
        ctx->session_list[i-1] = session;

        if(access_config->vlan_mode == VLAN_MODE_11) {
            /* Add 1:1 sessions to VLAN/session dictionary */
            result = dict_insert(ctx->vlan_session_dict, &session->vlan_key);
            if (result.inserted) {
                *result.datum_ptr = session;
            }
        }

        LOG(DEBUG, "Session %u created (%s.%u:%u)\n", i, access_config->interface, access_config->access_outer_vlan, access_config->access_inner_vlan);
        i++;
Next:
        if(access_config->next) {
            access_config = access_config->next;
        } else {
            if (t) {
                t = 0;
                access_config = ctx->config.access_config;
            } else {
                LOG(ERROR, "Failed to create sessions because VLAN ranges exhausted!\n");
                return false;
            }

        }
    }
    return true;
}

