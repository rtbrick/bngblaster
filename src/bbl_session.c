/*
 * BNG Blaster (BBL) - Sessions
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_stats.h"

extern volatile bool g_teardown;

const char *
session_state_string(uint32_t state) {
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
ppp_state_string(uint32_t state) {
    switch(state) {
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
dhcp_state_string(uint32_t state) {
    switch(state) {
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
    bbl_interface_s *interface = session->interface;
    if(CIRCLEQ_NEXT(session, session_tx_qnode)) {
        return;
    }
    CIRCLEQ_INSERT_TAIL(&interface->session_tx_qhead, session, session_tx_qnode);
}

void
bbl_session_tx_qnode_remove(bbl_session_s *session)
{
    bbl_interface_s *interface = session->interface;
    CIRCLEQ_REMOVE(&interface->session_tx_qhead, session, session_tx_qnode);
    CIRCLEQ_NEXT(session, session_tx_qnode) = NULL;
    CIRCLEQ_PREV(session, session_tx_qnode) = NULL;
}

void
bbl_session_network_tx_qnode_insert(bbl_session_s *session)
{
    bbl_interface_s *interface = session->network_interface;
    if(CIRCLEQ_NEXT(session, session_network_tx_qnode)) {
        return;
    }
    if(interface) {
        CIRCLEQ_INSERT_TAIL(&interface->session_tx_qhead, session, session_network_tx_qnode);
    }
}

void
bbl_session_network_tx_qnode_remove(bbl_session_s *session)
{
    bbl_interface_s *interface = session->network_interface;
    if(interface) {
        CIRCLEQ_REMOVE(&interface->session_tx_qhead, session, session_network_tx_qnode);
        CIRCLEQ_NEXT(session, session_network_tx_qnode) = NULL;
        CIRCLEQ_PREV(session, session_network_tx_qnode) = NULL;
    }
}

void
bbl_session_rate_job (timer_s *timer) {
    bbl_session_s *session = timer->data;
    bbl_compute_avg_rate(&session->stats.rate_packets_tx, session->stats.packets_tx);
    bbl_compute_avg_rate(&session->stats.rate_packets_rx, session->stats.packets_rx);
    bbl_compute_avg_rate(&session->stats.rate_bytes_tx, session->stats.bytes_tx);
    bbl_compute_avg_rate(&session->stats.rate_bytes_rx, session->stats.bytes_rx);
}

/**
 * bbl_session_get
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
        if(session->session_state == BBL_ESTABLISHED) {
            /* Decrement sessions established if old state is established. */
            if(ctx->sessions_established) {
                ctx->sessions_established--;
            }
            if(session->dhcp_established) {
                session->dhcp_established = false;
                ctx->dhcp_established--;
            }
            if(session->dhcp_requested) {
                session->dhcp_requested = false;
                ctx->dhcp_requested--;
            }
            if(session->dhcpv6_established) {
                session->dhcpv6_established = false;
                ctx->dhcpv6_established--;
            }
            if(session->dhcpv6_requested) {
                session->dhcpv6_requested = false;
                ctx->dhcpv6_requested--;
            }
        }

        if(state == BBL_ESTABLISHED) {
            /* Increment sessions established and decrement outstanding
             * if new state is established. */
            ctx->sessions_established++;
            if(ctx->sessions_established > ctx->sessions_established_max) ctx->sessions_established_max = ctx->sessions_established;
            if(ctx->sessions_outstanding) ctx->sessions_outstanding--;
            if(ctx->sessions_established == ctx->sessions) {
                LOG(INFO, "ALL SESSIONS ESTABLISHED\n");
            }
        } else if(state == BBL_PPP_TERMINATING) {
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;
        } else if(state == BBL_TERMINATED) {
            /* Stop all session tiemrs */
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
            timer_del(session->timer_session_traffic_ipv4);
            timer_del(session->timer_session_traffic_ipv6);
            timer_del(session->timer_session_traffic_ipv6pd);

            /* Reset all states */
            session->lcp_state = BBL_PPP_CLOSED;
            session->ipcp_state = BBL_PPP_CLOSED;
            session->ip6cp_state = BBL_PPP_CLOSED;

            /* Cleanup A10NSP session */
            bbl_a10nsp_session_free(session);

            /* Increment sessions terminated if new state is terminated. */
            if(g_teardown) {
                ctx->sessions_terminated++;
            } else {
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    if(ctx->config.pppoe_reconnect) {
                        /* Reset session for reconnect */
                        state = BBL_IDLE;
                        CIRCLEQ_INSERT_TAIL(&ctx->sessions_idle_qhead, session, session_idle_qnode);
                        memset(&session->server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
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
                        session->dhcpv6_requested = false;
                        session->dhcpv6_established = false;
                        session->dhcpv6_state = BBL_DHCP_INIT;
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
                        session->l2tp_session = NULL;

                        /* Session traffic */
                        session->session_traffic_flows = 0;
                        session->session_traffic_flows_verified = 0;
                        session->access_ipv4_tx_flow_id = 0;
                        session->access_ipv4_tx_seq = 0;
                        session->access_ipv4_tx_packet_len = 0;
                        session->access_ipv4_rx_first_seq = 0;
                        session->access_ipv4_rx_last_seq = 0;
                        session->network_ipv4_tx_flow_id = 0;
                        session->network_ipv4_tx_seq = 0;
                        session->network_ipv4_tx_packet_len = 0;
                        session->network_ipv4_rx_first_seq = 0;
                        session->network_ipv4_rx_last_seq = 0;
                        session->access_ipv6_tx_flow_id = 0;
                        session->access_ipv6_tx_seq = 0;
                        session->access_ipv6_tx_packet_len = 0;
                        session->access_ipv6_rx_first_seq = 0;
                        session->access_ipv6_rx_last_seq = 0;
                        session->network_ipv6_tx_flow_id = 0;
                        session->network_ipv6_tx_seq = 0;
                        session->network_ipv6_tx_packet_len = 0;
                        session->network_ipv6_rx_first_seq = 0;
                        session->network_ipv6_rx_last_seq = 0;
                        session->access_ipv6pd_tx_flow_id = 0;
                        session->access_ipv6pd_tx_seq = 0;
                        session->access_ipv6pd_tx_packet_len = 0;
                        session->access_ipv6pd_rx_first_seq = 0;
                        session->access_ipv6pd_rx_last_seq = 0;
                        session->network_ipv6pd_tx_flow_id = 0;
                        session->network_ipv6pd_tx_seq = 0;
                        session->network_ipv6pd_tx_packet_len = 0;
                        session->network_ipv6pd_rx_first_seq = 0;
                        session->network_ipv6pd_rx_last_seq = 0;

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
                        session->stats.access_ipv4_rx = 0;
                        session->stats.access_ipv4_tx = 0;
                        session->stats.access_ipv4_loss = 0;
                        session->stats.network_ipv4_rx = 0;
                        session->stats.network_ipv4_tx = 0;
                        session->stats.network_ipv4_loss = 0;
                        session->stats.access_ipv6_rx = 0;
                        session->stats.access_ipv6_tx = 0;
                        session->stats.access_ipv6_loss = 0;
                        session->stats.network_ipv6_rx = 0;
                        session->stats.network_ipv6_tx = 0;
                        session->stats.network_ipv6_loss = 0;
                        session->stats.access_ipv6pd_rx = 0;
                        session->stats.access_ipv6pd_tx = 0;
                        session->stats.access_ipv6pd_loss = 0;
                        session->stats.network_ipv6pd_rx = 0;
                        session->stats.network_ipv6pd_tx = 0;
                        session->stats.network_ipv6pd_loss = 0;

                        /* Increment flap counter */
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
    session_state_t new_state = BBL_TERMINATED;

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
        if(session->dhcp_state > BBL_DHCP_SELECTING) {
            new_state = BBL_TERMINATING;
            if(session->dhcp_state != BBL_DHCP_RELEASE) {
                session->dhcp_state = BBL_DHCP_RELEASE;
                session->dhcp_xid = rand();
                session->dhcp_request_timestamp.tv_sec = 0;
                session->dhcp_request_timestamp.tv_nsec = 0;
                session->dhcp_retry = 0;
                session->send_requests |= BBL_SEND_DHCP_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
        }
        if(session->dhcpv6_state > BBL_DHCP_SELECTING) {
            new_state = BBL_TERMINATING;
            if(session->dhcpv6_state != BBL_DHCP_RELEASE) {
                session->dhcpv6_state = BBL_DHCP_RELEASE;
                session->dhcpv6_xid = rand() & 0xffffff;
                session->dhcpv6_request_timestamp.tv_sec = 0;
                session->dhcpv6_request_timestamp.tv_nsec = 0;
                session->dhcpv6_retry = 0;
                session->send_requests |= BBL_SEND_DHCPV6_REQUEST;
                bbl_session_tx_qnode_insert(session);
            }
        }
        bbl_session_update_state(ctx, session, new_state);
    }
}

static void
update_strings(char **target, const char *source, uint32_t *i, bbl_access_config_s *access_config)
{
    static char snum1[32];
    static char snum2[32];
    static char si1[32];
    static char si2[32];
    char *s;

    if(i && access_config) {
        /* Init iterator */
        snprintf(snum1, sizeof(snum1), "%d", *i);
        snprintf(snum2, sizeof(snum2), "%d", access_config->sessions);
        snprintf(si1, sizeof(si1), "%d", access_config->i1);
        access_config->i1 += access_config->i1_step;
        snprintf(si2, sizeof(si2), "%d", access_config->i2);
        access_config->i2 += access_config->i2_step;
    }
    if(target && source) {
        s = replace_substring(source, "{session-global}", snum1);
        s = replace_substring(s, "{session}", snum2);
        s = replace_substring(s, "{i1}", si1);
        s = replace_substring(s, "{i2}", si2);
        if(s) *target = strdup(s);
    }
}

bool
bbl_sessions_init(bbl_ctx_s *ctx)
{
    bbl_session_s *session;
    bbl_access_config_s *access_config;
    bbl_access_line_profile_s *access_line_profile;
    dict_insert_result result;

    uint32_t i = 1;  /* BNG Blaster internal session identifier */

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
            if(access_config->exhausted) goto NEXT;
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
                goto NEXT;
            }
        }
        t++;
        access_config->sessions++;
        session = calloc(1, sizeof(bbl_session_s));
        if (!session) {
            LOG(ERROR, "Failed to allocate memory for session %u!\n", i);
            return false;
        }
        memset(&session->server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
        memset(&session->dhcp_server_mac, 0xff, ETH_ADDR_LEN); /* init with broadcast MAC */
        session->session_id = i; /* BNG Blaster internal session identifier */
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

        /* Update CFM */
        if(access_config->cfm_cc) {
            session->cfm_cc = true;
            session->cfm_level = access_config->cfm_level;
            session->cfm_ma_id = access_config->cfm_ma_id;
            update_strings(&session->cfm_ma_name, access_config->cfm_ma_name, NULL, NULL);
        }

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
        session->stream_traffic = true;

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
        session->network_interface = bbl_get_network_interface(ctx, access_config->network_interface);
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
        if(access_config->stream_group_id) {
            if(!bbl_stream_add(ctx, access_config, session)) {
                LOG(ERROR, "Failed to create session traffic stream!\n");
                return false;
            }
            timer_add_periodic(&ctx->timer_root, &session->timer_rate, "Rate Computation", 1, 0, session, &bbl_session_rate_job);
        }

        if(access_config->access_line_profile_id) {
            access_line_profile = ctx->config.access_line_profile;
            while(access_line_profile) {
                if(access_line_profile->access_line_profile_id == access_config->access_line_profile_id) {
                    session->access_line_profile = access_line_profile;
                    break;
                }
                access_line_profile = access_line_profile->next;
            }
        }

        LOG(DEBUG, "Session %u created (%s.%u:%u)\n", i, access_config->interface, access_config->access_outer_vlan, access_config->access_inner_vlan);
        i++;
NEXT:
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

json_t *
bbl_session_json(bbl_session_s *session)
{
    json_t *root = NULL;
    json_t *session_traffic = NULL;
    json_t *a10nsp_session = NULL;

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

    if(session->session_traffic_flows) {
        session_traffic = json_pack("{si si si si si si si si si si si si si si si si si si si si si si si si si si}",
            "total-flows", session->session_traffic_flows,
            "verified-flows", session->session_traffic_flows_verified,
            "first-seq-rx-access-ipv4", session->access_ipv4_rx_first_seq,
            "first-seq-rx-access-ipv6", session->access_ipv6_rx_first_seq,
            "first-seq-rx-access-ipv6pd", session->access_ipv6pd_rx_first_seq,
            "first-seq-rx-network-ipv4", session->network_ipv4_rx_first_seq,
            "first-seq-rx-network-ipv6", session->network_ipv6_rx_first_seq,
            "first-seq-rx-network-ipv6pd", session->network_ipv6pd_rx_first_seq,
            "access-tx-session-packets", session->stats.access_ipv4_tx,
            "access-rx-session-packets", session->stats.access_ipv4_rx,
            "access-rx-session-packets-loss", session->stats.access_ipv4_loss,
            "network-tx-session-packets", session->stats.network_ipv4_tx,
            "network-rx-session-packets", session->stats.network_ipv4_rx,
            "network-rx-session-packets-loss", session->stats.network_ipv4_loss,
            "access-tx-session-packets-ipv6", session->stats.access_ipv6_tx,
            "access-rx-session-packets-ipv6", session->stats.access_ipv6_rx,
            "access-rx-session-packets-ipv6-loss", session->stats.access_ipv6_loss,
            "network-tx-session-packets-ipv6", session->stats.network_ipv6_tx,
            "network-rx-session-packets-ipv6", session->stats.network_ipv6_rx,
            "network-rx-session-packets-ipv6-loss", session->stats.network_ipv6_loss,
            "access-tx-session-packets-ipv6pd", session->stats.access_ipv6pd_tx,
            "access-rx-session-packets-ipv6pd", session->stats.access_ipv6pd_rx,
            "access-rx-session-packets-ipv6pd-loss", session->stats.access_ipv6pd_loss,
            "network-tx-session-packets-ipv6pd", session->stats.network_ipv6pd_tx,
            "network-rx-session-packets-ipv6pd", session->stats.network_ipv6pd_rx,
            "network-rx-session-packets-ipv6pd-loss", session->stats.network_ipv6pd_loss);
    }

    if(session->a10nsp_session) {
        a10nsp_session = json_pack("{ss si sb sb ss* ss* si si}",
            "interface", session->a10nsp_session->a10nsp_if->name,
            "s-vlan", session->a10nsp_session->s_vlan,
            "qinq-send", session->a10nsp_session->a10nsp_if->qinq,
            "qinq-received", session->a10nsp_session->qinq_received,
            "pppoe-aci", session->a10nsp_session->pppoe_aci,
            "pppoe-ari", session->a10nsp_session->pppoe_ari,
            "tx-packets", session->a10nsp_session->stats.packets_tx,
            "rx-packets", session->a10nsp_session->stats.packets_rx);
    }

    if(session->access_type == ACCESS_TYPE_PPPOE) {
        root = json_pack("{ss si ss ss si si ss ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* si si si so* so*}",
            "type", "pppoe",
            "session-id", session->session_id,
            "session-state", session_state_string(session->session_state),
            "interface", session->interface->name,
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
            "session-traffic", session_traffic,
            "a10nsp", a10nsp_session);

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

        root = json_pack("{ss si ss ss si si ss ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* ss* si si si si si si si si si si si si ss* si si si si si si si si si si si si ss* ss* si si si so* so*}",
            "type", "ipoe",
            "session-id", session->session_id,
            "session-state", session_state_string(session->session_state),
            "interface", session->interface->name,
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
            "session-traffic", session_traffic,
            "a10nsp", a10nsp_session);
    }
    if(!root) {
        if(a10nsp_session) json_decref(a10nsp_session);
        if(session_traffic) json_decref(session_traffic);
    }
    return root;
}