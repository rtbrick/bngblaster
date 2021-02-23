/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <jansson.h>

#include "bbl.h"
#include "bbl_ctrl.h"
#include "bbl_logging.h"

#define BACKLOG 4
#define INPUT_BUFFER 1024

extern volatile bool g_teardown;
extern volatile bool g_teardown_request;

typedef ssize_t callback_function(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments);

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

ssize_t
bbl_ctrl_status(int fd, const char *status, uint32_t code, const char *message) {
    ssize_t result = 0;
    json_t *root = json_pack("{sssiss*}", "status", status, "code", code, "message", message);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

ssize_t
bbl_ctrl_multicast_traffic_start(int fd, bbl_ctx_s *ctx, session_key_t *key __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ctx->multicast_traffic = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

ssize_t
bbl_ctrl_multicast_traffic_stop(int fd, bbl_ctx_s *ctx, session_key_t *key __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ctx->multicast_traffic = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

ssize_t
bbl_ctrl_session_traffic(int fd, bbl_ctx_s *ctx, session_key_t *key, bool status) {
    struct dict_itor *itor;
    bbl_session_s *session;
    void **search;
    if(key->outer_vlan_id || key->inner_vlan_id) {
        search = dict_search(ctx->session_dict, key);
        if(search) {
            session = *search;
            session->session_traffic = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        itor = dict_itor_new(ctx->session_dict);
        dict_itor_first(itor);
        for (; dict_itor_valid(itor); dict_itor_next(itor)) {
            session = (bbl_session_s*)*dict_itor_datum(itor);
            if(session) {
                session->session_traffic = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
    return 0;
}

ssize_t
bbl_ctrl_session_traffic_start(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_traffic(fd, ctx, key, true);
}

ssize_t
bbl_ctrl_session_traffic_stop(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_traffic(fd, ctx, key, false);
}

ssize_t
bbl_ctrl_igmp_join(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments) {
    bbl_session_s *session;
    void **search;
    const char *s;
    uint32_t group_address = 0;
    uint32_t source1 = 0;
    uint32_t source2 = 0;
    uint32_t source3 = 0;
    bbl_igmp_group_s *group = NULL;
    int i;

    /* Unpack further arguments */
    if (json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }
    if (json_unpack(arguments, "{s:s}", "source1", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source1)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source1 address");
        }
    }
    if (json_unpack(arguments, "{s:s}", "source2", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source2)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source2 address");
        }
    }
    if (json_unpack(arguments, "{s:s}", "source3", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source3)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source3 address");
        }
    }

    /* Search session */
    search = dict_search(ctx->session_dict, key);
    if(search) {
        session = *search;
        /* Search for free slot ... */
        for(i=0; i < IGMP_MAX_GROUPS; i++) {
            if(!session->igmp_groups[i].zapping) {
                if (session->igmp_groups[i].group == group_address) {
                    group = &session->igmp_groups[i];
                    if(group->state == IGMP_GROUP_IDLE) {
                        break;
                    } else {
                        return bbl_ctrl_status(fd, "error", 409, "group already exists");
                    }
                } else if(session->igmp_groups[i].state == IGMP_GROUP_IDLE) {
                    group = &session->igmp_groups[i];
                }
            }
        }
        if(!group) {
            return bbl_ctrl_status(fd, "error", 409, "no igmp group slot available");
        }

        memset(group, 0x0, sizeof(bbl_igmp_group_s));
        group->group = group_address;
        if(source1) group->source[0] = source1;
        if(source2) group->source[1] = source2;
        if(source3) group->source[2] = source3;
        group->state = IGMP_GROUP_JOINING;
        group->robustness_count = session->igmp_robustness;
        group->send = true;
        session->send_requests |= BBL_SEND_IGMP;
        bbl_session_tx_qnode_insert(session);

        LOG(IGMP, "IGMP (Q-in-Q %u:%u) join %s\n",
                session->key.outer_vlan_id, session->key.inner_vlan_id,
                format_ipv4_address(&group->group));

        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
    return 0;
}

ssize_t
bbl_ctrl_igmp_leave(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments) {

    bbl_session_s *session;
    void **search;
    const char *s;
    uint32_t group_address = 0;
    bbl_igmp_group_s *group = NULL;
    int i;

    if(!(key->outer_vlan_id || key->inner_vlan_id)) {
        /* VLAN is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "invalid request");
    }
    if (json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }

    search = dict_search(ctx->session_dict, key);
    if(search) {
        session = *search;
        /* Search for group ... */
        for(i=0; i < IGMP_MAX_GROUPS; i++) {
            if (session->igmp_groups[i].group == group_address) {
                group = &session->igmp_groups[i];
                break;
            }
        }
        if(!group) {
            return bbl_ctrl_status(fd, "warning", 404, "group not found");
        }
        if(group->zapping) {
            return bbl_ctrl_status(fd, "error", 408, "group used by zapping test");
        }
        if(group->state <= IGMP_GROUP_LEAVING) {
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        }
        group->state = IGMP_GROUP_LEAVING;
        group->robustness_count = session->igmp_robustness;
        group->send = true;
        group->leave_tx_time.tv_sec = 0;
        group->leave_tx_time.tv_nsec = 0;
        group->last_mc_rx_time.tv_sec = 0;
        group->last_mc_rx_time.tv_nsec = 0;
        session->send_requests |= BBL_SEND_IGMP;
        bbl_session_tx_qnode_insert(session);

        LOG(IGMP, "IGMP (Q-in-Q %u:%u) leave %s\n",
                session->key.outer_vlan_id, session->key.inner_vlan_id,
                format_ipv4_address(&group->group));

        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
    return 0;
}

ssize_t
bbl_ctrl_igmp_info(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root, *groups, *record, *sources;
    bbl_session_s *session = NULL;
    void **search;
    bbl_igmp_group_s *group = NULL;
    uint32_t delay = 0;
    struct timespec time_diff;
    int ms, i, i2;
    search = dict_search(ctx->session_dict, key);
    if(search) {
        session = *search;
        groups = json_array();
        /* Add group informations */
        for(i=0; i < IGMP_MAX_GROUPS; i++) {
            group = &session->igmp_groups[i];
            if(group->group) {
                sources = json_array();
                for(i2=0; i2 < IGMP_MAX_SOURCES; i2++) {
                    if(group->source[i2]) {
                        json_array_append(sources, json_string(format_ipv4_address(&group->source[i2])));
                    }
                }
                record = json_pack("{ss so si si}", 
                                "group", format_ipv4_address(&group->group), 
                                "sources", sources,
                                "packets", group->packets,
                                "loss", group->loss);
                
                switch (group->state) {
                    case IGMP_GROUP_IDLE:
                        json_object_set(record, "state", json_string("idle"));
                        if(group->last_mc_rx_time.tv_sec && group->leave_tx_time.tv_sec) {
                            timespec_sub(&time_diff, &group->last_mc_rx_time, &group->leave_tx_time);
                            ms = round(time_diff.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
                            delay = (time_diff.tv_sec * 1000) + ms;
                            json_object_set(record, "leave-delay-ms", json_integer(delay));
                        }
                        break;
                    case IGMP_GROUP_LEAVING:
                        json_object_set(record, "state", json_string("leaving"));
                        break;
                    case IGMP_GROUP_ACTIVE:
                        json_object_set(record, "state", json_string("active"));
                        if(group->first_mc_rx_time.tv_sec) {
                            timespec_sub(&time_diff, &group->first_mc_rx_time, &group->join_tx_time);
                            ms = round(time_diff.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
                            delay = (time_diff.tv_sec * 1000) + ms;
                            json_object_set(record, "join-delay-ms", json_integer(delay));
                        }
                        break;
                    case IGMP_GROUP_JOINING:
                        json_object_set(record, "state", json_string("joining"));
                        if(group->first_mc_rx_time.tv_sec) {
                            timespec_sub(&time_diff, &group->first_mc_rx_time, &group->join_tx_time);
                            ms = round(time_diff.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
                            delay = (time_diff.tv_sec * 1000) + ms;
                            json_object_set(record, "join-delay-ms", json_integer(delay));
                        }
                        break;
                    default:
                        break;
                }
                json_array_append(groups, record);
            }
        }
        root = json_pack("{ss si so}", 
                        "status", "ok", 
                        "code", 200,
                        "igmp-groups", groups);
        if(root) {
            result = json_dumpfd(root, fd, 0);
            json_decref(root);
        } else {
            bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(groups);
        }        
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_session_counters(int fd, bbl_ctx_s *ctx, session_key_t *key __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root = json_pack("{ss si s{si si si si}}", 
                             "status", "ok", 
                             "code", 200,
                             "session-counters",
                             "sessions", ctx->config.sessions,
                             "sessions-established", ctx->sessions_established_max,
                             "sessions-flapped", ctx->sessions_flapped,
                             "dhcpv6-sessions-established", ctx->dhcpv6_established_max);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

ssize_t
bbl_ctrl_session_info(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root;
    json_t *session_traffic = NULL;

    bbl_session_s *session;
    void **search;

    const char *ipv4 = NULL;
    const char *ipv6 = NULL;
    const char *ipv6pd = NULL;
    const char *type = NULL;
    const char *username = NULL;
    const char *lcp = NULL;
    const char *ipcp = NULL;
    const char *ip6cp = NULL;

    search = dict_search(ctx->session_dict, key);
    if(search) {
        session = *search;
        if(session->ip_address) {
            ipv4 = format_ipv4_address(&session->ip_address);
        }
        if(session->ipv6_prefix.len) {
            ipv6 = format_ipv6_prefix(&session->ipv6_prefix);
        }
        if(session->delegated_ipv6_prefix.len) {
            ipv6pd = format_ipv6_prefix(&session->delegated_ipv6_prefix);
        }

        if(session->access_type == ACCESS_TYPE_PPPOE) {
            type = "pppoe";
            username = session->username;
            lcp = ppp_state_string(session->lcp_state);
            ipcp = ppp_state_string(session->ipcp_state);
            ip6cp = ppp_state_string(session->ip6cp_state);

        } else {
            type = "ipoe";
        }
        if(ctx->config.session_traffic_ipv4_pps || ctx->config.session_traffic_ipv6_pps || ctx->config.session_traffic_ipv6pd_pps) {
            session_traffic = json_pack("{si si si si si si si si si si si si si si si si si si si si si si si si}", 
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
        root = json_pack("{ss si s{ss ss* ss ss ss ss* ss* ss* ss* ss* ss* so*}}", 
                        "status", "ok", 
                        "code", 200,
                        "session-information",
                        "type", type,
                        "username", username,
                        "agent-circuit-id", session->agent_circuit_id,
                        "agent-remote-id", session->agent_remote_id,
                        "session-state", session_state_string(session->session_state),
                        "lcp-state", lcp,
                        "ipcp-state", ipcp,
                        "ip6cp-state", ip6cp,
                        "ipv4-address",ipv4,
                        "ipv6-prefix", ipv6,
                        "ipv6-delegated-prefix", ipv6pd,
                        "session-traffic", session_traffic);
        if(root) {
            result = json_dumpfd(root, fd, 0);
            json_decref(root);
        } else {
            bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(session_traffic);
        }
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_interfaces(int fd, bbl_ctx_s *ctx, session_key_t *key __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root, *interfaces, *interface;
    char *type = "network";
    int i;

    interfaces = json_array();
    for(i=0; i < ctx->op.access_if_count; i++) {
        if(ctx->op.access_if[i]->access) {
            type = "access";
        }
        interface = json_pack("{ss si ss}", 
                            "name", ctx->op.access_if[i]->name, 
                            "ifindex", ctx->op.access_if[i]->addr.sll_ifindex,
                            "type", type);
        json_array_append(interfaces, interface);
    }

    root = json_pack("{ss si so}", 
                    "status", "ok", 
                    "code", 200,
                    "interfaces", interfaces);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(interfaces);
    }
    return result;
}

ssize_t
bbl_ctrl_session_terminate(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    bbl_session_s *session;
    void **search;
    if(key->outer_vlan_id || key->inner_vlan_id) {
        /* Terminate single matching session ... */
        search = dict_search(ctx->session_dict, key);
        if(search) {
            session = *search;
            bbl_session_clear(ctx, session);
            return bbl_ctrl_status(fd, "ok", 200, "terminate session");
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Terminate all sessions ... */
        g_teardown = true;
        g_teardown_request = true;
        LOG(NORMAL, "Teardown request\n");
        return bbl_ctrl_status(fd, "ok", 200, "terminate all sessions");
    }
    return 0;
}

static void
bbl_ctrl_session_ncp_open(bbl_session_s *session, bool ipcp) {
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

static void
bbl_ctrl_session_ncp_close(bbl_ctx_s *ctx, bbl_session_s *session, bool ipcp) {
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
        } else {
            /* ip6cp */
            if(session->ip6cp_state == BBL_PPP_OPENED) {
                session->ip6cp_state = BBL_PPP_TERMINATE;
                session->ip6cp_request_code = PPP_CODE_TERM_REQUEST;
                session->send_requests |= BBL_SEND_IP6CP_REQUEST;
                session->ipv6_prefix.len = 0;
                session->delegated_ipv6_prefix.len = 0;
                session->icmpv6_ra_received = false;
                session->dhcpv6_type = DHCPV6_MESSAGE_SOLICIT;
                session->dhcpv6_ia_pd_option_len = 0;
                if(session->dhcpv6_received) {
                    ctx->dhcpv6_established--;
                }
                session->dhcpv6_received = false;
                if(session->dhcpv6_requested) {
                    ctx->dhcpv6_requested--;
                }
                session->dhcpv6_requested = false;
                bbl_session_tx_qnode_insert(session);
            }
        }
    }
}

ssize_t
bbl_ctrl_session_ncp_open_close(int fd, bbl_ctx_s *ctx, session_key_t *key, bool open, bool ipcp) {
    struct dict_itor *itor;
    bbl_session_s *session;
    void **search;
    if(key->outer_vlan_id || key->inner_vlan_id) {
        search = dict_search(ctx->session_dict, key);
        if(search) {
            session = *search;
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                if(open) {
                    bbl_ctrl_session_ncp_open(session, ipcp);
                } else {
                    bbl_ctrl_session_ncp_close(ctx, session, ipcp);
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
        itor = dict_itor_new(ctx->session_dict);
        dict_itor_first(itor);
        for (; dict_itor_valid(itor); dict_itor_next(itor)) {
            session = (bbl_session_s*)*dict_itor_datum(itor);
            if(session) {
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    if(open) {
                        bbl_ctrl_session_ncp_open(session, ipcp);
                    } else {
                        bbl_ctrl_session_ncp_close(ctx, session, ipcp);
                    }
                }
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
    return 0;
}

ssize_t
bbl_ctrl_session_ipcp_open(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, key, true, true);
}

ssize_t
bbl_ctrl_session_ipcp_close(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, key, false, true);
}

ssize_t
bbl_ctrl_session_ip6cp_open(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, key, true, false);
}

ssize_t
bbl_ctrl_session_ip6cp_close(int fd, bbl_ctx_s *ctx, session_key_t *key, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, key, false, false);
}

ssize_t
bbl_ctrl_li_flows(int fd, bbl_ctx_s *ctx, session_key_t *key __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root, *flows, *flow;
    bbl_li_flow_t *li_flow;
    struct dict_itor *itor;

    flows = json_array();
    itor = dict_itor_new(ctx->li_flow_dict);
    dict_itor_first(itor);
    for (; dict_itor_valid(itor); dict_itor_next(itor)) {
        li_flow = (bbl_li_flow_t*)*dict_itor_datum(itor);
        if(li_flow) {
            flow = json_pack("{si si si si si si si si si si}", 
                                "direction", li_flow->direction, 
                                "packet-type", li_flow->packet_type, 
                                "sub-packet-type", li_flow->sub_packet_type,
                                "liid", li_flow->liid,
                                "bytes-rx", li_flow->bytes_rx,
                                "packets-rx", li_flow->packets_rx,
                                "packets-rx-ipv4", li_flow->packets_rx_ipv4,
                                "packets-rx-ipv4-tcp", li_flow->packets_rx_ipv4_tcp,
                                "packets-rx-ipv4-udp", li_flow->packets_rx_ipv4_udp,
                                "packets-rx-ipv4-host-internal", li_flow->packets_rx_ipv4_internal);
            json_array_append(flows, flow);
        }
    }
    root = json_pack("{ss si so}", 
                    "status", "ok", 
                    "code", 200,
                    "li-flows", flows);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(flows);
    }
    return result;
}
struct action {
    char *name;
    callback_function *fn;
};

struct action actions[] = {
    {"interfaces", bbl_ctrl_interfaces},
    {"terminate", bbl_ctrl_session_terminate},
    {"ipcp-open", bbl_ctrl_session_ipcp_open},
    {"ipcp-close", bbl_ctrl_session_ipcp_close},
    {"ip6cp-open", bbl_ctrl_session_ip6cp_open},
    {"ip6cp-close", bbl_ctrl_session_ip6cp_close},
    {"session-counters", bbl_ctrl_session_counters},
    {"session-info", bbl_ctrl_session_info},
    {"session-traffic-enabled", bbl_ctrl_session_traffic_start},
    {"session-traffic-start", bbl_ctrl_session_traffic_start},
    {"session-traffic-disabled", bbl_ctrl_session_traffic_stop},
    {"session-traffic-stop", bbl_ctrl_session_traffic_stop},
    {"multicast-traffic-start", bbl_ctrl_multicast_traffic_start},
    {"multicast-traffic-stop", bbl_ctrl_multicast_traffic_stop},
    {"igmp-join", bbl_ctrl_igmp_join},
    {"igmp-leave", bbl_ctrl_igmp_leave},
    {"igmp-info", bbl_ctrl_igmp_info},
    {"li-flows", bbl_ctrl_li_flows},
    {NULL, NULL},
};

void
bbl_ctrl_socket_job (timer_s *timer) {
    bbl_ctx_s *ctx = timer->data;

    session_key_t key = {0};

    char buf[INPUT_BUFFER];
    ssize_t len;
    int fd;
    size_t i;
    json_error_t error;
    json_t *root = NULL;
    json_t* arguments = NULL;
    json_t* value = NULL;

    const char *command = NULL;

    while(true) {
        fd = accept(ctx->ctrl_socket, 0, 0);
        if(fd < 0) {
            /* The accept function fails with error EAGAIN or EWOULDBLOCK if
             * there are no pending connections present on the queue.*/
            if((errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
        } else {
            /* New connection */
            bzero(buf, sizeof(buf));
            len = read(fd, buf, INPUT_BUFFER);
            if(len) {
                root = json_loads((const char*)buf, 0, &error);
                if (!root) {
                    LOG(DEBUG, "Invalid json via ctrl socket: line %d: %s\n", error.line, error.text);
                    bbl_ctrl_status(fd, "error", 400, "invalid json");
                } else {
                    /* Each command request should be formatted as shown in the example below
                     * with a mandatory command element and optional arguments.
                     * {
                     *    "command": "session-info",
                     *    "arguments": {
                     *        "outer-vlan": 1,
                     *        "inner-vlan": 2
                     *    }
                     * }
                     */
                    if(json_unpack(root, "{s:s, s?o}", "command", &command, "arguments", &arguments) != 0) {
                        LOG(DEBUG, "Invalid command via ctrl socket\n");
                        bbl_ctrl_status(fd, "error", 400, "invalid request");
                    } else {
                        if(arguments) {
                            value = json_object_get(arguments, "ifindex");
                            if (value) {
                                if(json_is_number(value)) {
                                    key.ifindex = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid ifindex");
                                    goto Close;
                                }
                            } else {
                                /* Use first interface as default. */
                                key.ifindex = ctx->op.access_if[0]->addr.sll_ifindex;
                            }
                            value = json_object_get(arguments, "outer-vlan");
                            if (value) {
                                if(json_is_number(value)) {
                                    key.outer_vlan_id = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid outer-vlan");
                                    goto Close;
                                }
                            }
                            value = json_object_get(arguments, "inner-vlan");
                            if (value) {
                                if(json_is_number(value)) {
                                    key.inner_vlan_id = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid inner-vlan");
                                    goto Close;
                                }
                            }
                        }
                        for(i = 0; true; i++) {
                            if(actions[i].name == NULL) {
                                bbl_ctrl_status(fd, "error", 400, "unknown command");
                                break;
                            } else if(strcmp(actions[i].name, command) == 0) {
                                actions[i].fn(fd, ctx, &key, arguments);
                                break;
                            }
                        }
                    }
                }
            }
Close:
            if(root) json_decref(root);
            close(fd);
        }
    }
}

bool
bbl_ctrl_socket_open (bbl_ctx_s *ctx) {
    struct sockaddr_un addr = {0};
    ctx->ctrl_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if(ctx->ctrl_socket < 0) {
        fprintf(stderr, "Error: Failed to create ctrl socket\n");
        return false;
    }
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ctx->ctrl_socket_path, sizeof(addr.sun_path)-1);
    
    unlink(ctx->ctrl_socket_path);
    if (bind(ctx->ctrl_socket, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
        fprintf(stderr, "Error: Failed to bind ctrl socket %s (error %d)\n", ctx->ctrl_socket_path, errno);
        return false;
    }

    if (listen(ctx->ctrl_socket, BACKLOG) != 0) {
        fprintf(stderr, "Error: Failed to listen on ctrl socket %s (error %d)\n", ctx->ctrl_socket_path, errno);
        return false;
    }

    /* Change socket to non-blocking */
    fcntl(ctx->ctrl_socket, F_SETFL, O_NONBLOCK);

    timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_timer, "CTRL Socket Timer", 0, 100 * MSEC, ctx, bbl_ctrl_socket_job);

    LOG(NORMAL, "Opened control socket %s\n", ctx->ctrl_socket_path);
    return true;
}

bool
bbl_ctrl_socket_close (bbl_ctx_s *ctx) {
    if(ctx->ctrl_socket) {
        close(ctx->ctrl_socket);
        ctx->ctrl_socket = 0;
        unlink(ctx->ctrl_socket_path);
    }
    return true;
}