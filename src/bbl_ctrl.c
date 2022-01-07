/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
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

#include "bbl.h"
#include "bbl_ctrl.h"
#include "bbl_logging.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

#define BACKLOG 4
#define INPUT_BUFFER 1024

extern volatile bool g_teardown;
extern volatile bool g_teardown_request;

typedef ssize_t callback_function(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments);

static char *
string_or_na(char *string) {
    if(string) {
        return string;
    } else {
        return "N/A";
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
bbl_ctrl_multicast_traffic_start(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ctx->multicast_traffic = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

ssize_t
bbl_ctrl_multicast_traffic_stop(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ctx->multicast_traffic = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

ssize_t
bbl_ctrl_session_traffic_stats(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root = json_pack("{ss si s{si si}}",
                             "status", "ok",
                             "code", 200,
                             "session-traffic",
                             "total-flows", ctx->stats.session_traffic_flows,
                             "verified-flows", ctx->stats.session_traffic_flows_verified);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

ssize_t
bbl_ctrl_session_traffic(int fd, bbl_ctx_s *ctx, uint32_t session_id, bool status) {
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(ctx, session_id);
        if(session) {
            session->session_traffic = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < ctx->sessions; i++) {
            session = ctx->session_list[i];
            if(session) {
                session->session_traffic = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

ssize_t
bbl_ctrl_session_traffic_start(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_traffic(fd, ctx, session_id, true);
}

ssize_t
bbl_ctrl_session_traffic_stop(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_traffic(fd, ctx, session_id, false);
}

ssize_t
bbl_ctrl_setup_summary(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;

    json_t *root = json_pack("{ss si s{si si si si si s{sf sf sf sf sf} si}}",
        "status", "ok",
        "code", 200,
        "setup-summary",
            "total", ctx->sessions,
            "established", ctx->sessions_established,
            "outstanding", ctx->sessions_outstanding,
            "terminated", ctx->sessions_terminated,
            "setup-time", ctx->stats.setup_time,
            "setup-rate",
                "min", ctx->stats.cps_min,
                "avg", ctx->stats.cps_avg,
                "max", ctx->stats.cps_max,
                "sum", ctx->stats.cps_sum,
                "count", ctx->stats.cps_count,
            "flapped", ctx->sessions_flapped);
    if (root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }

    return result;
}

#define set_max(a, b) \
    ({__typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      if (_b) a = _a > _b ? _a : _b; })

#define set_min(a, b) \
    ({__typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      a = _a < _b ? _a : _b; })

ssize_t
bbl_ctrl_total_session_login_time(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    int64_t i;
    ssize_t result = 0;
    uint64_t tmp_seq;

    uint64_t ipcp_min = UINT64_MAX, ipcp_max = 0;
    uint64_t ipcpv6_min = UINT64_MAX, ipcpv6_max = 0;
    uint64_t dhcpv6pd_min = UINT64_MAX, dhcpv6pd_max = 0;

    uint64_t network_traffic_min = UINT64_MAX, network_traffic_max = 0;
    uint64_t network_trafficv6_min = UINT64_MAX, network_trafficv6_max = 0;
    uint64_t network_trafficv6pd_min = UINT64_MAX, network_trafficv6pd_max = 0;
    uint64_t access_traffic_min = UINT64_MAX, access_traffic_max = 0;
    uint64_t access_trafficv6_min = UINT64_MAX, access_trafficv6_max = 0;
    uint64_t access_trafficv6pd_min = UINT64_MAX, access_trafficv6pd_max = 0;

    uint64_t total_v4_min = UINT64_MAX, total_v4_max = 0;
    uint64_t total_v6_min = UINT64_MAX, total_v6_max = 0;
    uint64_t total_v6pd_min = UINT64_MAX, total_v6pd_max = 0;

    bbl_session_s *session;

    for(i = 0; i < (int64_t)ctx->sessions; ++i) {
        session = ctx->session_list[i];
        if (!session) { continue; }

        tmp_seq = session->access_ipv4_rx_first_seq;
        set_min(access_traffic_min, tmp_seq);
        set_max(access_traffic_max, tmp_seq);

        tmp_seq = session->access_ipv6_rx_first_seq;
        set_max(access_trafficv6_max, tmp_seq);
        set_min(access_trafficv6_min, tmp_seq);

        tmp_seq = session->access_ipv6pd_rx_first_seq;
        set_min(access_trafficv6pd_min, tmp_seq);
        set_max(access_trafficv6pd_max, tmp_seq);

        tmp_seq = session->network_ipv4_rx_first_seq;
        set_min(network_traffic_min, tmp_seq);
        set_max(network_traffic_max, tmp_seq);

        tmp_seq = session->network_ipv6_rx_first_seq;
        set_min(network_trafficv6_min, tmp_seq);
        set_max(network_trafficv6_max, tmp_seq);

        tmp_seq = session->network_ipv6pd_rx_first_seq;
        set_max(network_trafficv6pd_max, tmp_seq);
        set_min(network_trafficv6pd_min, tmp_seq);
    }

    json_t *root = json_pack("{ss si s{s{si si si si si si} s{si si si si si si si si si si si si} s{si, si, si}}}",
        "status", "ok",
        "code", 200,
        "session-login-time-summary",
            "control-plane",
                "ipcp-min", ipcp_min,
                "ipcp-max", ipcp_max,
                "ipv6cp-min", ipv6cp_min,
                "ipv6cp-max", ipv6cp_max,
                "dhcpv6pd-min", dhcpv6pd_min,
                "dhcpv6pd-max", dhcpv6pd_max,
            "data-plane",
                "access-traffic-min", access_traffic_min,
                "access-trafficv6-min", access_trafficv6_min,
                "access-trafficv6pd-min", access_trafficv6pd_min,
                "access-traffic-max", access_traffic_max,
                "access-trafficv6-max", access_trafficv6_max,
                "access-trafficv6pd-max", access_trafficv6pd_max,
                "network-traffic-min", network_traffic_min,
                "network-trafficv6-min", network_trafficv6_min,
                "network-trafficv6pd-min", network_trafficv6pd_min,
                "network-traffic-max", network_traffic_max,
                "network-trafficv6-max", network_trafficv6_max,
                "network-trafficv6pd-max", network_trafficv6pd_max,
            "total",
                "v4-min", total_v4_min,
                "v4-max", total_v4_max,
                "v6-min", total_v6_min,
                "v6-max", total_v6_max,
                "v6pd-min", total_v6pd_min,
                "v6pd-max", total_v6pd_max);


    if (root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }

    return result;
}

ssize_t
bbl_ctrl_igmp_join(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments) {
    bbl_session_s *session;
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
    session = bbl_session_get(ctx, session_id);
    if(session) {
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
        LOG(IGMP, "IGMP (ID: %u) join %s\n",
            session->session_id, format_ipv4_address(&group->group));
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_igmp_leave(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments) {

    bbl_session_s *session;
    const char *s;
    uint32_t group_address = 0;
    bbl_igmp_group_s *group = NULL;
    int i;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }
    if (json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }

    session = bbl_session_get(ctx, session_id);
    if(session) {
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
        LOG(IGMP, "IGMP (ID: %u) leave %s\n",
            session->session_id, format_ipv4_address(&group->group));
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_igmp_info(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root, *groups, *record, *sources;
    bbl_session_s *session = NULL;
    bbl_igmp_group_s *group = NULL;
    uint32_t delay = 0;
    uint32_t ms;

    struct timespec time_diff;
    int i, i2;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(ctx, session_id);
    if(session) {
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
                            ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
                            if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
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
                            ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
                            if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
                            delay = (time_diff.tv_sec * 1000) + ms;
                            json_object_set(record, "join-delay-ms", json_integer(delay));
                        }
                        break;
                    case IGMP_GROUP_JOINING:
                        json_object_set(record, "state", json_string("joining"));
                        if(group->first_mc_rx_time.tv_sec) {
                            timespec_sub(&time_diff, &group->first_mc_rx_time, &group->join_tx_time);
                            ms = time_diff.tv_nsec / 1000000; /* convert nanoseconds to milliseconds */
                            if(time_diff.tv_nsec % 1000000) ms++; /* simple roundup function */
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
            result = bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(groups);
        }
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_session_counters(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
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
bbl_ctrl_session_info(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root;
    json_t *session_json;
    bbl_session_s *session;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(ctx, session_id);
    if(session) {
        session_json = bbl_session_json(session);
        if(!session_json) {
            bbl_ctrl_status(fd, "error", 500, "internal error");
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

ssize_t
bbl_ctrl_interfaces(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root, *interfaces, *interface;
    int i;

    interfaces = json_array();
    for(i=0; i < ctx->interfaces.network_if_count; i++) {
        interface = json_pack("{ss si ss}",
                            "name", ctx->interfaces.network_if[i]->name,
                            "ifindex", ctx->interfaces.network_if[i]->ifindex,
                            "type", "network");
        json_array_append(interfaces, interface);
    }
    for(i=0; i < ctx->interfaces.access_if_count; i++) {
        interface = json_pack("{ss si ss}",
                            "name", ctx->interfaces.access_if[i]->name,
                            "ifindex", ctx->interfaces.access_if[i]->ifindex,
                            "type", "access");
        json_array_append(interfaces, interface);
    }
    for(i=0; i < ctx->interfaces.a10nsp_if_count; i++) {
        interface = json_pack("{ss si ss}",
                            "name", ctx->interfaces.a10nsp_if[i]->name,
                            "ifindex", ctx->interfaces.a10nsp_if[i]->ifindex,
                            "type", "a10nsp");
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
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(interfaces);
    }
    return result;
}

ssize_t
bbl_ctrl_session_terminate(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    bbl_session_s *session;
    if(session_id) {
        /* Terminate single matching session ... */
        session = bbl_session_get(ctx, session_id);
        if(session) {
            bbl_session_clear(ctx, session);
            return bbl_ctrl_status(fd, "ok", 200, "terminate session");
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Terminate all sessions ... */
        g_teardown = true;
        g_teardown_request = true;
        LOG(INFO, "Teardown request\n");
        return bbl_ctrl_status(fd, "ok", 200, "terminate all sessions");
    }
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
bbl_ctrl_session_ncp_close(bbl_session_s *session, bool ipcp) {
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

ssize_t
bbl_ctrl_session_ncp_open_close(int fd, bbl_ctx_s *ctx, uint32_t session_id, bool open, bool ipcp) {
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(ctx, session_id);
        if(session) {
            if(session->access_type == ACCESS_TYPE_PPPOE) {
                if(open) {
                    bbl_ctrl_session_ncp_open(session, ipcp);
                } else {
                    bbl_ctrl_session_ncp_close(session, ipcp);
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
        for(i = 0; i < ctx->sessions; i++) {
            session = ctx->session_list[i];
            if(session) {
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    if(open) {
                        bbl_ctrl_session_ncp_open(session, ipcp);
                    } else {
                        bbl_ctrl_session_ncp_close(session, ipcp);
                    }
                }
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

ssize_t
bbl_ctrl_session_ipcp_open(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, session_id, true, true);
}

ssize_t
bbl_ctrl_session_ipcp_close(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, session_id, false, true);
}

ssize_t
bbl_ctrl_session_ip6cp_open(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, session_id, true, false);
}

ssize_t
bbl_ctrl_session_ip6cp_close(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_session_ncp_open_close(fd, ctx, session_id, false, false);
}

ssize_t
bbl_ctrl_li_flows(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
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
            flow = json_pack("{ss si ss si ss ss ss si si si si si si si si si si si si}",
                                "source-address", format_ipv4_address(&li_flow->src_ipv4),
                                "source-port", li_flow->src_port,
                                "destination-address", format_ipv4_address(&li_flow->dst_ipv4),
                                "destination-port", li_flow->dst_port,
                                "direction", bbl_li_direction_string(li_flow->direction),
                                "packet-type", bbl_li_packet_type_string(li_flow->packet_type),
                                "sub-packet-type", bbl_li_sub_packet_type_string(li_flow->sub_packet_type),
                                "liid", li_flow->liid,
                                "bytes-rx", li_flow->bytes_rx,
                                "packets-rx", li_flow->packets_rx,
                                "packets-rx-ipv4", li_flow->packets_rx_ipv4,
                                "packets-rx-ipv4-tcp", li_flow->packets_rx_ipv4_tcp,
                                "packets-rx-ipv4-udp", li_flow->packets_rx_ipv4_udp,
                                "packets-rx-ipv4-host-internal", li_flow->packets_rx_ipv4_internal,
                                "packets-rx-ipv6", li_flow->packets_rx_ipv6,
                                "packets-rx-ipv6-tcp", li_flow->packets_rx_ipv6_tcp,
                                "packets-rx-ipv6-udp", li_flow->packets_rx_ipv6_udp,
                                "packets-rx-ipv6-host-internal", li_flow->packets_rx_ipv6_internal,
                                "packets-rx-ipv6-no-next-header", li_flow->packets_rx_ipv6_no_next_header);
            json_array_append(flows, flow);
        }
    }
    dict_itor_free(itor);
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "li-flows", flows);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(flows);
    }
    return result;
}

ssize_t
bbl_ctrl_l2tp_tunnels(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root, *tunnels, *tunnel;

    bbl_l2tp_server_t *l2tp_server = ctx->config.l2tp_server;
    bbl_l2tp_tunnel_t *l2tp_tunnel;

    tunnels = json_array();

    while(l2tp_server) {
        CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {

            tunnel = json_pack("{ss ss ss si si ss ss ss ss si si si si si si si}",
                                "state", l2tp_tunnel_state_string(l2tp_tunnel->state),
                                "server-name", l2tp_server->host_name,
                                "server-address", format_ipv4_address(&l2tp_server->ip),
                                "tunnel-id", l2tp_tunnel->tunnel_id,
                                "peer-tunnel-id", l2tp_tunnel->peer_tunnel_id,
                                "peer-name", string_or_na(l2tp_tunnel->peer_name),
                                "peer-address", format_ipv4_address(&l2tp_tunnel->peer_ip),
                                "peer-vendor", string_or_na(l2tp_tunnel->peer_vendor),
                                "secret", string_or_na(l2tp_server->secret),
                                "control-packets-rx", l2tp_tunnel->stats.control_rx,
                                "control-packets-rx-dup", l2tp_tunnel->stats.control_rx_dup,
                                "control-packets-rx-out-of-order", l2tp_tunnel->stats.control_rx_ooo,
                                "control-packets-tx", l2tp_tunnel->stats.control_tx,
                                "control-packets-tx-retry", l2tp_tunnel->stats.control_retry,
                                "data-packets-rx", l2tp_tunnel->stats.data_rx,
                                "data-packets-tx", l2tp_tunnel->stats.data_tx);
            json_array_append(tunnels, tunnel);
        }
        l2tp_server = l2tp_server->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "l2tp-tunnels", tunnels);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(tunnels);
    }
    return result;
}

json_t *
l2tp_session_json(bbl_l2tp_session_t *l2tp_session) {
    char *proxy_auth_response = NULL;

    if(l2tp_session->proxy_auth_response) {
        if(l2tp_session->proxy_auth_type == L2TP_PROXY_AUTH_TYPE_PAP) {
            proxy_auth_response = (char*)l2tp_session->proxy_auth_response;
        } else {
            proxy_auth_response = "0x...";
        }
    }

    return json_pack("{ss si si si si si ss ss ss ss ss si si ss ss si si si si}",
                     "state", l2tp_session_state_string(l2tp_session->state),
                     "tunnel-id", l2tp_session->key.tunnel_id,
                     "session-id", l2tp_session->key.session_id,
                     "peer-tunnel-id", l2tp_session->tunnel->peer_tunnel_id,
                     "peer-session-id", l2tp_session->peer_session_id,
                     "peer-proxy-auth-type", l2tp_session->proxy_auth_type,
                     "peer-proxy-auth-name", string_or_na(l2tp_session->proxy_auth_name),
                     "peer-proxy-auth-response", string_or_na(proxy_auth_response),
                     "peer-called-number", string_or_na(l2tp_session->peer_called_number),
                     "peer-calling-number", string_or_na(l2tp_session->peer_calling_number),
                     "peer-sub-address", string_or_na(l2tp_session->peer_sub_address),
                     "peer-tx-bps", l2tp_session->peer_tx_bps,
                     "peer-rx-bps", l2tp_session->peer_rx_bps,
                     "peer-ari", string_or_na(l2tp_session->peer_ari),
                     "peer-aci", string_or_na(l2tp_session->peer_aci),
                     "data-packets-rx", l2tp_session->stats.data_rx,
                     "data-packets-tx", l2tp_session->stats.data_tx,
                     "data-ipv4-packets-rx", l2tp_session->stats.data_ipv4_rx,
                     "data-ipv4-packets-tx", l2tp_session->stats.data_ipv4_tx);
}

ssize_t
bbl_ctrl_l2tp_sessions(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments) {
    ssize_t result = 0;
    json_t *root, *sessions;

    bbl_l2tp_server_t *l2tp_server = ctx->config.l2tp_server;
    bbl_l2tp_tunnel_t *l2tp_tunnel;
    bbl_l2tp_session_t *l2tp_session;
    l2tp_key_t l2tp_key = {0};
    void **search = NULL;

    int l2tp_tunnel_id = 0;
    int l2tp_session_id = 0;

    json_unpack(arguments, "{s:i}", "tunnel-id", &l2tp_tunnel_id);
    json_unpack(arguments, "{s:i}", "session-id", &l2tp_session_id);

    sessions = json_array();

    if(l2tp_tunnel_id && l2tp_session_id) {
        l2tp_key.tunnel_id = l2tp_tunnel_id;
        l2tp_key.session_id = l2tp_session_id;
        search = dict_search(ctx->l2tp_session_dict, &l2tp_key);
        if(search) {
            l2tp_session = *search;
            json_array_append(sessions, l2tp_session_json(l2tp_session));
        } else {
            result = bbl_ctrl_status(fd, "warning", 404, "session not found");
            json_decref(sessions);
            return result;
        }
    } else if (l2tp_tunnel_id) {
        l2tp_key.tunnel_id = l2tp_tunnel_id;
        search = dict_search(ctx->l2tp_session_dict, &l2tp_key);
        if(search) {
            l2tp_session = *search;
            l2tp_tunnel = l2tp_session->tunnel;
            CIRCLEQ_FOREACH(l2tp_session, &l2tp_tunnel->session_qhead, session_qnode) {
                if(!l2tp_session->key.session_id) continue; /* skip tunnel session */
                json_array_append(sessions, l2tp_session_json(l2tp_session));
            }
        } else {
            result = bbl_ctrl_status(fd, "warning", 404, "tunnel not found");
            json_decref(sessions);
            return result;
        }
    } else {
        while(l2tp_server) {
            CIRCLEQ_FOREACH(l2tp_tunnel, &l2tp_server->tunnel_qhead, tunnel_qnode) {
                CIRCLEQ_FOREACH(l2tp_session, &l2tp_tunnel->session_qhead, session_qnode) {
                    if(!l2tp_session->key.session_id) continue; /* skip tunnel session */
                    json_array_append(sessions, l2tp_session_json(l2tp_session));
                }
            }
            l2tp_server = l2tp_server->next;
        }
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "l2tp-sessions", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

ssize_t
bbl_ctrl_l2tp_csurq(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments) {
    json_t *sessions, *number;

    bbl_l2tp_tunnel_t *l2tp_tunnel;
    bbl_l2tp_session_t *l2tp_session;
    l2tp_key_t l2tp_key = {0};
    void **search = NULL;

    uint16_t l2tp_session_id = 0;
    int l2tp_tunnel_id = 0;
    int size, i;

    /* Unpack further arguments */
    if (json_unpack(arguments, "{s:i}", "tunnel-id", &l2tp_tunnel_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing tunnel-id");
    }
    l2tp_key.tunnel_id = l2tp_tunnel_id;
    search = dict_search(ctx->l2tp_session_dict, &l2tp_key);
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "tunnel not established");
        }
        sessions = json_object_get(arguments, "sessions");
        if (json_is_array(sessions)) {
            size = json_array_size(sessions);
            l2tp_tunnel->csurq_requests_len = size;
            l2tp_tunnel->csurq_requests = malloc(size * sizeof(uint16_t));
            for (i = 0; i < size; i++) {
                number = json_array_get(sessions, i);
                if(json_is_number(number)) {
                    l2tp_session_id = json_number_value(number);
                    l2tp_tunnel->csurq_requests[i] = l2tp_session_id;
                }
            }
            bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_CSURQ);
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "error", 400, "invalid request");
        }
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "tunnel not found");
    }
}


ssize_t
bbl_ctrl_l2tp_tunnel_terminate(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments) {
    bbl_l2tp_tunnel_t *l2tp_tunnel;
    bbl_l2tp_session_t *l2tp_session;
    l2tp_key_t l2tp_key = {0};
    void **search = NULL;

    int l2tp_tunnel_id = 0;
    int result_code;
    int error_code;
    char *error_message;

    /* Unpack further arguments */
    if (json_unpack(arguments, "{s:i}", "tunnel-id", &l2tp_tunnel_id) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing tunnel-id");
    }
    l2tp_key.tunnel_id = l2tp_tunnel_id;
    search = dict_search(ctx->l2tp_session_dict, &l2tp_key);
    if(search) {
        l2tp_session = *search;
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "tunnel not established");
        }
        bbl_l2tp_tunnel_update_state(l2tp_tunnel, BBL_L2TP_TUNNEL_SEND_STOPCCN);
        if (json_unpack(arguments, "{s:i}", "result-code", &result_code) != 0) {
            result_code = 1;
        }
        l2tp_tunnel->result_code = result_code;
        if (json_unpack(arguments, "{s:i}", "error-code", &error_code) != 0) {
            error_code = 0;
        }
        l2tp_tunnel->error_code = error_code;
        if (json_unpack(arguments, "{s:s}", "error-message", &error_message) != 0) {
            error_message = NULL;
        }
        l2tp_tunnel->error_message = error_message;
        bbl_l2tp_send(l2tp_tunnel, NULL, L2TP_MESSAGE_STOPCCN);
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "tunnel not found");
    }
}

ssize_t
bbl_ctrl_l2tp_session_terminate(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments) {
    bbl_session_s *session;
    bbl_l2tp_tunnel_t *l2tp_tunnel;
    bbl_l2tp_session_t *l2tp_session;

    int result_code;
    int error_code;
    char *error_message;
    int disconnect_code;
    int disconnect_protocol;
    int disconnect_direction;
    char* disconnect_message;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(ctx, session_id);
    if(session) {
        l2tp_session = session->l2tp_session;
        if(!l2tp_session) {
            return bbl_ctrl_status(fd, "error", 400, "no L2TP session");
        }
        l2tp_tunnel = l2tp_session->tunnel;
        if(l2tp_tunnel->state != BBL_L2TP_TUNNEL_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "tunnel not established");
        }
        if(l2tp_session->state != BBL_L2TP_SESSION_ESTABLISHED) {
            return bbl_ctrl_status(fd, "warning", 400, "session not established");
        }
        if (json_unpack(arguments, "{s:i}", "result-code", &result_code) != 0) {
            result_code = 2;
        }
        l2tp_session->result_code = result_code;
        if (json_unpack(arguments, "{s:i}", "error-code", &error_code) != 0) {
            error_code = 0;
        }
        l2tp_session->error_code = error_code;
        if (json_unpack(arguments, "{s:s}", "error-message", &error_message) != 0) {
            error_message = NULL;
        }
        l2tp_session->error_message = error_message;
        if (json_unpack(arguments, "{s:i}", "disconnect-code", &disconnect_code) != 0) {
            disconnect_code = 0;
        }
        l2tp_session->disconnect_code = disconnect_code;
        if (json_unpack(arguments, "{s:i}", "disconnect-protocol", &disconnect_protocol) != 0) {
            disconnect_protocol = 0;
        }
        l2tp_session->disconnect_protocol = disconnect_protocol;
        if (json_unpack(arguments, "{s:i}", "disconnect-direction", &disconnect_direction) != 0) {
            disconnect_direction = 0;
        }
        l2tp_session->disconnect_direction = disconnect_direction;
        if (json_unpack(arguments, "{s:s}", "disconnect-message", &disconnect_message) != 0) {
            disconnect_message = NULL;
        }
        l2tp_session->disconnect_message = disconnect_message;
        bbl_l2tp_send(l2tp_tunnel, l2tp_session, L2TP_MESSAGE_CDN);
        bbl_l2tp_session_delete(l2tp_session);
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_session_streams(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root;
    json_t *json_streams = NULL;
    json_t *json_stream = NULL;

    bbl_session_s *session;
    bbl_stream *stream;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(ctx, session_id);
    if(session) {
        stream = session->stream;

        json_streams = json_array();
        while(stream) {
            json_stream = bbl_stream_json(stream);
            json_array_append(json_streams, json_stream);
            stream = stream->next;
        }
        root = json_pack("{ss si s{si si si si si si si si si sf sf so*}}",
                        "status", "ok",
                        "code", 200,
                        "session-streams",
                        "session-id", session->session_id,
                        "rx-packets", session->stats.packets_rx,
                        "tx-packets", session->stats.packets_tx,
                        "rx-accounting-packets", session->stats.accounting_packets_rx,
                        "tx-accounting-packets", session->stats.accounting_packets_tx,
                        "rx-pps", session->stats.rate_packets_rx.avg,
                        "tx-pps", session->stats.rate_packets_tx.avg,
                        "rx-bps-l2", session->stats.rate_bytes_rx.avg * 8,
                        "tx-bps-l2", session->stats.rate_bytes_tx.avg * 8,
                        "rx-mbps-l2", (double)(session->stats.rate_bytes_rx.avg * 8) / 1000000.0,
                        "tx-mbps-l2", (double)(session->stats.rate_bytes_tx.avg * 8) / 1000000.0,
                        "streams", json_streams);

        if(root) {
            result = json_dumpfd(root, fd, 0);
            json_decref(root);
        } else {
            result = bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(json_streams);
        }
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

ssize_t
bbl_ctrl_stream_traffic(int fd, bbl_ctx_s *ctx, uint32_t session_id, bool status) {
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(ctx, session_id);
        if(session) {
            session->stream_traffic = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < ctx->sessions; i++) {
            session = ctx->session_list[i];
            if(session) {
                session->stream_traffic = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

ssize_t
bbl_ctrl_stream_traffic_start(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_stream_traffic(fd, ctx, session_id, true);
}

ssize_t
bbl_ctrl_stream_traffic_stop(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_stream_traffic(fd, ctx, session_id, false);
}

ssize_t
bbl_ctrl_sessions_pending(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {

    ssize_t result = 0;
    json_t *root, *json_session, *json_sessions;

    bbl_session_s *session;
    uint32_t i;

    json_sessions = json_array();

    /* Iterate over all sessions */
    for(i = 0; i < ctx->sessions; i++) {
        session = ctx->session_list[i];
        if(!session) continue;
        
        if(session->session_state != BBL_ESTABLISHED || 
           session->session_traffic_flows != session->session_traffic_flows_verified) {
            json_session = json_pack("{si ss si si}",
                                     "session-id", session->session_id,
                                     "session-state", session_state_string(session->session_state),
                                     "session-traffic-flows", session->session_traffic_flows,
                                     "session-traffic-flows-verified", session->session_traffic_flows_verified);
            json_array_append(json_sessions, json_session);
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

ssize_t
bbl_ctrl_cfm_cc_start_stop(int fd, bbl_ctx_s *ctx, uint32_t session_id, bool status) {
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(ctx, session_id);
        if(session) {
            session->cfm_cc = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < ctx->sessions; i++) {
            session = ctx->session_list[i];
            if(session) {
                session->cfm_cc = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

ssize_t
bbl_ctrl_cfm_cc_start(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_cfm_cc_start_stop(fd, ctx, session_id, true);
}

ssize_t
bbl_ctrl_cfm_cc_stop(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_cfm_cc_start_stop(fd, ctx, session_id, false);
}

ssize_t
bbl_ctrl_cfm_cc_rdi(int fd, bbl_ctx_s *ctx, uint32_t session_id, bool status) {
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(ctx, session_id);
        if(session) {
            session->cfm_rdi = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < ctx->sessions; i++) {
            session = ctx->session_list[i];
            if(session) {
                session->cfm_rdi = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

ssize_t
bbl_ctrl_cfm_cc_rdi_on(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_cfm_cc_rdi(fd, ctx, session_id, true);
}

ssize_t
bbl_ctrl_cfm_cc_rdi_off(int fd, bbl_ctx_s *ctx, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    return bbl_ctrl_cfm_cc_rdi(fd, ctx, session_id, false);
}

ssize_t
bbl_ctrl_stream_stats(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    ssize_t result = 0;
    json_t *root = json_pack("{ss si s{si si}}",
                             "status", "ok",
                             "code", 200,
                             "stream-stats",
                             "total-flows", ctx->stats.stream_traffic_flows,
                             "verified-flows", ctx->stats.stream_traffic_flows_verified);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

ssize_t
bbl_ctrl_stream_info(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments) {
    ssize_t result = 0;

    json_t *root;
    json_t *json_stream = NULL;

    bbl_stream *stream;
    void **search = NULL;

    int number = 0;
    uint64_t flow_id;

    /* Unpack further arguments */
    if (json_unpack(arguments, "{s:i}", "flow-id", &number) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing flow-id");
    }

    flow_id = number;
    search = dict_search(ctx->stream_flow_dict, &flow_id);
    if(search) {
        stream = *search;
        if(stream->thread.thread) {
            pthread_mutex_lock(&stream->thread.mutex);
        }
        json_stream = bbl_stream_json(stream);
        root = json_pack("{ss si so*}",
                         "status", "ok",
                         "code", 200,
                         "stream-info", json_stream);
        if(root) {
            result = json_dumpfd(root, fd, 0);
            json_decref(root);
        } else {
            result = bbl_ctrl_status(fd, "error", 500, "internal error");
            json_decref(json_stream);
        }
        if(stream->thread.thread) {
            pthread_mutex_unlock(&stream->thread.mutex);
        }
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "stream not found");
    }
}

ssize_t
bbl_ctrl_traffic(int fd, bbl_ctx_s *ctx, uint32_t session_id, bool status) {
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(ctx, session_id);
        if(session) {
            session->stream_traffic = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < ctx->sessions; i++) {
            session = ctx->session_list[i];
            if(session) {
                session->stream_traffic = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

ssize_t
bbl_ctrl_traffic_start(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    enable_disable_traffic(ctx, true);
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

ssize_t
bbl_ctrl_traffic_stop(int fd, bbl_ctx_s *ctx, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    enable_disable_traffic(ctx, false);
    return bbl_ctrl_status(fd, "ok", 200, NULL);
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
    {"session-traffic", bbl_ctrl_session_traffic_stats},
    {"session-traffic-enabled", bbl_ctrl_session_traffic_start},
    {"session-traffic-start", bbl_ctrl_session_traffic_start},
    {"session-traffic-disabled", bbl_ctrl_session_traffic_stop},
    {"session-traffic-stop", bbl_ctrl_session_traffic_stop},
    {"setup-summary", bbl_ctrl_setup_summary},
    {"session-login-time-summary", bbl_ctrl_total_session_login_time},
    {"multicast-traffic-start", bbl_ctrl_multicast_traffic_start},
    {"multicast-traffic-stop", bbl_ctrl_multicast_traffic_stop},
    {"igmp-join", bbl_ctrl_igmp_join},
    {"igmp-leave", bbl_ctrl_igmp_leave},
    {"igmp-info", bbl_ctrl_igmp_info},
    {"li-flows", bbl_ctrl_li_flows},
    {"l2tp-tunnels", bbl_ctrl_l2tp_tunnels},
    {"l2tp-sessions", bbl_ctrl_l2tp_sessions},
    {"l2tp-csurq", bbl_ctrl_l2tp_csurq},
    {"l2tp-tunnel-terminate", bbl_ctrl_l2tp_tunnel_terminate},
    {"l2tp-session-terminate", bbl_ctrl_l2tp_session_terminate},
    {"session-streams", bbl_ctrl_session_streams},
    {"stream-traffic-enabled", bbl_ctrl_stream_traffic_start},
    {"stream-traffic-start", bbl_ctrl_stream_traffic_start},
    {"stream-traffic-disabled", bbl_ctrl_stream_traffic_stop},
    {"stream-traffic-stop", bbl_ctrl_stream_traffic_stop},
    {"stream-info", bbl_ctrl_stream_info},
    {"stream-stats", bbl_ctrl_stream_stats},
    {"sessions-pending", bbl_ctrl_sessions_pending},
    {"cfm-cc-start", bbl_ctrl_cfm_cc_start},
    {"cfm-cc-stop", bbl_ctrl_cfm_cc_stop},
    {"cfm-cc-rdi-on", bbl_ctrl_cfm_cc_rdi_on},
    {"cfm-cc-rdi-off", bbl_ctrl_cfm_cc_rdi_off},
    {"traffic-start", bbl_ctrl_traffic_start},
    {"traffic-stop", bbl_ctrl_traffic_stop},
    {NULL, NULL},
};

void
bbl_ctrl_socket_job (timer_s *timer) {
    bbl_ctx_s *ctx = timer->data;
    char buf[INPUT_BUFFER];
    ssize_t len;
    int fd;
    size_t i;
    json_error_t error;
    json_t *root = NULL;
    json_t* arguments = NULL;
    json_t* value = NULL;
    const char *command = NULL;
    uint32_t session_id = 0;

    vlan_session_key_t key = {0};
    bbl_session_s *session;
    void **search;

    while(true) {
        fd = accept(ctx->ctrl_socket, 0, 0);
        if(fd < 0) {
            /* The accept function fails with error EAGAIN or EWOULDBLOCK if
             * there are no pending connections present on the queue.*/
            if(errno == EAGAIN) {
                return;
            }
        } else {
            /* New connection */
            memset(buf, 0x0, sizeof(buf));
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
                            value = json_object_get(arguments, "session-id");
                            if (value) {
                                if(json_is_number(value)) {
                                    session_id = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid session-id");
                                    goto CLOSE;
                                }
                            } else {
                                /* Deprecated!
                                 * For backward compatibility with version 0.4.X, we still
                                 * support per session commands using VLAN index instead of
                                 * new session-id. */
                                value = json_object_get(arguments, "ifindex");
                                if (value) {
                                    if(json_is_number(value)) {
                                        key.ifindex = json_number_value(value);
                                    } else {
                                        bbl_ctrl_status(fd, "error", 400, "invalid ifindex");
                                        goto CLOSE;
                                    }
                                } else {
                                    /* Use first interface as default. */
                                    if(ctx->interfaces.access_if[0]) {
                                        key.ifindex = ctx->interfaces.access_if[0]->ifindex;
                                    }
                                }
                                value = json_object_get(arguments, "outer-vlan");
                                if (value) {
                                    if(json_is_number(value)) {
                                        key.outer_vlan_id = json_number_value(value);
                                    } else {
                                        bbl_ctrl_status(fd, "error", 400, "invalid outer-vlan");
                                        goto CLOSE;
                                    }
                                }
                                value = json_object_get(arguments, "inner-vlan");
                                if (value) {
                                    if(json_is_number(value)) {
                                        key.inner_vlan_id = json_number_value(value);
                                    } else {
                                        bbl_ctrl_status(fd, "error", 400, "invalid inner-vlan");
                                        goto CLOSE;
                                    }
                                }
                                if(key.outer_vlan_id) {
                                    search = dict_search(ctx->vlan_session_dict, &key);
                                    if(search) {
                                        session = *search;
                                        session_id = session->session_id;
                                    } else {
                                        bbl_ctrl_status(fd, "warning", 404, "session not found");
                                        goto CLOSE;
                                    }
                                }
                            }
                        }
                        for(i = 0; true; i++) {
                            if(actions[i].name == NULL) {
                                bbl_ctrl_status(fd, "error", 400, "unknown command");
                                break;
                            } else if(strcmp(actions[i].name, command) == 0) {
                                actions[i].fn(fd, ctx, session_id, arguments);
                                break;
                            }
                        }
                    }
                }
            }
CLOSE:
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

    timer_add_periodic(&ctx->timer_root, &ctx->ctrl_socket_timer, "CTRL Socket Timer", 0, 100 * MSEC, ctx, &bbl_ctrl_socket_job);

    LOG(INFO, "Opened control socket %s\n", ctx->ctrl_socket_path);
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
