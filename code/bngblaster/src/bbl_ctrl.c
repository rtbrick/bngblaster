/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
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
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

#define BACKLOG 4

extern volatile bool g_teardown;
extern volatile bool g_teardown_request;
extern volatile bool g_monkey;

typedef int callback_function(int fd, uint32_t session_id, json_t* arguments);

static char *
string_or_na(char *string)
{
    if(string) {
        return string;
    } else {
        return "N/A";
    }
}

int
bbl_ctrl_status(int fd, const char *status, uint32_t code, const char *message)
{
    int result = 0;
    json_t *root = json_pack("{sssiss*}", "status", status, "code", code, "message", message);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

int
bbl_ctrl_multicast_traffic_start(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    g_ctx->multicast_traffic = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_multicast_traffic_stop(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    g_ctx->multicast_traffic = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_session_traffic_stats(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
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

int
bbl_ctrl_session_traffic(int fd, uint32_t session_id, bool status)
{
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            session->session_traffic.active = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                session->session_traffic.active = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_ctrl_session_traffic_start(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_session_traffic(fd, session_id, true);
}

int
bbl_ctrl_session_traffic_stop(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_session_traffic(fd, session_id, false);
}

int
bbl_ctrl_igmp_join(int fd, uint32_t session_id, json_t* arguments) {
    bbl_session_s *session;
    const char *s;
    uint32_t group_address = 0;
    uint32_t source1 = 0;
    uint32_t source2 = 0;
    uint32_t source3 = 0;
    bbl_igmp_group_s *group = NULL;
    int i;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }
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
    session = bbl_session_get(session_id);
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
         /* Join group... */
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

int
bbl_ctrl_igmp_join_iter(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments)
{
    bbl_session_s *session;
    const char *s;
    uint32_t group_address = 0;
    uint32_t group_iter = 1;
    int group_count = 0;
    bbl_igmp_group_s *group = NULL;
    uint32_t source1 = 0;
    uint32_t source2 = 0;
    uint32_t source3 = 0;
    uint32_t i, i2;
    uint32_t join_count;

    /* Unpack group arguments */
    if (json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }
    if (json_unpack(arguments, "{s:d}", "group-iter", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_iter)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group-iter");
        }
        group_iter = be32toh(group_iter);
    }
    json_unpack(arguments, "{s:i}", "group-count", &group_count);
    if(group_count < 1) group_count = 1;

    /* Unpack source address arguments */
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

    while(group_count) {
        /* Iterate over all sessions */
        join_count = 0;
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                /* Search for free slot ... */
                for(i2=0; i2 < IGMP_MAX_GROUPS; i2++) {
                    group = &session->igmp_groups[i2];
                    if(group->zapping) {
                        continue;
                    }
                    if(group->group == group_address && 
                       group->state != IGMP_GROUP_IDLE) {
                        /* Group already exists. */
                        group_address = htobe32(be32toh(group_address) + group_iter);
                        break;
                    }
                    if(group->state != IGMP_GROUP_IDLE) {
                        continue;
                    }
                    /* Join group. */
                    memset(group, 0x0, sizeof(bbl_igmp_group_s));
                    group->group = group_address;
                    if(source1) group->source[0] = source1;
                    if(source2) group->source[1] = source2;
                    if(source3) group->source[2] = source3;
                    group->state = IGMP_GROUP_JOINING;
                    group->robustness_count = session->igmp_robustness;
                    group->send = true;
                    LOG(IGMP, "IGMP (ID: %u) join %s\n",
                        session->session_id, format_ipv4_address(&group->group));
                    session->send_requests |= BBL_SEND_IGMP;

                    join_count++;
                    if(--group_count == 0) {
                        return bbl_ctrl_status(fd, "ok", 200, NULL);
                    };
                    /* Get next group address. */
                    group_address = htobe32(be32toh(group_address) + group_iter);
                    break;
                }
            }
        }
        /* Prevent infinity loops! */
        if(!join_count) break;
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_igmp_leave(int fd, uint32_t session_id, json_t* arguments)
{
    bbl_session_s *session;
    const char *s;
    uint32_t group_address = 0;
    bbl_igmp_group_s *group = NULL;
    int i;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }
    /* Unpack further arguments */
    if (json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }

    session = bbl_session_get(session_id);
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

int
bbl_ctrl_igmp_leave_all(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    bbl_session_s *session;
    bbl_igmp_group_s *group = NULL;
    uint32_t i, i2;

    /* Iterate over all sessions */
    for(i = 0; i < g_ctx->sessions; i++) {
        session = &g_ctx->session_list[i];
        if(session) {
            /* Search for group ... */
            for(i2=0; i2 < IGMP_MAX_GROUPS; i2++) {
                group = &session->igmp_groups[i2];
                if(group->zapping || group->state <= IGMP_GROUP_LEAVING) {
                    continue;
                }
                group->state = IGMP_GROUP_LEAVING;
                group->robustness_count = session->igmp_robustness;
                group->send = true;
                group->leave_tx_time.tv_sec = 0;
                group->leave_tx_time.tv_nsec = 0;
                group->last_mc_rx_time.tv_sec = 0;
                group->last_mc_rx_time.tv_nsec = 0;
                LOG(IGMP, "IGMP (ID: %u) leave %s\n",
                    session->session_id, format_ipv4_address(&group->group));
                session->send_requests |= BBL_SEND_IGMP;
                bbl_session_tx_qnode_insert(session);
            }
        }
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_igmp_info(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    int result = 0;
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

    session = bbl_session_get(session_id);
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

int
bbl_ctrl_zapping_start(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    g_ctx->zapping = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_zapping_stop(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    g_ctx->zapping = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_zapping_stats(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root;

    bbl_stats_s stats = {0};
    int reset = 0;
    
    json_unpack(arguments, "{s:b}", "reset", &reset);
    bbl_stats_generate_multicast(&stats, reset);

    root = json_pack("{ss si s{si si si si si si si si si si si si si si si si si}}",
                     "status", "ok",
                     "code", 200,
                     "zapping-stats",
                     "join-delay-ms-min", stats.min_join_delay,
                     "join-delay-ms-avg", stats.avg_join_delay,
                     "join-delay-ms-max", stats.max_join_delay,
                     "join-delay-violations", stats.join_delay_violations,
                     "join-delay-violations-threshold", g_ctx->config.igmp_max_join_delay,
                     "join-delay-violations-125ms", stats.join_delay_violations_125ms,
                     "join-delay-violations-250ms", stats.join_delay_violations_250ms,
                     "join-delay-violations-500ms", stats.join_delay_violations_500ms,
                     "join-delay-violations-1s", stats.join_delay_violations_1s,
                     "join-delay-violations-2s", stats.join_delay_violations_2s,
                     "join-count", stats.zapping_join_count,
                     "leave-delay-ms-min", stats.min_leave_delay,
                     "leave-delay-ms-avg", stats.avg_leave_delay,
                     "leave-delay-ms-max", stats.max_leave_delay,
                     "leave-count", stats.zapping_leave_count,
                     "multicast-packets-overlap", stats.mc_old_rx_after_first_new,
                     "multicast-not-received", stats.mc_not_received);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

int
bbl_ctrl_session_counters(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root = json_pack("{ss si s{si si si si si si si si si si si si si si sf sf sf sf si si si si}}",
                             "status", "ok",
                             "code", 200,
                             "session-counters",
                             "sessions", g_ctx->config.sessions,
                             "sessions-pppoe", g_ctx->sessions_pppoe,
                             "sessions-ipoe", g_ctx->sessions_ipoe,
                             "sessions-established", g_ctx->sessions_established,
                             "sessions-established-max", g_ctx->sessions_established_max,
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
bbl_ctrl_session_info(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
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

int
bbl_ctrl_session_start(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    bbl_session_s *session;

    if(g_teardown) {
        return bbl_ctrl_status(fd, "error", 405, "teardown");
    }

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(session_id);
    if(session) {
        if(session->session_state == BBL_TERMINATED && 
           session->reconnect_delay == 0) {
            g_ctx->sessions_flapped++;
            session->stats.flapped++;
            session->session_state = BBL_IDLE;
            bbl_session_reset(session);
            if(g_ctx->sessions_terminated) {
                g_ctx->sessions_terminated--;
            }
        } else if(session->session_state != BBL_IDLE || 
           CIRCLEQ_NEXT(session, session_idle_qnode) || 
           CIRCLEQ_PREV(session, session_idle_qnode)) {
           return bbl_ctrl_status(fd, "error", 405, "wrong session state");
        }
        CIRCLEQ_INSERT_TAIL(&g_ctx->sessions_idle_qhead, session, session_idle_qnode);
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "session not found");
    }
}

static json_t *
bbl_ctrl_network_interface_json(bbl_network_interface_s *interface)
{
    return json_pack("{ss si ss si si si si si si si si si si si si si si si si si si si si si si si si si si si si si si}",
                     "name", interface->name,
                     "ifindex", interface->interface->ifindex,
                     "type", "network",
                     "tx-packets", interface->stats.packets_tx,
                     "tx-bytes", interface->stats.bytes_tx, 
                     "tx-pps", interface->stats.rate_packets_tx.avg,
                     "tx-kbps", interface->stats.rate_bytes_tx.avg * 8 / 1000,
                     "rx-packets", interface->stats.packets_rx, 
                     "rx-bytes", interface->stats.bytes_rx,
                     "rx-pps", interface->stats.rate_packets_rx.avg,
                     "rx-kbps", interface->stats.rate_bytes_rx.avg * 8 / 1000,
                     "tx-packets-multicast", interface->stats.mc_tx,
                     "tx-pps-multicast", interface->stats.rate_mc_tx.avg,
                     "tx-packets-session-ipv4", interface->stats.session_ipv4_tx,
                     "tx-pps-session-ipv4", interface->stats.rate_session_ipv4_tx.avg,
                     "rx-packets-session-ipv4", interface->stats.session_ipv4_rx,
                     "rx-pps-session-ipv4", interface->stats.rate_session_ipv4_rx.avg,
                     "loss-packets-session-ipv4", interface->stats.session_ipv4_loss,
                     "tx-packets-session-ipv6", interface->stats.session_ipv6_tx,
                     "tx-pps-session-ipv6", interface->stats.rate_session_ipv6_tx.avg,
                     "rx-packets-session-ipv6", interface->stats.session_ipv6_rx,
                     "rx-pps-session-ipv6", interface->stats.rate_session_ipv6_rx.avg,
                     "loss-packets-session-ipv6", interface->stats.session_ipv6_loss,
                     "tx-packets-session-ipv6pd", interface->stats.session_ipv6pd_tx,
                     "tx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_tx.avg,
                     "rx-packets-session-ipv6pd", interface->stats.session_ipv6pd_rx,
                     "rx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_rx.avg,
                     "loss-packets-session-ipv6pd", interface->stats.session_ipv6pd_loss,
                     "tx-packets-streams", interface->stats.stream_tx,
                     "tx-pps-streams", interface->stats.rate_stream_tx.avg,
                     "rx-packets-streams", interface->stats.stream_rx,
                     "rx-pps-streams", interface->stats.rate_stream_rx.avg,
                     "loss-packets-streams", interface->stats.stream_loss
                    );
}

static json_t *
bbl_ctrl_access_interface_json(bbl_access_interface_s *interface)
{
    return json_pack("{ss si ss si si si si si si si si si si si si si si si si si si si si si si si si si si si si si si si}",
                     "name", interface->interface->name,
                     "ifindex", interface->interface->ifindex,
                     "type", "access",
                     "tx-packets", interface->stats.packets_tx,
                     "tx-bytes", interface->stats.bytes_tx, 
                     "tx-pps", interface->stats.rate_packets_tx.avg,
                     "tx-kbps", interface->stats.rate_bytes_tx.avg * 8 / 1000,
                     "rx-packets", interface->stats.packets_rx, 
                     "rx-bytes", interface->stats.bytes_rx,
                     "rx-pps", interface->stats.rate_packets_rx.avg,
                     "rx-kbps", interface->stats.rate_bytes_rx.avg * 8 / 1000,
                     "rx-packets-multicast", interface->stats.mc_rx,
                     "rx-pps-multicast", interface->stats.rate_mc_rx.avg,
                     "loss-packets-multicast", interface->stats.mc_loss,
                     "tx-packets-session-ipv4", interface->stats.session_ipv4_tx,
                     "tx-pps-session-ipv4", interface->stats.rate_session_ipv4_tx.avg,
                     "rx-packets-session-ipv4", interface->stats.session_ipv4_rx,
                     "rx-pps-session-ipv4", interface->stats.rate_session_ipv4_rx.avg,
                     "loss-packets-session-ipv4", interface->stats.session_ipv4_loss,
                     "tx-packets-session-ipv6", interface->stats.session_ipv6_tx,
                     "tx-pps-session-ipv6", interface->stats.rate_session_ipv6_tx.avg,
                     "rx-packets-session-ipv6", interface->stats.session_ipv6_rx,
                     "rx-pps-session-ipv6", interface->stats.rate_session_ipv6_rx.avg,
                     "loss-packets-session-ipv6", interface->stats.session_ipv6_loss,
                     "tx-packets-session-ipv6pd", interface->stats.session_ipv6pd_tx,
                     "tx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_tx.avg,
                     "rx-packets-session-ipv6pd", interface->stats.session_ipv6pd_rx,
                     "rx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_rx.avg,
                     "loss-packets-session-ipv6pd", interface->stats.session_ipv6pd_loss,
                     "tx-packets-streams", interface->stats.stream_tx,
                     "tx-pps-streams", interface->stats.rate_stream_tx.avg,
                     "rx-packets-streams", interface->stats.stream_rx,
                     "rx-pps-streams", interface->stats.rate_stream_rx.avg,
                     "loss-packets-streams", interface->stats.stream_loss
                    );
}

static json_t *
bbl_ctrl_a10nsp_interface_json(bbl_a10nsp_interface_s *interface)
{
    return json_pack("{ss si ss si si si si si si si si si si si si si si si si si si si si si si si si si si si si}",
                     "name", interface->interface->name,
                     "ifindex", interface->interface->ifindex,
                     "type", "a10nsp",
                     "tx-packets", interface->stats.packets_tx,
                     "tx-bytes", interface->stats.bytes_tx, 
                     "tx-pps", interface->stats.rate_packets_tx.avg,
                     "tx-kbps", interface->stats.rate_bytes_tx.avg * 8 / 1000,
                     "rx-packets", interface->stats.packets_rx, 
                     "rx-bytes", interface->stats.bytes_rx,
                     "rx-pps", interface->stats.rate_packets_rx.avg,
                     "rx-kbps", interface->stats.rate_bytes_rx.avg * 8 / 1000,
                     "tx-packets-session-ipv4", interface->stats.session_ipv4_tx,
                     "tx-pps-session-ipv4", interface->stats.rate_session_ipv4_tx.avg,
                     "rx-packets-session-ipv4", interface->stats.session_ipv4_rx,
                     "rx-pps-session-ipv4", interface->stats.rate_session_ipv4_rx.avg,
                     "loss-packets-session-ipv4", interface->stats.session_ipv4_loss,
                     "tx-packets-session-ipv6", interface->stats.session_ipv6_tx,
                     "tx-pps-session-ipv6", interface->stats.rate_session_ipv6_tx.avg,
                     "rx-packets-session-ipv6", interface->stats.session_ipv6_rx,
                     "rx-pps-session-ipv6", interface->stats.rate_session_ipv6_rx.avg,
                     "loss-packets-session-ipv6", interface->stats.session_ipv6_loss,
                     "tx-packets-session-ipv6pd", interface->stats.session_ipv6pd_tx,
                     "tx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_tx.avg,
                     "rx-packets-session-ipv6pd", interface->stats.session_ipv6pd_rx,
                     "rx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_rx.avg,
                     "loss-packets-session-ipv6pd", interface->stats.session_ipv6pd_loss,
                     "tx-packets-streams", interface->stats.stream_tx,
                     "tx-pps-streams", interface->stats.rate_stream_tx.avg,
                     "rx-packets-streams", interface->stats.stream_rx,
                     "rx-pps-streams", interface->stats.rate_stream_rx.avg,
                     "loss-packets-streams", interface->stats.stream_loss
                    );
}

int
bbl_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *interfaces;

    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;

    interfaces = json_array();
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            json_array_append(interfaces, bbl_ctrl_network_interface_json(network_interface));
            network_interface = network_interface->next;
        }
        if(interface->access) {
            json_array_append(interfaces, bbl_ctrl_access_interface_json(interface->access));
        } else if(interface->a10nsp) {
            json_array_append(interfaces, bbl_ctrl_a10nsp_interface_json(interface->a10nsp));
        }
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

int
bbl_ctrl_session_terminate(int fd, uint32_t session_id, json_t* arguments)
{
    bbl_session_s *session;
    int reconnect_delay = 0;

    if(session_id) {
        /* Terminate single matching session ... */
        session = bbl_session_get(session_id);
        if(session) {
            json_unpack(arguments, "{s:i}", "reconnect-delay", &session->reconnect_delay);
            if(reconnect_delay > 0) {
                session->reconnect_delay = reconnect_delay;
            }
            bbl_session_clear(session);
            return bbl_ctrl_status(fd, "ok", 200, "terminate session");
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Terminate all sessions ... */
        g_teardown = true;
        g_teardown_request = true;
        LOG_NOARG(INFO, "Teardown request\n");
        return bbl_ctrl_status(fd, "ok", 200, "terminate all sessions");
    }
}

int
bbl_ctrl_session_ncp_open_close(int fd, uint32_t session_id, bool open, bool ipcp) {
    bbl_session_s *session;
    uint32_t i;
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
            if(session) {
                if(session->access_type == ACCESS_TYPE_PPPOE) {
                    if(open) {
                        bbl_session_ncp_open(session, ipcp);
                    } else {
                        bbl_session_ncp_close(session, ipcp);
                    }
                }
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_ctrl_session_ipcp_open(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_session_ncp_open_close(fd, session_id, true, true);
}

int
bbl_ctrl_session_ipcp_close(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_session_ncp_open_close(fd, session_id, false, true);
}

int
bbl_ctrl_session_ip6cp_open(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_session_ncp_open_close(fd, session_id, true, false);
}

int
bbl_ctrl_session_ip6cp_close(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_session_ncp_open_close(fd, session_id, false, false);
}

int
bbl_ctrl_li_flows(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *flows, *flow;
    bbl_li_flow_t *li_flow;
    struct dict_itor *itor;

    flows = json_array();
    itor = dict_itor_new(g_ctx->li_flow_dict);
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

int
bbl_ctrl_l2tp_tunnels(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *tunnels, *tunnel;

    bbl_l2tp_server_s *l2tp_server = g_ctx->config.l2tp_server;
    bbl_l2tp_tunnel_s *l2tp_tunnel;

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
l2tp_session_json(bbl_l2tp_session_s *l2tp_session)
{
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

int
bbl_ctrl_l2tp_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments)
{
    int result = 0;
    json_t *root, *sessions;

    bbl_l2tp_server_s *l2tp_server = g_ctx->config.l2tp_server;
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;
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
        search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
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
        search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
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

int
bbl_ctrl_l2tp_csurq(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments)
{
    json_t *sessions, *number;

    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;
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
    search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
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

int
bbl_ctrl_l2tp_tunnel_terminate(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments)
{
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;
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
    search = dict_search(g_ctx->l2tp_session_dict, &l2tp_key);
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

int
bbl_ctrl_l2tp_session_terminate(int fd, uint32_t session_id, json_t* arguments)
{
    bbl_session_s *session;
    bbl_l2tp_tunnel_s *l2tp_tunnel;
    bbl_l2tp_session_s *l2tp_session;

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

    session = bbl_session_get(session_id);
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

int
bbl_ctrl_session_streams(int fd, uint32_t session_id, json_t* arguments __attribute__((unused))) {
    int result = 0;
    json_t *root;
    json_t *json_streams = NULL;
    json_t *json_stream = NULL;

    bbl_session_s *session;
    bbl_stream_s *stream;

    if(session_id == 0) {
        /* session-id is mandatory */
        return bbl_ctrl_status(fd, "error", 400, "missing session-id");
    }

    session = bbl_session_get(session_id);
    if(session) {
        stream = session->streams.head;

        json_streams = json_array();
        while(stream) {
            json_stream = bbl_stream_json(stream);
            json_array_append(json_streams, json_stream);
            stream = stream->session_next;
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

static int
bbl_ctrl_stream_traffic_start_stop(int fd, uint32_t session_id, bool status)
{
    bbl_session_s *session;
    uint32_t i;

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            session->streams.active = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                session->streams.active = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_ctrl_stream_traffic_start(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_stream_traffic_start_stop(fd, session_id, true);
}

int
bbl_ctrl_stream_traffic_stop(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_stream_traffic_start_stop(fd, session_id, false);
}

int
bbl_ctrl_stream_reset(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    bbl_stream_s *stream;
    struct dict_itor *itor;
    
    g_ctx->stats.stream_traffic_flows_verified = 0;

    /* Iterate over all traffic streams */
    itor = dict_itor_new(g_ctx->stream_flow_dict);
    dict_itor_first(itor);
    for (; dict_itor_valid(itor); dict_itor_next(itor)) {
        stream = (bbl_stream_s*)*dict_itor_datum(itor);
        if(!stream) {
            continue;
        }
        bbl_stream_reset(stream);
    }
    dict_itor_free(itor);
    return bbl_ctrl_status(fd, "ok", 200, NULL);    
}

int
bbl_ctrl_sessions_pending(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
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

int
bbl_ctrl_cfm_cc_start_stop(int fd, uint32_t session_id, bool status)
{
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            session->cfm_cc = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                session->cfm_cc = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_ctrl_cfm_cc_start(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_cfm_cc_start_stop(fd, session_id, true);
}

int
bbl_ctrl_cfm_cc_stop(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_cfm_cc_start_stop(fd, session_id, false);
}

int
bbl_ctrl_cfm_cc_rdi(int fd, uint32_t session_id, bool status)
{
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            session->cfm_rdi = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                session->cfm_rdi = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_ctrl_cfm_cc_rdi_on(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_cfm_cc_rdi(fd, session_id, true);
}

int
bbl_ctrl_cfm_cc_rdi_off(int fd, uint32_t session_id, json_t* arguments __attribute__((unused)))
{
    return bbl_ctrl_cfm_cc_rdi(fd, session_id, false);
}

int
bbl_ctrl_stream_stats(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused))) {
    int result = 0;
    json_t *root = json_pack("{ss si s{si si}}",
                             "status", "ok",
                             "code", 200,
                             "stream-stats",
                             "total-flows", g_ctx->stats.stream_traffic_flows,
                             "verified-flows", g_ctx->stats.stream_traffic_flows_verified);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

int
bbl_ctrl_stream_info(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments)
{
    int result = 0;

    json_t *root;
    json_t *json_stream = NULL;

    bbl_stream_s *stream;
    void **search = NULL;

    int number = 0;
    uint64_t flow_id;

    /* Unpack further arguments */
    if (json_unpack(arguments, "{s:i}", "flow-id", &number) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing flow-id");
    }

    flow_id = number;
    search = dict_search(g_ctx->stream_flow_dict, &flow_id);
    if(search) {
        stream = *search;
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
        return result;
    } else {
        return bbl_ctrl_status(fd, "warning", 404, "stream not found");
    }
}

int
bbl_ctrl_stream_summary(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    int result = 0;

    json_t *root = json_pack("{ss si so*}",
        "status", "ok",
        "code", 200,
        "stream-summary", 
        bbl_stream_summary_json());

    result = json_dumpfd(root, fd, 0);
    json_decref(root);
    return result;
}

int
bbl_ctrl_traffic_start(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    enable_disable_traffic(true);
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_traffic_stop(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    enable_disable_traffic(false);
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bgp_ctrl_monkey_start(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    if(!g_monkey) {
        LOG_NOARG(INFO, "Start monkey\n");
    }
    g_monkey = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bgp_ctrl_monkey_stop(int fd, uint32_t session_id __attribute__((unused)), json_t* arguments __attribute__((unused)))
{
    if(g_monkey) {
        LOG_NOARG(INFO, "Stop monkey\n");
    }
    g_monkey = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

struct action {
    char *name;
    callback_function *fn;
    bool thread_safe;
};

struct action actions[] = {
    {"interfaces", bbl_ctrl_interfaces, true},
    {"terminate", bbl_ctrl_session_terminate, false},
    {"session-counters", bbl_ctrl_session_counters, true},
    {"session-info", bbl_ctrl_session_info, true},
    {"session-start", bbl_ctrl_session_start, true},
    {"session-traffic", bbl_ctrl_session_traffic_stats, true},
    {"session-traffic-enabled", bbl_ctrl_session_traffic_start, false},
    {"session-traffic-start", bbl_ctrl_session_traffic_start, false},
    {"session-traffic-disabled", bbl_ctrl_session_traffic_stop, false},
    {"session-traffic-stop", bbl_ctrl_session_traffic_stop, false},
    {"session-streams", bbl_ctrl_session_streams, true},
    {"sessions-pending", bbl_ctrl_sessions_pending, true},
    {"stream-traffic-enabled", bbl_ctrl_stream_traffic_start, false},
    {"stream-traffic-start", bbl_ctrl_stream_traffic_start, false},
    {"stream-traffic-disabled", bbl_ctrl_stream_traffic_stop, false},
    {"stream-traffic-stop", bbl_ctrl_stream_traffic_stop, false},
    {"stream-info", bbl_ctrl_stream_info, true},
    {"stream-summary", bbl_ctrl_stream_summary, true},
    {"stream-stats", bbl_ctrl_stream_stats, true},
    {"stream-reset", bbl_ctrl_stream_reset, false},
    {"multicast-traffic-start", bbl_ctrl_multicast_traffic_start, false},
    {"multicast-traffic-stop", bbl_ctrl_multicast_traffic_stop, false},
    {"igmp-join", bbl_ctrl_igmp_join, false},
    {"igmp-join-iter", bbl_ctrl_igmp_join_iter, false},
    {"igmp-leave", bbl_ctrl_igmp_leave, false},
    {"igmp-leave-all", bbl_ctrl_igmp_leave_all, false},
    {"igmp-info", bbl_ctrl_igmp_info, true},
    {"zapping-start", bbl_ctrl_zapping_start, true},
    {"zapping-stop", bbl_ctrl_zapping_stop, false},
    {"zapping-stats", bbl_ctrl_zapping_stats, true},
    {"li-flows", bbl_ctrl_li_flows, true},
    {"l2tp-tunnels", bbl_ctrl_l2tp_tunnels, true},
    {"l2tp-sessions", bbl_ctrl_l2tp_sessions, true},
    {"l2tp-csurq", bbl_ctrl_l2tp_csurq, false},
    {"l2tp-tunnel-terminate", bbl_ctrl_l2tp_tunnel_terminate, false},
    {"l2tp-session-terminate", bbl_ctrl_l2tp_session_terminate, false},
    {"ipcp-open", bbl_ctrl_session_ipcp_open, false},
    {"ipcp-close", bbl_ctrl_session_ipcp_close, false},
    {"ip6cp-open", bbl_ctrl_session_ip6cp_open, false},
    {"ip6cp-close", bbl_ctrl_session_ip6cp_close, false},
    {"cfm-cc-start", bbl_ctrl_cfm_cc_start, false},
    {"cfm-cc-stop", bbl_ctrl_cfm_cc_stop, false},
    {"cfm-cc-rdi-on", bbl_ctrl_cfm_cc_rdi_on, false},
    {"cfm-cc-rdi-off", bbl_ctrl_cfm_cc_rdi_off, false},
    {"traffic-start", bbl_ctrl_traffic_start, false},
    {"traffic-stop", bbl_ctrl_traffic_stop, false},
    {"isis-adjacencies", isis_ctrl_adjacencies, true},
    {"isis-database", isis_ctrl_database, true},
    {"isis-load-mrt", isis_ctrl_load_mrt, false},
    {"isis-lsp-update", isis_ctrl_lsp_update, false},
    {"isis-teardown", isis_ctrl_teardown, false},
    {"bgp-sessions", bgp_ctrl_sessions, true},
    {"bgp-disconnect", bgp_ctrl_disconnect, false},
    {"bgp-teardown", bgp_ctrl_teardown, true},
    {"bgp-raw-update-list", bgp_ctrl_raw_update_list, true},
    {"bgp-raw-update", bgp_ctrl_raw_update, false},
    {"monkey-start", bgp_ctrl_monkey_start, false},
    {"monkey-stop", bgp_ctrl_monkey_stop, false},
    {NULL, NULL, false},
};

static void
bbl_ctrl_socket_main(bbl_ctrl_thread_s *ctrl)
{
    if(ctrl->main.fd) {
        pthread_mutex_lock(&ctrl->mutex);
        actions[ctrl->main.action].fn(ctrl->main.fd, ctrl->main.session_id, (json_t*)ctrl->main.arguments);
        ctrl->main.action = 0;
        ctrl->main.fd = 0;
        ctrl->main.session_id = 0;
        ctrl->main.arguments = NULL;
        pthread_cond_signal(&ctrl->cond);
        pthread_mutex_unlock(&ctrl->mutex);
    }
}

void
bbl_ctrl_socket_main_job(timer_s *timer)
{
    bbl_ctrl_socket_main(timer->data);
}

void *
bbl_ctrl_socket_thread(void *thread_data)
{
    bbl_ctrl_thread_s *ctrl = thread_data;

    size_t i;
    size_t flags = JSON_DISABLE_EOF_CHECK;
    json_error_t error;
    json_t *root = NULL;
    json_t* arguments = NULL;
    json_t* value = NULL;
    const char *command = NULL;
    uint32_t session_id = 0;

    bbl_access_interface_s *access_interface;

    vlan_session_key_t key = {0};
    bbl_session_s *session;
    void **search;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 1 * MSEC;

    /* ToDo: Add connection manager!
     * This is just a temporary workaround! Finally we need
     * to create a connection manager. */
    static int fd = 0;

    ctrl->active = true;
    while(ctrl->active) {
        fd = accept(ctrl->socket, 0, 0);
        if(fd > 0) {
            /* New connection */
            root = json_loadfd(fd, flags, &error);
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
                command = NULL;
                arguments = NULL;
                session_id = 0;
                key.ifindex = 0;
                key.inner_vlan_id = 0;
                key.outer_vlan_id = 0;
                if(json_unpack(root, "{s:s, s?o}", "command", &command, "arguments", &arguments) != 0) {
                    LOG_NOARG(DEBUG, "Invalid command via ctrl socket\n");
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
                                access_interface = bbl_access_interface_get(NULL);
                                if(access_interface) {
                                    key.ifindex = access_interface->interface->ifindex;
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
                                search = dict_search(g_ctx->vlan_session_dict, &key);
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
                            if(actions[i].thread_safe) {
                                actions[i].fn(fd, session_id, arguments);
                            } else {
                                pthread_mutex_lock(&ctrl->mutex);
                                ctrl->main.fd = fd;
                                ctrl->main.action = i;
                                ctrl->main.session_id = session_id;
                                ctrl->main.arguments = (void*)arguments;
                                pthread_cond_wait(&ctrl->cond, &ctrl->mutex);
                                pthread_mutex_unlock(&ctrl->mutex);
                            }
                            break;
                        }
                    }
                }
            }
CLOSE:
            if(root) {
                json_decref(root);
                root = NULL;
            }
            shutdown(fd, SHUT_WR);
        }
        nanosleep(&sleep, &rem);
        if(fd > 0) {
            close(fd);
        }
    }
    return NULL;
}

bool
bbl_ctrl_socket_init()
{
    bbl_ctrl_thread_s *ctrl;
    struct sockaddr_un addr = {0};

    if(!g_ctx->ctrl_socket_path) {
        return true;
    }

    ctrl = calloc(1, sizeof(bbl_ctrl_thread_s));
    if(!ctrl) {
        fprintf(stderr, "Error: Failed to init ctrl socket memory\n");
        return false;
    }
    g_ctx->ctrl_thread = ctrl;

    ctrl->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if(ctrl->socket < 0) {
        fprintf(stderr, "Error: Failed to create ctrl socket\n");
        return false;
    }
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_ctx->ctrl_socket_path, sizeof(addr.sun_path)-1);
    unlink(g_ctx->ctrl_socket_path);
    if(bind(ctrl->socket, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
        fprintf(stderr, "Error: Failed to bind ctrl socket %s (error %d)\n", g_ctx->ctrl_socket_path, errno);
        return false;
    }
    if(listen(ctrl->socket, BACKLOG) != 0) {
        fprintf(stderr, "Error: Failed to listen on ctrl socket %s (error %d)\n", g_ctx->ctrl_socket_path, errno);
        return false;
    }

    /* Change socket to non-blocking */
    fcntl(ctrl->socket, F_SETFL, O_NONBLOCK);

    /* Create ctrl thread */
    if(pthread_mutex_init(&ctrl->mutex, NULL) != 0) {
        LOG_NOARG(ERROR, "Failed to init ctrl mutex\n");
        return false;
    }
    if(pthread_cond_init(&ctrl->cond, NULL) != 0) {
        LOG_NOARG(ERROR, "Failed to init ctrl condition\n");
        return false;
    }
    if(pthread_create(&ctrl->thread, NULL, bbl_ctrl_socket_thread, (void *)ctrl) != 0) {
        LOG_NOARG(ERROR, "Failed to create ctrl thread\n");
        return false;
    }

    /* Start ctrl main job */
    timer_add_periodic(&g_ctx->timer_root, &ctrl->main.timer, "CTRL Socket Main Timer", 0, 1000 * MSEC, ctrl, &bbl_ctrl_socket_main_job);

    LOG(INFO, "Opened control socket %s\n", g_ctx->ctrl_socket_path);
    return true;
}

bool
bbl_ctrl_socket_close()
{
    bbl_ctrl_thread_s *ctrl;
    if(g_ctx->ctrl_thread) {
        ctrl = g_ctx->ctrl_thread;
        if(ctrl->active) {
            ctrl->active = false;
            bbl_ctrl_socket_main(ctrl);
            pthread_join(ctrl->thread, NULL);
            pthread_mutex_destroy(&ctrl->mutex);
            pthread_cond_destroy(&ctrl->cond);
        }
        if(ctrl->socket) {
            close(ctrl->socket);
        }
        unlink(g_ctx->ctrl_socket_path);
        free(g_ctx->ctrl_thread);
        g_ctx->ctrl_thread = NULL;
    }
    return true;
}