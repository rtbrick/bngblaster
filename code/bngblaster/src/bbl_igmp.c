/*
 * BNG Blaster (BBL) - IGMP Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

struct keyval_ igmp_msg_names[] = {
    { IGMP_TYPE_QUERY,      "general-query" },
    { IGMP_TYPE_REPORT_V1,  "v1-report" },
    { IGMP_TYPE_REPORT_V2,  "v2-report" },
    { IGMP_TYPE_LEAVE,      "v2-leave" },
    { IGMP_TYPE_REPORT_V3,  "v3-report" },
    { 0, NULL}
};

void
bbl_igmp_rx(bbl_session_s *session, bbl_ipv4_s *ipv4)
{
    bbl_igmp_s *igmp = (bbl_igmp_s*)ipv4->next;
    bbl_igmp_group_s *group = NULL;
    int i;
    bool send = false;

#if 0
    LOG(IGMP, "IGMPv%d (ID: %u) type %s received\n",
        igmp->version,
        session->session_id,
        val2key(igmp_msg_names, igmp->type));
#endif

    if(igmp->type == IGMP_TYPE_QUERY) {

        if(igmp->robustness) {
            session->igmp_robustness = igmp->robustness;
        }

        if(igmp->group) {
            /* Group Specific Query */
            for(i=0; i < IGMP_MAX_GROUPS; i++) {
                group = &session->igmp_groups[i];
                if(group->group == igmp->group &&
                   group->state == IGMP_GROUP_ACTIVE) {
                    group->send = true;
                    send = true;
                }
            }
        } else {
            /* General Query */
            for(i=0; i < IGMP_MAX_GROUPS; i++) {
                group = &session->igmp_groups[i];
                if(group->state == IGMP_GROUP_ACTIVE) {
                    group->send = true;
                    send = true;
                }
            }
        }

        if(send) {
            session->send_requests |= BBL_SEND_IGMP;
            bbl_session_tx_qnode_insert(session);
        }
    }
}

/* Control Socket Commands */

int
bbl_igmp_ctrl_join(int fd, uint32_t session_id, json_t *arguments)
{
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
    if(json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }
    if(json_unpack(arguments, "{s:s}", "source1", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source1)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source1 address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "source2", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source2)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source2 address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "source3", &s) == 0) {
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
                if(session->igmp_groups[i].group == group_address) {
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
bbl_igmp_ctrl_join_iter(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
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
    if(json_unpack(arguments, "{s:s}", "group", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group address");
        }
    } else {
        return bbl_ctrl_status(fd, "error", 400, "missing group address");
    }
    if(json_unpack(arguments, "{s:d}", "group-iter", &s) == 0) {
        if(!inet_pton(AF_INET, s, &group_iter)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid group-iter");
        }
        group_iter = be32toh(group_iter);
    }
    json_unpack(arguments, "{s:i}", "group-count", &group_count);
    if(group_count < 1) group_count = 1;

    /* Unpack source address arguments */
    if(json_unpack(arguments, "{s:s}", "source1", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source1)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source1 address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "source2", &s) == 0) {
        if(!inet_pton(AF_INET, s, &source2)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid source2 address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "source3", &s) == 0) {
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
bbl_igmp_ctrl_leave(int fd, uint32_t session_id, json_t *arguments)
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
    if(json_unpack(arguments, "{s:s}", "group", &s) == 0) {
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
            if(session->igmp_groups[i].group == group_address) {
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
bbl_igmp_ctrl_leave_all(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
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
bbl_igmp_ctrl_info(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
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
                record = json_pack("{ss so sI sI}",
                                   "group", format_ipv4_address(&group->group),
                                   "sources", sources,
                                   "packets", group->packets,
                                   "loss", group->loss);

                switch(group->state) {
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
bbl_igmp_ctrl_zapping_start(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    g_ctx->zapping = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_igmp_ctrl_zapping_stop(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    g_ctx->zapping = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_igmp_ctrl_zapping_stats(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
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