/*
 * BNG Blaster (BBL) - Stats
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_STATS_H__
#define __BBL_STATS_H__

typedef struct bbl_stats_ {
    uint32_t min_join_delay; // IGMP join delay
    uint32_t avg_join_delay; // IGMP join delay
    uint32_t max_join_delay; // IGMP join delay

    uint32_t min_leave_delay; // IGMP leave delay
    uint32_t avg_leave_delay; // IGMP leave delay
    uint32_t max_leave_delay; // IGMP leave delay

    uint32_t mc_old_rx_after_first_new;
    uint32_t mc_not_received;

    uint64_t min_access_ipv4_rx_first_seq;
    uint64_t max_access_ipv4_rx_first_seq;
    uint64_t min_network_ipv4_rx_first_seq;
    uint64_t max_network_ipv4_rx_first_seq;
    uint64_t min_access_ipv6_rx_first_seq;
    uint64_t max_access_ipv6_rx_first_seq;
    uint64_t min_network_ipv6_rx_first_seq;
    uint64_t max_network_ipv6_rx_first_seq;
    uint64_t min_access_ipv6pd_rx_first_seq;
    uint64_t max_access_ipv6pd_rx_first_seq;
    uint64_t min_network_ipv6pd_rx_first_seq;
    uint64_t max_network_ipv6pd_rx_first_seq;

    uint32_t sessions_access_ipv4_rx;
    uint32_t sessions_network_ipv4_rx;
    uint32_t sessions_access_ipv6_rx;
    uint32_t sessions_network_ipv6_rx;
    uint32_t sessions_access_ipv6pd_rx;
    uint32_t sessions_network_ipv6pd_rx;
} bbl_stats_t;

void bbl_compute_avg_rate (bbl_rate_s *rate, uint64_t current_value);
void bbl_stats_update_cps (bbl_ctx_s *ctx);
void bbl_stats_generate(bbl_ctx_s *ctx, bbl_stats_t *stats);
void bbl_stats_stdout(bbl_ctx_s *ctx, bbl_stats_t *stats);
void bbl_stats_json(bbl_ctx_s *ctx, bbl_stats_t *stats);
void bbl_compute_interface_rate_job(timer_s *timer);

#endif
