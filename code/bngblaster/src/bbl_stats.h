/*
 * BNG Blaster (BBL) - Stats
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_STATS_H__
#define __BBL_STATS_H__

typedef struct bbl_rate_
{
    uint64_t diff_value[BBL_AVG_SAMPLES];
    uint32_t cursor;
    uint64_t last_value;
    uint64_t avg;
    uint64_t avg_max;
} bbl_rate_s;

typedef struct bbl_stats_ 
{
    /* Multicast */

    uint32_t zapping_join_count;
    uint32_t zapping_leave_count;

    uint32_t min_join_delay; /* IGMP join delay (min) */
    uint32_t avg_join_delay; /* IGMP join delay (avg) */
    uint32_t max_join_delay; /* IGMP join delay (max) */

    uint32_t join_delay_violations;
    uint32_t join_delay_violations_125ms;
    uint32_t join_delay_violations_250ms;
    uint32_t join_delay_violations_500ms;
    uint32_t join_delay_violations_1s;
    uint32_t join_delay_violations_2s;

    uint32_t min_leave_delay; /* IGMP leave delay (min) */
    uint32_t avg_leave_delay; /* IGMP leave delay (avg) */
    uint32_t max_leave_delay; /* IGMP leave delay (max) */

    uint32_t mc_old_rx_after_first_new;
    uint32_t mc_not_received;

    /* Session Traffic */

    uint64_t min_down_ipv4_rx_first_seq;
    uint64_t avg_down_ipv4_rx_first_seq;
    uint64_t max_down_ipv4_rx_first_seq;
    uint64_t violations_down_ipv4_1s;
    uint64_t violations_down_ipv4_2s;
    uint64_t violations_down_ipv4_3s;
    uint32_t sessions_down_ipv4_rx;

    float min_down_ipv4_rx_seconds;
    float avg_down_ipv4_rx_seconds;
    float max_down_ipv4_rx_seconds;

    uint64_t min_up_ipv4_rx_first_seq;
    uint64_t avg_up_ipv4_rx_first_seq;
    uint64_t max_up_ipv4_rx_first_seq;
    uint64_t violations_up_ipv4_1s;
    uint64_t violations_up_ipv4_2s;
    uint64_t violations_up_ipv4_3s;
    uint32_t sessions_up_ipv4_rx;

    float min_up_ipv4_rx_seconds;
    float avg_up_ipv4_rx_seconds;
    float max_up_ipv4_rx_seconds;

    uint64_t min_down_ipv6_rx_first_seq;
    uint64_t avg_down_ipv6_rx_first_seq;
    uint64_t max_down_ipv6_rx_first_seq;
    uint64_t violations_down_ipv6_1s;
    uint64_t violations_down_ipv6_2s;
    uint64_t violations_down_ipv6_3s;
    uint32_t sessions_down_ipv6_rx;

    float min_down_ipv6_rx_seconds;
    float avg_down_ipv6_rx_seconds;
    float max_down_ipv6_rx_seconds;

    uint64_t min_up_ipv6_rx_first_seq;
    uint64_t avg_up_ipv6_rx_first_seq;
    uint64_t max_up_ipv6_rx_first_seq;
    uint64_t violations_up_ipv6_1s;
    uint64_t violations_up_ipv6_2s;
    uint64_t violations_up_ipv6_3s;
    uint32_t sessions_up_ipv6_rx;

    float min_up_ipv6_rx_seconds;
    float avg_up_ipv6_rx_seconds;
    float max_up_ipv6_rx_seconds;

    uint64_t min_down_ipv6pd_rx_first_seq;
    uint64_t avg_down_ipv6pd_rx_first_seq;
    uint64_t max_down_ipv6pd_rx_first_seq;
    uint64_t violations_down_ipv6pd_1s;
    uint64_t violations_down_ipv6pd_2s;
    uint64_t violations_down_ipv6pd_3s;
    uint32_t sessions_down_ipv6pd_rx;

    float min_down_ipv6pd_rx_seconds;
    float avg_down_ipv6pd_rx_seconds;
    float max_down_ipv6pd_rx_seconds;

    uint64_t min_up_ipv6pd_rx_first_seq;
    uint64_t avg_up_ipv6pd_rx_first_seq;
    uint64_t max_up_ipv6pd_rx_first_seq;
    uint64_t violations_up_ipv6pd_1s;
    uint64_t violations_up_ipv6pd_2s;
    uint64_t violations_up_ipv6pd_3s;
    uint32_t sessions_up_ipv6pd_rx;

    float min_up_ipv6pd_rx_seconds;
    float avg_up_ipv6pd_rx_seconds;
    float max_up_ipv6pd_rx_seconds;

    /* Stream */

    uint64_t min_stream_loss;
    uint64_t max_stream_loss;
    uint64_t min_stream_rx_first_seq;
    uint64_t max_stream_rx_first_seq;
    uint64_t min_stream_delay_us;
    uint64_t max_stream_delay_us;

    /* L2TP */

    uint32_t l2tp_control_tx;
    uint32_t l2tp_control_rx;
    uint32_t l2tp_control_rx_dup;
    uint32_t l2tp_control_rx_ooo;
    uint32_t l2tp_control_retry;
    uint64_t l2tp_data_tx;
    uint64_t l2tp_data_rx;

    /* LI */
    uint64_t li_rx;

} bbl_stats_s;

typedef struct bbl_interface_stats_ {
    uint64_t packets;
    uint64_t bytes;
    uint64_t unknown;
    uint64_t protocol_errors;
    uint64_t io_errors;
    uint64_t to_long;
    uint64_t no_buffer;
    uint64_t polled;
} bbl_interface_stats_s;

void 
bbl_compute_avg_rate(bbl_rate_s *rate, uint64_t current_value);

void 
bbl_stats_update_cps();

void 
bbl_stats_generate_multicast(bbl_stats_s *stats, bool reset);

void
bbl_stats_generate(bbl_stats_s *stats);

void
bbl_stats_stdout(bbl_stats_s *stats);

void 
bbl_stats_json(bbl_stats_s *stats);

#endif
