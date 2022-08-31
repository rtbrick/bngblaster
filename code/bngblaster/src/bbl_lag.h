/*
 * BNG Blaster (BBL) - LAG Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_LAG_H__
#define __BBL_LAG_H__

typedef struct bbl_lag_
{
    uint8_t id;
    char *interface;

    bbl_lag_config_s *config;
    CIRCLEQ_HEAD(lag_interface_, bbl_interface_ ) lag_interface_qhead; /* list of interfaces */
    CIRCLEQ_ENTRY(bbl_lag_) lag_qnode;

    interface_state_t state;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
        uint64_t bytes_tx;
        uint64_t bytes_rx;
        bbl_rate_s rate_packets_tx;
        bbl_rate_s rate_packets_rx;
        bbl_rate_s rate_bytes_tx;
        bbl_rate_s rate_bytes_rx;
    } stats;

    struct timer_ *lacp_timer;

    struct timer_ *tx_job;
    struct timer_ *rate_job;
} bbl_lag_s;

bbl_lag_s *
bbl_lag_get(uint8_t id);

bool
bbl_lag_add();

bool
bbl_lag_interface_add(bbl_interface_s *interface, bbl_link_config_s *link_config);

#endif