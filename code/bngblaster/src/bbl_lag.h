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

#define LAG_MEMBER_ACTIVE_MAX 16

typedef struct bbl_lag_
{
    uint8_t id;
    bbl_interface_s *interface;
    bbl_lag_config_s *config;

    uint8_t active_max;
    uint8_t active_count;
    bbl_lag_member_s *active_list[LAG_MEMBER_ACTIVE_MAX];

    CIRCLEQ_ENTRY(bbl_lag_) lag_qnode;
    CIRCLEQ_HEAD(lag_member_, bbl_lag_member_ ) lag_member_qhead; /* list of member interfaces */
} bbl_lag_s;

typedef struct bbl_lag_member_
{
    bbl_lag_s *lag;
    bbl_interface_s *interface;
    lacp_state_t lacp_state;

    bool primary;
    bool periodic_fast;

    struct timer_ *lacp_timer;
    uint8_t timeout;

    uint8_t     actor_system_id[ETH_ADDR_LEN];
    uint16_t    actor_system_priority;
    uint16_t    actor_key;
    uint16_t    actor_port_priority;
    uint16_t    actor_port_id;
    uint8_t     actor_state;

    uint8_t     partner_system_id[ETH_ADDR_LEN];
    uint16_t    partner_system_priority;
    uint16_t    partner_key;
    uint16_t    partner_port_priority;
    uint16_t    partner_port_id;
    uint8_t     partner_state;

    CIRCLEQ_ENTRY(bbl_lag_member_) lag_member_qnode;
    struct {
        uint32_t lacp_rx;
        uint32_t lacp_tx;
        uint32_t lacp_dropped;
        uint32_t lacp_transitions;
    } stats;
} bbl_lag_member_s;

bbl_lag_s *
bbl_lag_get(uint8_t id);

bool
bbl_lag_add();

bool
bbl_lag_interface_add(bbl_interface_s *interface, bbl_link_config_s *link_config);

void
bbl_lag_rx_lacp(bbl_interface_s *interface,
                bbl_ethernet_header_s *eth);

#endif