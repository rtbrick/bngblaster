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
    interface_state_t state;

    uint8_t id;
    char *interface;

    bbl_lag_config_s *config;
    CIRCLEQ_HEAD(lag_interface_, bbl_interface_ ) lag_interface_qhead; /* list of interfaces */
    CIRCLEQ_ENTRY(bbl_lag_) lag_qnode;
} bbl_lag_s;

typedef struct bbl_lag_member_
{
    bbl_lag_s *lag;

    interface_state_t state;

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