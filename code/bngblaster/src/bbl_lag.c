/*
 * BNG Blaster (BBL) - LAG Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

uint16_t g_lag_port_id = 1;

/**
 * bbl_lag_get
 * 
 * Get interface by name. 
 *
 * @param id LAG identifier
 * @return the LAG group or NULL
 */
bbl_lag_s *
bbl_lag_get(uint8_t id)
{
    bbl_lag_s *lag;
    CIRCLEQ_FOREACH(lag, &g_ctx->lag_qhead, lag_qnode) {
        if(lag->id == id) {
            return lag;
        }
    }
    return NULL;
}

/**
 * bbl_lag_add
 *
 * @brief This function will add and initialize
 * all LAG groups defined in the configuration.
 *
 * @return true if all LAG groups are
 * added and initialised successfully
 */
bool
bbl_lag_add()
{
    bbl_lag_config_s *lag_config = g_ctx->config.lag_config;
    bbl_lag_s *lag;

    char name[sizeof("lag255")];

    while(lag_config) {
        snprintf(name, sizeof(name), "lag%u", lag->id);
        CIRCLEQ_FOREACH(lag, &g_ctx->lag_qhead, lag_qnode) {
            if(lag->id == lag_config->id) {
                LOG(ERROR, "Failed to add %s (duplicate)\n", name);
                return false;
            }
        }
        lag = calloc(1, sizeof(bbl_lag_s));
        lag->id = lag_config->id;
        lag->interface = strdup(name);
        lag->config = lag_config;
        
        CIRCLEQ_INIT(&lag->lag_interface_qhead);
        CIRCLEQ_INSERT_TAIL(&g_ctx->lag_qhead, lag, lag_qnode);

        lag_config = lag_config->next;
    }
    return true;
}


void
bbl_lag_lacp_tx_job(timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    bbl_lag_member_s *member = interface->lag;

    interface->send_requests |= BBL_SEND_LACP;
    member->timeout++;
    if(member->timeout > 3) {
        member->state = INTERFACE_DOWN;
        interface->state = INTERFACE_DOWN;
    }
}

bool
bbl_lag_interface_add(bbl_interface_s *interface, bbl_link_config_s *link_config)
{
    bbl_lag_s *lag;
    bbl_lag_member_s *member;
    time_t timer_sec;

    if(link_config->lag_id) {
        lag = bbl_lag_get(link_config->lag_id);
        if(!lag) {
            LOG(ERROR, "Failed to add link %s (LAG %u not defined)\n", 
                link_config->interface, link_config->lag_id);
            return false;
        }
        member = calloc(1, sizeof(bbl_lag_member_s));
        member->lag = lag;
        if(lag->config->lacp_enable) {
            member->state = INTERFACE_DOWN;
            interface->state = INTERFACE_DOWN;
            memcpy(member->actor_system_id, lag->config->lacp_system_id, ETH_ADDR_LEN);
            member->actor_system_priority = lag->config->lacp_system_priority;
            member->actor_key = lag->id;
            member->actor_port_priority = interface->config->lacp_priority;
            member->actor_port_id = g_lag_port_id++;
            member->actor_state = LACP_STATE_FLAG_ACTIVE|LACP_STATE_FLAG_IN_SYNC|LACP_STATE_FLAG_AGGREGATION|LACP_STATE_FLAG_DEFAULTED;
            if(lag->config->lacp_timeout_short) {
                timer_sec = 1;
                member->actor_state |= LACP_STATE_FLAG_SHORT_TIMEOUT;
            } else {
                timer_sec = 30;
            }
            timer_add_periodic(&g_ctx->timer_root, &member->lacp_timer, "LACP",
                               timer_sec, 0, interface, &bbl_lag_lacp_tx_job);
        } else {
            member->state = INTERFACE_UP;
        }

        interface->lag = member;
        CIRCLEQ_INSERT_TAIL(&lag->lag_interface_qhead, interface, interface_lag_qnode);
    }
    return true;
}

void
bbl_lag_rx_lacp(bbl_interface_s *interface,
                bbl_ethernet_header_s *eth)
{
    bbl_lag_member_s *member = interface->lag;
    bbl_lacp_s *lacp = (bbl_lacp_s*)eth->next; 

    if(member) {
        memcpy(member->partner_system_id, lacp->actor_system_id, ETH_ADDR_LEN);
        member->partner_system_priority = lacp->actor_system_priority;
        member->partner_key = lacp->actor_key;
        member->partner_port_priority = lacp->actor_port_priority;
        member->partner_port_id = lacp->actor_port_id;
        member->partner_state = lacp->actor_state;
        member->stats.lacp_rx++;
    }
    return;
}