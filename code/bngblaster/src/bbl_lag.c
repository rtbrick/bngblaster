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

bbl_lag_s *
bbl_lag_get_by_name(char *interface)
{
    bbl_lag_s *lag;
    CIRCLEQ_FOREACH(lag, &g_ctx->lag_qhead, lag_qnode) {
        if(strcmp(lag->interface->name, interface) == 0) {
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
    bbl_lag_config_s *config = g_ctx->config.lag_config;
    bbl_interface_s *interface;
    bbl_lag_s *lag;

    while(config) {
        lag = calloc(1, sizeof(bbl_lag_s));
        if(!lag) return false;
        lag->id = config->id;
        lag->config = config;

        interface = calloc(1, sizeof(bbl_interface_s));
        if(!interface) return false;
        lag->interface = interface;
        interface->name = config->interface;
        interface->type = LAG_INTERFACE;
        interface->state = INTERFACE_DOWN;
        interface->ifindex = lag->id;
        interface->pcap_index = g_ctx->pcap.index++;
        interface->lag = lag;
        memcpy(interface->mac, config->mac, ETH_ADDR_LEN);

        CIRCLEQ_INIT(&lag->lag_member_qhead);
        CIRCLEQ_INSERT_TAIL(&g_ctx->lag_qhead, lag, lag_qnode);
        CIRCLEQ_INSERT_TAIL(&g_ctx->interface_qhead, interface, interface_qnode);

        LOG(LAG, "LAG (%s) New lag-interface created\n", interface->name);
        config = config->next;
    }
    return true;
}

void
bbl_lag_lacp_job(timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    bbl_lag_member_s *member = interface->lag_member;

    interface->send_requests |= BBL_SEND_LACP;
    member->timeout++;
    if(member->timeout > 3) {
        interface->state = INTERFACE_DOWN;
        if(!(member->actor_state & LACP_STATE_FLAG_EXPIRED)) {
            member->actor_state |= LACP_STATE_FLAG_EXPIRED;
            LOG(LAG, "LAG (%s) LACP expired on interface %s\n", 
                member->lag->interface->name, interface->name);
        }
        if(member->timeout > 6) {
            if(!(member->actor_state & LACP_STATE_FLAG_DEFAULTED)) {
                member->actor_state |= LACP_STATE_FLAG_DEFAULTED;
            }
        }
    }
}

bool
bbl_lag_interface_add(bbl_interface_s *interface, bbl_link_config_s *link_config)
{
    bbl_lag_s *lag;
    bbl_lag_member_s *member;
    time_t timer_sec;

    if(link_config->lag_interface) {
        lag = bbl_lag_get_by_name(link_config->lag_interface);
        if(!lag) {
            LOG(ERROR, "Failed to add link %s to lag-interface %s (not found)\n", 
                link_config->interface, link_config->lag_interface);
            return false;
        }
        if(link_config->tx_threads) {
            LOG(ERROR, "Failed to add link %s to lag-interface %s (TX threads not allowed for LAG interfaces)\n", 
                link_config->interface, link_config->lag_interface);
            return false;
        }
        member = calloc(1, sizeof(bbl_lag_member_s));
        member->lag = lag;
        member->interface = interface;

        interface->type = LAG_MEMBER_INTERFACE;
        interface->lag = lag;
        interface->lag_member = member;
        memcpy(interface->mac, lag->interface->mac, ETH_ADDR_LEN);
        if(lag->config->lacp_enable) {
            member->lacp_state = LACP_DEFAULTED;
            interface->state = INTERFACE_DOWN;
            memcpy(member->actor_system_id, lag->config->lacp_system_id, ETH_ADDR_LEN);
            member->actor_system_priority = lag->config->lacp_system_priority;
            member->actor_key = lag->id;
            member->actor_port_priority = interface->config->lacp_priority;
            member->actor_port_id = g_lag_port_id++;
            member->actor_state = LACP_STATE_FLAG_ACTIVE|LACP_STATE_FLAG_IN_SYNC|LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_AGGREGATION|LACP_STATE_FLAG_DEFAULTED;
            if(lag->config->lacp_timeout_short) {
                timer_sec = 1;
                member->actor_state |= LACP_STATE_FLAG_SHORT_TIMEOUT;
            } else {
                timer_sec = 30;
            }
            timer_add_periodic(&g_ctx->timer_root, &member->lacp_timer, "LACP",
                               timer_sec, 0, interface, &bbl_lag_lacp_job);
        } else {
            member->lacp_state = LACP_DISABLED;
        }
        CIRCLEQ_INSERT_TAIL(&lag->lag_member_qhead, member, lag_member_qnode);
        LOG(LAG, "LAG (%s) Interface %s added\n", lag->interface->name, interface->name);
    }
    return true;
}

static void
bbl_lag_select(bbl_lag_s *lag)
{
    bbl_lag_member_s *member;
    lag->active_count = 0;

    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        member->primary = false;
        if(member->partner_state & (LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING)) {
            member->actor_state |= (LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
            member->interface->state = INTERFACE_UP;
            lag->active_list[lag->active_count++] = member;
            if(lag->active_count == 1) {
                member->primary = true;
                LOG(LAG, "LAG (%s) Interface %s set to UP (primary)\n", member->lag->interface->name, member->interface->name);

            } else {
                LOG(LAG, "LAG (%s) Interface %s set to UP\n", member->lag->interface->name, member->interface->name);

            }
        } else {
            member->interface->state = INTERFACE_DOWN;
        }
    }
    if(lag->active_count) {
        lag->interface->state = INTERFACE_UP;
    } else {
        lag->interface->state = INTERFACE_DOWN;
    }
}

void
bbl_lag_rx_lacp(bbl_interface_s *interface,
                bbl_ethernet_header_s *eth)
{
    bbl_lag_member_s *member = interface->lag_member;
    bbl_lacp_s *lacp = (bbl_lacp_s*)eth->next; 

    if(member) {
        member->timeout = 0;
        member->actor_state &= ~(LACP_STATE_FLAG_DEFAULTED|LACP_STATE_FLAG_EXPIRED);
        member->stats.lacp_rx++;
        if(member->partner_state != lacp->actor_state ||
           member->partner_system_priority != lacp->actor_system_priority) {
            memcpy(member->partner_system_id, lacp->actor_system_id, ETH_ADDR_LEN);
            member->partner_system_priority = lacp->actor_system_priority;
            member->partner_key = lacp->actor_key;
            member->partner_port_priority = lacp->actor_port_priority;
            member->partner_port_id = lacp->actor_port_id;
            member->partner_state = lacp->actor_state;
            bbl_lag_select(member->lag);
        }
    }
}