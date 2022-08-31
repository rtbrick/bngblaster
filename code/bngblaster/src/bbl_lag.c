/*
 * BNG Blaster (BBL) - LAG Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

void
bbl_lag_rate_job(timer_s *timer)
{
    bbl_lag_s *lag = timer->data;
    bbl_compute_avg_rate(&lag->stats.rate_packets_tx, lag->stats.packets_tx);
    bbl_compute_avg_rate(&lag->stats.rate_packets_rx, lag->stats.packets_rx);
    bbl_compute_avg_rate(&lag->stats.rate_bytes_tx, lag->stats.bytes_tx);
    bbl_compute_avg_rate(&lag->stats.rate_bytes_rx, lag->stats.bytes_rx);
}

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

        timer_add_periodic(&g_ctx->timer_root, &lag->rate_job, "Rate Computation", 1, 0, lag, &bbl_lag_rate_job);
        lag_config = lag_config->next;
    }
    return true;
}

bool
bbl_lag_interface_add(bbl_interface_s *interface, bbl_link_config_s *link_config)
{
    bbl_lag_s *lag;

    if(link_config->lag_id) {
        lag = bbl_lag_get(link_config->lag_id);
        if(!lag) {
            LOG(ERROR, "Failed to add link %s (LAG %u not defined)\n", 
                link_config->interface, link_config->lag_id);
            return false;
        }
        interface->lag = lag;
        CIRCLEQ_INSERT_TAIL(&lag->lag_interface_qhead, interface, interface_lag_qnode);
    }
    return true;
}