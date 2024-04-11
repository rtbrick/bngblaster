/*
 * BNG Blaster (BBL) - LAG Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

uint16_t g_lag_port_id = 1;

const char *
lacp_state_string(lacp_state_t type)
{
    switch(type) {
        case LACP_EXPIRED: return "Expired";
        case LACP_DEFAULTED: return "Defaulted";
        case LACP_CURRENT: return "Current";
        default: return "Disabled";
    }
}

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
        interface->ifindex = g_ctx->interfaces++;
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

static void
bbl_lag_member_update_state(bbl_lag_member_s *member, interface_state_t state)
{
    bbl_interface_s *interface = member->interface;
    if(interface->state == state) {
        return;
    }

    LOG(LAG, "LAG (%s) Member interface %s state changed from %s to %s\n", 
        member->lag->interface->name, 
        interface->name,
        interface_state_string(interface->state),
        interface_state_string(state));

    interface->state_transitions++;
    interface->state = state;
    switch(state) {
        case INTERFACE_UP:
            member->actor_state |= (LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
            break;
        case INTERFACE_STANDBY:
            member->actor_state &= ~LACP_STATE_FLAG_DISTRIBUTING;
            member->actor_state |= LACP_STATE_FLAG_COLLECTING;
            break;
        default:
            member->actor_state &= ~(LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
            break;
    }
}

static void
bbl_lag_update_state(bbl_lag_s *lag, interface_state_t state)
{
    bbl_interface_s *interface = lag->interface;
    if(interface->state == state) {
        return;
    }

    LOG(LAG, "LAG (%s) Interface state changed from %s to %s\n", 
        interface->name, 
        interface_state_string(interface->state),
        interface_state_string(state));

    interface->state_transitions++;
    interface->state = state;
}

static void
bbl_lag_select(bbl_lag_s *lag)
{
    bbl_lag_member_s *member;
    bbl_stream_s *stream = lag->stream_head;
    io_handle_s *io;

    uint8_t active_count = 0;
    uint8_t key;

    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        io = member->interface->io.tx;
        io->stream_pps = 0;
        io->stream_count = 0;
        io->stream_head = NULL;
        io->stream_cur = NULL;

        member->primary = false;
        if(member->interface->state != INTERFACE_DISABLED) {
            if(member->lacp_state == LACP_CURRENT && 
               member->partner_state & LACP_STATE_FLAG_COLLECTING) {
                if(active_count >= LAG_MEMBER_ACTIVE_MAX ||
                   active_count >= lag->config->lacp_max_active_links) {
                    bbl_lag_member_update_state(member, INTERFACE_STANDBY);
                } else {
                    if(active_count == 0) {
                        member->primary = true;
                    }
                    lag->active_list[active_count++] = member;
                    bbl_lag_member_update_state(member, INTERFACE_UP);
                }
            } else {
                bbl_lag_member_update_state(member, INTERFACE_DOWN);
            }
        }
    }

    /* Update LAG state */
    if(active_count && 
       active_count >= lag->config->lacp_min_active_links) {
        bbl_lag_update_state(lag, INTERFACE_UP);
        /* Distribute streams */
        while(stream) {
            key = stream->flow_id % active_count;
            io = lag->active_list[key]->interface->io.tx;
            stream->io = io;
            stream->io_next = io->stream_head;
            io->stream_head = stream;
            io->stream_cur = stream;
            io->stream_pps += stream->pps;
            io->stream_count++;
            stream = stream->lag_next;
        }
    } else {
        bbl_lag_update_state(lag, INTERFACE_DOWN);
        while(stream) {
            stream->io = NULL;
            stream->io_next = NULL;
            stream = stream->lag_next;
        }
    }
    lag->active_count = active_count;
}

void
bbl_lag_lacp_job(timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    bbl_lag_member_s *member = interface->lag_member;

    interface->send_requests |= BBL_SEND_LACP;
    member->timeout++;
    if(member->timeout > 3) {
        if(!(member->actor_state & LACP_STATE_FLAG_EXPIRED)) {
            member->lacp_state = LACP_EXPIRED;
            member->actor_state |= LACP_STATE_FLAG_EXPIRED;
            LOG(LAG, "LAG (%s) LACP expired on interface %s\n",
                member->lag->interface->name, interface->name);
            bbl_lag_select(member->lag);
        }
        if(member->timeout > 6) {
            if(!(member->actor_state & LACP_STATE_FLAG_DEFAULTED)) {
                member->lacp_state = LACP_DEFAULTED;
                member->actor_state |= LACP_STATE_FLAG_DEFAULTED;
                memset(member->partner_system_id, 0x0, ETH_ADDR_LEN);
                member->partner_system_priority = 0;
                member->partner_key = 0;
                member->partner_port_priority = 0;
                member->partner_port_id = 0;
                member->partner_state = 0;
                LOG(LAG, "LAG (%s) LACP defaulted on interface %s\n", 
                    member->lag->interface->name, interface->name);
                bbl_lag_select(member->lag);
            }
        }
    }
}

static void
bbl_lag_member_insert(bbl_lag_s *lag, bbl_lag_member_s *member)
{
    /* Insert LAG member links by port priority 
     * (lower value is higher priority). */
    bbl_lag_member_s *member_iter;
    CIRCLEQ_FOREACH(member_iter, &lag->lag_member_qhead, lag_member_qnode) {
        if(member_iter->actor_port_priority > member->actor_port_priority) {
            CIRCLEQ_INSERT_BEFORE(&lag->lag_member_qhead, member_iter, member, lag_member_qnode);
            return;
        }
    }
    CIRCLEQ_INSERT_TAIL(&lag->lag_member_qhead, member, lag_member_qnode);
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
            member->actor_state = LACP_STATE_FLAG_ACTIVE|LACP_STATE_FLAG_IN_SYNC|LACP_STATE_FLAG_AGGREGATION|LACP_STATE_FLAG_EXPIRED|LACP_STATE_FLAG_DEFAULTED;
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
            lag->interface->state = INTERFACE_UP;
            lag->active_list[lag->active_count++] = member;
            if(CIRCLEQ_EMPTY(&lag->lag_member_qhead)) {
                member->primary = true;
            }
        }

        bbl_lag_member_insert(lag, member);
        LOG(LAG, "LAG (%s) Interface %s added\n", lag->interface->name, interface->name);
    }
    return true;
}

void
bbl_lag_member_lacp_reset(bbl_interface_s *interface)
{
    bbl_lag_member_s *member = interface->lag_member;

    if(member && member->lacp_state) {
        member->lacp_state = LACP_DEFAULTED;
        member->actor_state |= (LACP_STATE_FLAG_EXPIRED|LACP_STATE_FLAG_DEFAULTED);
        memset(member->partner_system_id, 0x0, ETH_ADDR_LEN);
        member->partner_system_priority = 0;
        member->partner_key = 0;
        member->partner_port_priority = 0;
        member->partner_port_id = 0;
        member->partner_state = 0;
        LOG(LAG, "LAG (%s) LACP defaulted on interface %s\n", 
            member->lag->interface->name, interface->name);
        bbl_lag_select(member->lag);
    }
}

void
bbl_lag_rx_lacp(bbl_interface_s *interface, bbl_ethernet_header_s *eth)
{
    bbl_lag_member_s *member = interface->lag_member;
    bbl_lacp_s *lacp = (bbl_lacp_s*)eth->next; 

    if(member && member->lacp_state) {
        member->timeout = 0;
        member->actor_state &= ~(LACP_STATE_FLAG_DEFAULTED|LACP_STATE_FLAG_EXPIRED);
        member->stats.lacp_rx++;
        if(member->lacp_state != LACP_CURRENT ||
           member->partner_state != lacp->actor_state ||
           member->partner_system_priority != lacp->actor_system_priority ||
           member->partner_port_priority != lacp->actor_port_priority) {
            /* Update partner informations and trigger member selection */
            member->lacp_state = LACP_CURRENT;
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

static json_t *
bbl_lag_json(bbl_lag_s *lag)
{
    bbl_lag_member_s *member;
    io_handle_s *io;
    json_t *jobj_lag, *jobj_member, *jobj_lacp, *jobj_array;

    jobj_array = json_array();

    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        if(member->lacp_state) {
            io = member->interface->io.tx;
            jobj_lacp = json_pack("{si si si ss* si si si si si ss* si si si si si si sf}",
                "bpdu-rx", member->stats.lacp_rx,
                "bpdu-tx", member->stats.lacp_tx,
                "bpdu-dropped", member->stats.lacp_dropped,
                "actor-system-id", format_mac_address(member->actor_system_id),
                "actor-system-priority", member->actor_system_priority,
                "actor-key", member->actor_key,
                "actor-port-priority", member->actor_port_priority,
                "actor-port-id", member->actor_port_id,
                "actor-state", member->actor_state,
                "partner-system-id", format_mac_address(member->partner_system_id),
                "partner-system-priority", member->partner_system_priority,
                "partner-key", member->partner_key,
                "partner-port-priority", member->partner_port_priority,
                "partner-port-id", member->partner_port_id,
                "partner-state", member->partner_state,
                "stream-count", io->stream_count,
                "stream-pps", io->stream_pps
                );
        } else {
            jobj_lacp = NULL;
        }
        jobj_member = json_pack("{ss* ss* si sI sI ss* so*}",
            "interface", member->interface->name,
            "state", interface_state_string(member->interface->state),
            "state-transitions", member->interface->state_transitions,
            "packets-rx", member->interface->io.rx->stats.packets,
            "packets-tx", member->interface->io.tx->stats.packets,
            "lacp-state", lacp_state_string(member->lacp_state),
            "lacp", jobj_lacp);
        if(jobj_member) {
            json_array_append(jobj_array, jobj_member);
        }
    }

    jobj_lag = json_pack("{si ss* ss* si sI si so*}",
        "id", lag->id,
        "interface", lag->interface->name,
        "state", interface_state_string(lag->interface->state),
        "state-transitions", lag->interface->state_transitions,
        "stream-count", lag->stream_count,
        "members-active", lag->active_count,
        "members", jobj_array);
    
    return jobj_lag;
}

int
bbl_lag_ctrl_info(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;

    bbl_lag_s *lag;    
    json_t *root, *jobj, *jobj_array;
    const char *interface = NULL;

    jobj_array = json_array();

    /* Unpack further arguments */
    json_unpack(arguments, "{s:s}", "interface", &interface);

    CIRCLEQ_FOREACH(lag, &g_ctx->lag_qhead, lag_qnode) {
        if(interface) {
            if(strcmp(lag->interface->name, interface) != 0) {
                continue;
            }
        }
        jobj = bbl_lag_json(lag);
        if(jobj) {
            json_array_append(jobj_array, jobj);
        }
    }

    root = json_pack("{ss si so*}",
        "status", "ok",
        "code", 200,
        "lag-info", jobj_array);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}