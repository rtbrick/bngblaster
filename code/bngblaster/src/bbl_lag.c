/*
 * BNG Blaster (BBL) - LAG Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

#define LACP_NTT_STATE_MASK (LACP_STATE_FLAG_ACTIVE|LACP_STATE_FLAG_SHORT_TIMEOUT|\
                             LACP_STATE_FLAG_AGGREGATION|LACP_STATE_FLAG_IN_SYNC)

extern volatile bool g_teardown;
extern volatile bool g_monkey;

uint16_t g_lag_port_id = 1;

static void
bbl_lag_monkey_job(timer_s *timer);

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
        if(!interface) {
            free(lag);
            return false;
        }
        lag->interface = interface;
        interface->name = config->interface;
        interface->type = LAG_INTERFACE;
        interface->state = INTERFACE_DOWN;
        interface->ifindex = g_ctx->interfaces++;
        interface->lock_fd = -1;
        interface->lag = lag;
        memcpy(interface->mac, config->mac, ETH_ADDR_LEN);

        CIRCLEQ_INIT(&lag->lag_member_qhead);
        CIRCLEQ_INSERT_TAIL(&g_ctx->lag_qhead, lag, lag_qnode);
        CIRCLEQ_INSERT_TAIL(&g_ctx->interface_qhead, interface, interface_qnode);

        if(config->monkey) {
            timer_add_periodic(&g_ctx->timer_root, &lag->monkey_timer, "LAG MONKEY",
                               LAG_MONKEY_INTERVAL, 0, lag, &bbl_lag_monkey_job);
        }

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

/* A passive member sends LACP PDUs only if the
 * partner is active (IEEE 802.1AX periodic machine). */
static void
bbl_lag_lacp_send(bbl_lag_member_s *member)
{
    if((member->actor_state | member->partner_state) & LACP_STATE_FLAG_ACTIVE) {
        member->interface->send_requests |= BBL_SEND_LACP;
    }
}

static void
bbl_lag_select(bbl_lag_s *lag)
{
    bbl_lag_member_s *member;
    bbl_stream_s *stream;
    io_handle_s *io;

    uint8_t active_count = 0;
    uint8_t selected_count = 0;
    uint8_t actor_state;
    uint8_t key;
    bbl_lag_member_s *selected = NULL;

    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        io = member->interface->io.tx;
        io_stream_clear(io);

        member->primary = false;
        if(member->interface->state != INTERFACE_DISABLED && member->interface->link_down) {
            /* Physical link down (DPDK link state). */
            bbl_lag_member_update_state(member, INTERFACE_DOWN);
        } else if(member->interface->state != INTERFACE_DISABLED) {
            actor_state = member->actor_state;
            /* As in IEEE 802.1AX, the members with current partner information
             * are selected in order of their port priority, up to the maximum
             * number of active links, independent of the partner state. Further
             * members are standby, which are not in sync, so that the partner
             * does not use them either. A selected member is in sync, collects
             * once the partner is in sync and distributes once the partner
             * collects as well. Collecting only once distributing would let
             * two BNG Blaster instances wait for each other forever. */
            if(member->lacp_state == LACP_DISABLED) {
                /* Without LACP, all enabled members are active. */
                if(active_count >= LAG_MEMBER_ACTIVE_MAX) {
                    bbl_lag_member_update_state(member, INTERFACE_STANDBY);
                } else {
                    if(active_count == 0) {
                        member->primary = true;
                    }
                    lag->active_list[active_count++] = member;
                    bbl_lag_member_update_state(member, INTERFACE_UP);
                }
            } else if(member->lacp_state != LACP_CURRENT) {
                bbl_lag_member_update_state(member, INTERFACE_DOWN);
                member->actor_state &= ~(LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
            } else if(selected_count >= LAG_MEMBER_ACTIVE_MAX ||
                      selected_count >= lag->config->lacp_max_active_links ||
                      (selected && (memcmp(selected->partner_system_id, member->partner_system_id, ETH_ADDR_LEN) != 0 ||
                                    selected->partner_key != member->partner_key))) {
                /* Only members connected to the same partner system and
                 * key aggregate with the first selected member. */
                bbl_lag_member_update_state(member, INTERFACE_STANDBY);
                member->actor_state &= ~(LACP_STATE_FLAG_IN_SYNC|LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
            } else {
                selected_count++;
                if(!selected) selected = member;
                member->actor_state |= LACP_STATE_FLAG_IN_SYNC;
                if(!(member->partner_state & LACP_STATE_FLAG_IN_SYNC)) {
                    bbl_lag_member_update_state(member, INTERFACE_DOWN);
                    member->actor_state &= ~(LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
                } else if(!(member->partner_state & LACP_STATE_FLAG_COLLECTING)) {
                    bbl_lag_member_update_state(member, INTERFACE_DOWN);
                    member->actor_state |= LACP_STATE_FLAG_COLLECTING;
                    member->actor_state &= ~LACP_STATE_FLAG_DISTRIBUTING;
                } else {
                    if(active_count == 0) {
                        member->primary = true;
                    }
                    lag->active_list[active_count++] = member;
                    bbl_lag_member_update_state(member, INTERFACE_UP);
                    member->actor_state |= (LACP_STATE_FLAG_COLLECTING|LACP_STATE_FLAG_DISTRIBUTING);
                }
            }
            if(member->lacp_state != LACP_DISABLED && member->actor_state != actor_state) {
                /* Inform the partner immediately instead of
                 * waiting for the next periodic LACP PDU. */
                bbl_lag_lacp_send(member);
            }
        }
    }

    /* Update LAG state */
    if(active_count && 
       active_count >= lag->config->lacp_min_active_links) {
        bbl_lag_update_state(lag, INTERFACE_UP);
        /* Distribute streams */
        stream = lag->stream_head;
        while(stream) {
            key = rand() % active_count;
            io = lag->active_list[key]->interface->io.tx;
            io_stream_add(io, stream);
            stream = stream->lag_next;
        }
        for(key=0; key <active_count; key++) {
            io = lag->active_list[key]->interface->io.tx;
            io_stream_smear(io);
        }
    } else {
        bbl_lag_update_state(lag, INTERFACE_DOWN);
    }
    lag->active_count = active_count;
}

/* The periodic rate is selected by the timeout of the partner
 * (IEEE 802.1AX periodic transmission machine). Without current
 * partner information, the rate follows the own timeout, so that
 * the LAG comes up fast with short timeout. */
static uint32_t
bbl_lag_lacp_periodic_time(bbl_lag_member_s *member)
{
    if(member->partner_state & LACP_STATE_FLAG_SHORT_TIMEOUT) {
        return LACP_FAST_PERIODIC_TIME;
    }
    if(member->lacp_state != LACP_CURRENT && 
       member->actor_state & LACP_STATE_FLAG_SHORT_TIMEOUT) {
        return LACP_FAST_PERIODIC_TIME;
    }
    return LACP_SLOW_PERIODIC_TIME;
}

void
bbl_lag_lacp_job(timer_s *timer)
{
    bbl_interface_s *interface = timer->data;
    bbl_lag_member_s *member = interface->lag_member;
    uint32_t expire;

    if(++member->periodic >= bbl_lag_lacp_periodic_time(member)) {
        member->periodic = 0;
        bbl_lag_lacp_send(member);
    }

    /* The partner information expires after the own timeout and
     * is defaulted after a further short timeout in state expired
     * (IEEE 802.1AX receive machine). */
    if(member->actor_state & LACP_STATE_FLAG_SHORT_TIMEOUT) {
        expire = LACP_SHORT_TIMEOUT_TIME;
    } else {
        expire = LACP_LONG_TIMEOUT_TIME;
    }
    if(member->timeout <= expire + LACP_SHORT_TIMEOUT_TIME) {
        member->timeout++;
    }
    if(member->timeout > expire) {
        if(!(member->actor_state & LACP_STATE_FLAG_EXPIRED)) {
            member->lacp_state = LACP_EXPIRED;
            member->actor_state |= LACP_STATE_FLAG_EXPIRED;
            /* Assume short timeout of the partner, which
             * selects the fast periodic rate. */
            member->partner_state |= LACP_STATE_FLAG_SHORT_TIMEOUT;
            member->partner_state &= ~LACP_STATE_FLAG_IN_SYNC;
            LOG(LAG, "LAG (%s) LACP expired on interface %s\n",
                member->lag->interface->name, interface->name);
            bbl_lag_select(member->lag);
        }
        if(member->timeout > expire + LACP_SHORT_TIMEOUT_TIME) {
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
    uint8_t members = 0;

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
        CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
            members++;
        }
        if(!lag->config->lacp_enable && members >= LAG_MEMBER_ACTIVE_MAX) {
            LOG(ERROR, "Failed to add link %s to lag-interface %s (max %u links without LACP)\n", 
                link_config->interface, link_config->lag_interface, LAG_MEMBER_ACTIVE_MAX);
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
            member->actor_state = LACP_STATE_FLAG_IN_SYNC|LACP_STATE_FLAG_AGGREGATION|LACP_STATE_FLAG_EXPIRED|LACP_STATE_FLAG_DEFAULTED;
            if(!lag->config->lacp_passive) {
                member->actor_state |= LACP_STATE_FLAG_ACTIVE;
            }
            if(lag->config->lacp_timeout_short) {
                member->actor_state |= LACP_STATE_FLAG_SHORT_TIMEOUT;
            }
            timer_add_periodic(&g_ctx->timer_root, &member->lacp_timer, "LACP",
                               1, 0, interface, &bbl_lag_lacp_job);
            /* Send the first LACP PDU immediately
             * instead of after the periodic interval. */
            bbl_lag_lacp_send(member);
        } else {
            member->lacp_state = LACP_DISABLED;
            if(interface->link_down) {
                /* The link state is known before the member is added (DPDK),
                 * the member is selected once the link is up. */
                interface->state = INTERFACE_DOWN;
            } else {
                lag->interface->state = INTERFACE_UP;
                if(lag->active_count == 0) {
                    member->primary = true;
                }
                lag->active_list[lag->active_count++] = member;
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

/**
 * bbl_lag_member_enable
 *
 * @brief Enable a disabled LAG member interface. With LACP,
 * the member is selected again once LACP is current, without
 * LACP it is selected immediately.
 */
void
bbl_lag_member_enable(bbl_interface_s *interface)
{
    bbl_lag_member_s *member = interface->lag_member;

    if(!member || interface->state != INTERFACE_DISABLED) {
        return;
    }
    if(member->lacp_state) {
        interface->state = INTERFACE_DOWN;
        bbl_lag_lacp_send(member);
    } else {
        /* Set to down so that the selection reports the transition to up. */
        interface->state = INTERFACE_DOWN;
        bbl_lag_select(member->lag);
    }
}

/**
 * bbl_lag_member_link
 *
 * @brief Physical link state of a member changed. On link down,
 * the LACP partner information is no longer current.
 */
void
bbl_lag_member_link(bbl_interface_s *interface)
{
    bbl_lag_member_s *member = interface->lag_member;

    if(!member) {
        return;
    }
    if(interface->link_down && member->lacp_state) {
        bbl_lag_member_lacp_reset(interface);
    } else {
        bbl_lag_select(member->lag);
    }
}

/**
 * bbl_lag_member_disable
 *
 * @brief Disable a LAG member interface, which
 * removes the member from the active members.
 */
void
bbl_lag_member_disable(bbl_interface_s *interface)
{
    bbl_lag_member_s *member = interface->lag_member;

    if(!member || interface->state == INTERFACE_DISABLED) {
        return;
    }
    if(member->lacp_state) {
        bbl_lag_member_lacp_reset(interface);
        interface->state = INTERFACE_DISABLED;
    } else {
        interface->state = INTERFACE_DISABLED;
        bbl_lag_select(member->lag);
    }
}

/**
 * bbl_lag_monkey_job
 *
 * @brief Flap (disable/enable) one random member of the LAG.
 * Members are toggled independently, so all members
 * can be disabled at the same time.
 */
static void
bbl_lag_monkey_job(timer_s *timer)
{
    bbl_lag_s *lag = timer->data;
    bbl_lag_member_s *member;
    bbl_interface_s *interface;
    uint32_t count = 0;
    uint32_t key;

    if(g_teardown || !g_monkey) {
        return;
    }

    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        count++;
    }
    if(!count) {
        return;
    }
    key = rand() % count;
    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        if(key-- == 0) break;
    }

    interface = member->interface;
    if(interface->state == INTERFACE_DISABLED) {
        LOG(LAG, "LAG (%s) Monkey enables interface %s\n", lag->interface->name, interface->name);
        bbl_lag_member_enable(interface);
    } else {
        LOG(LAG, "LAG (%s) Monkey disables interface %s\n", lag->interface->name, interface->name);
        bbl_lag_member_disable(interface);
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
        /* IEEE 802.1AX-2014 6.4.9 update_Selected: any change of the
         * partner port, priority, system or key selects again. */
        if(member->lacp_state != LACP_CURRENT ||
           member->partner_state != lacp->actor_state ||
           memcmp(member->partner_system_id, lacp->actor_system_id, ETH_ADDR_LEN) != 0 ||
           member->partner_system_priority != lacp->actor_system_priority ||
           member->partner_key != lacp->actor_key ||
           member->partner_port_priority != lacp->actor_port_priority ||
           member->partner_port_id != lacp->actor_port_id) {
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
        /* update_NTT: send a PDU if the partner has stale information
         * about this port (activity, timeout, sync and aggregation). */
        if(!lacp->partner_system_id ||
           memcmp(lacp->partner_system_id, member->actor_system_id, ETH_ADDR_LEN) != 0 ||
           lacp->partner_system_priority != member->actor_system_priority ||
           lacp->partner_key != member->actor_key ||
           lacp->partner_port_priority != member->actor_port_priority ||
           lacp->partner_port_id != member->actor_port_id ||
           (lacp->partner_state & LACP_NTT_STATE_MASK) != (member->actor_state & LACP_NTT_STATE_MASK)) {
            bbl_lag_lacp_send(member);
        }
    }
}

/* Sum over all RX handles (RX threads). */
static uint64_t
bbl_lag_member_rx_packets(bbl_lag_member_s *member)
{
    io_handle_s *io = member->interface->io.rx;
    uint64_t packets = 0;
    while(io) {
        packets += io->stats.packets;
        io = io->next;
    }
    return packets;
}

static json_t *
bbl_lag_json(bbl_lag_s *lag)
{
    bbl_lag_member_s *member;
    json_t *jobj_lag, *jobj_member, *jobj_lacp, *jobj_array;

    jobj_array = json_array();

    CIRCLEQ_FOREACH(member, &lag->lag_member_qhead, lag_member_qnode) {
        if(member->lacp_state) {
            jobj_lacp = json_pack("{si si si ss* si si si si si ss* si si si si si }",
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
                "partner-state", member->partner_state
                );
        } else {
            jobj_lacp = NULL;
        }
        jobj_member = json_pack("{ss* ss* si sI sI si sf ss* so*}",
            "interface", member->interface->name,
            "state", interface_state_string(member->interface->state),
            "state-transitions", member->interface->state_transitions,
            "packets-rx", (json_int_t)bbl_lag_member_rx_packets(member),
            "packets-tx", (json_int_t)member->interface->io.tx->stats.packets,
            "stream-count", member->interface->io.tx->stream_count,
            "stream-pps", bbl_round(member->interface->io.tx->stream_pps, 100),
            "lacp-state", lacp_state_string(member->lacp_state),
            "lacp", jobj_lacp);
        if(jobj_member) {
            json_array_append_new(jobj_array, jobj_member);
        }
    }

    jobj_lag = json_pack("{si ss* ss* si sI si so*}",
        "id", lag->id,
        "interface", lag->interface->name,
        "state", interface_state_string(lag->interface->state),
        "state-transitions", lag->interface->state_transitions,
        "stream-count", (json_int_t)lag->stream_count,
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
            json_array_append_new(jobj_array, jobj);
        }
    }

    root = json_pack("{ss si so*}",
        "status", "ok",
        "code", 200,
        "lag-info", jobj_array);

    if(root) {
        result = json_dumpfd(root, fd, BBL_JSON_REAL_PRECISION);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}