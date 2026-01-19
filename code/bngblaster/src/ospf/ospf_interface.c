/*
 * BNG Blaster (BBL) - OSPF Interface
 * 
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

static bool
ospf_interface_elect_dr_bdr(ospf_interface_s *ospf_interface)
{
    uint32_t dr = 0;
    uint32_t bdr = 0;
    uint32_t neighbor_id;

    ospf_config_s   *config = ospf_interface->instance->config;
    ospf_neighbor_s *dr_canditate = NULL;
    ospf_neighbor_s *bdr_canditate = NULL;
    ospf_neighbor_s *bdr_alternate = NULL; /* alternate BDR if no neighbor is declaring BDR */
    ospf_neighbor_s *neighbor;

    /* Create a neighbor structure for the local interface. */
    ospf_neighbor_s self = {0};
    self.router_id = config->router_id;
    self.priority = config->router_priority;
    self.ipv4 = ospf_interface->interface->ip.address;
    self.state = OSPF_NBSTATE_2WAY;
    self.dr = ospf_interface->dr;
    self.bdr = ospf_interface->bdr;
    self.next = ospf_interface->neighbors;

    neighbor = &self;
    while(neighbor) {
        /* Iterate over all neighbors with staet >= 2WAY ... */
        if(neighbor->state >= OSPF_NBSTATE_2WAY && neighbor->priority > 0) {
            if(ospf_interface->version == OSPF_VERSION_2) {
                neighbor_id = neighbor->ipv4;
            } else {
                neighbor_id = neighbor->router_id;
            }
            if(neighbor->dr == neighbor_id) {
                if(!dr_canditate) {
                    dr_canditate = neighbor;
                } else if(neighbor->priority > dr_canditate->priority) {
                    dr_canditate = neighbor;
                } else if(neighbor->priority == dr_canditate->priority && 
                          be32toh(neighbor->router_id) > be32toh(dr_canditate->router_id)) {
                    dr_canditate = neighbor;
                }
            } else {
                if(neighbor->bdr == neighbor_id) {
                    if(!bdr_canditate) {
                        bdr_canditate = neighbor;
                    } else if(neighbor->priority > bdr_canditate->priority) {
                        bdr_canditate = neighbor;
                    } else if(neighbor->priority == bdr_canditate->priority && 
                              be32toh(neighbor->router_id) > be32toh(bdr_canditate->router_id)) {
                        bdr_canditate = neighbor;
                    }
                } else if(!bdr_canditate) {
                    if(!bdr_alternate) {
                        bdr_alternate = neighbor;
                    } else if(neighbor->priority > bdr_alternate->priority) {
                        bdr_alternate = neighbor;
                    } else if(neighbor->priority == bdr_alternate->priority && 
                              be32toh(neighbor->router_id) > be32toh(bdr_alternate->router_id)) {
                        bdr_alternate = neighbor;
                    }
                }
            }
        }
        neighbor = neighbor->next;
    }
    if(!bdr_canditate) {
        bdr_canditate = bdr_alternate;
    }
    if(!dr_canditate) {
        dr_canditate = bdr_canditate;
    }

    if(ospf_interface->version == OSPF_VERSION_2) {
        if(bdr_canditate) {
            bdr = bdr_canditate->ipv4;
        }
        if(dr_canditate) {
            dr = dr_canditate->ipv4;
        }
    } else {
        if(bdr_canditate) {
            bdr = bdr_canditate->router_id;
        }
        if(dr_canditate) {
            dr = dr_canditate->router_id;
        }
    }

    if(dr != ospf_interface->dr || bdr != ospf_interface->bdr) {
        ospf_interface->dr = dr;
        ospf_interface->bdr = bdr;
        return true;
    }

    return false;
}

void
ospf_interface_ack_job(timer_s *timer)
{
    ospf_interface_s *ospf_interface = timer->data;
    ospf_lsa_ack_tx(ospf_interface, NULL);
}

void
ospf_interface_flood_job(timer_s *timer)
{
    ospf_interface_s *ospf_interface = timer->data;
    ospf_lsa_update_tx(ospf_interface, NULL, false);
}

void
ospf_interface_update_state(ospf_interface_s *ospf_interface, uint8_t state)
{
    if(ospf_interface->state == state) return;
 
    ospf_neighbor_s *neighbor = ospf_interface->neighbors;
    uint8_t old = ospf_interface->state;

    ospf_interface->state = state;
    LOG(OSPF, "OSPFv%u interface %s state %s -> %s\n",
        ospf_interface->version,
        ospf_interface->interface->name, 
        ospf_interface_state_string(old),
        ospf_interface_state_string(state));

    if(state > OSPF_IFSTATE_WAITING) {
        timer_add_periodic(&g_ctx->timer_root, &ospf_interface->timer_lsa_ack, "OSPF LSA ACK", 
                           0, 100 * MSEC, ospf_interface, &ospf_interface_ack_job);

        timer_add_periodic(&g_ctx->timer_root, &ospf_interface->timer_lsa_flood, "OSPF LSA FLOODING", 
                           0, 10 * MSEC, ospf_interface, &ospf_interface_flood_job);
    }

    if(old > OSPF_IFSTATE_P2P) {
        /* This refers to the event "AdjOK?" as described in RFC2328 */
        while(neighbor) {
            ospf_neighbor_adjok(neighbor);
            neighbor = neighbor->next;
        }
    }
    ospf_lsa_self_update_request(ospf_interface->instance);
}

void
ospf_interface_neighbor_change(ospf_interface_s *ospf_interface)
{
    ospf_config_s *config = ospf_interface->instance->config;
    uint32_t id;

    switch (ospf_interface->state) {
        case OSPF_IFSTATE_DOWN:
        case OSPF_IFSTATE_LOOPBACK:
        case OSPF_IFSTATE_P2P:
            return;
        default:
            break;
    }


    if(ospf_interface_elect_dr_bdr(ospf_interface)) {
        ospf_interface_elect_dr_bdr(ospf_interface);

        if(ospf_interface->version == OSPF_VERSION_2) {
            id = ospf_interface->interface->ip.address;
        } else {
            id = config->router_id;
        }

        if(ospf_interface->dr == id) {
            ospf_interface_update_state(ospf_interface, OSPF_IFSTATE_DR);
        } else if(ospf_interface->dr && ospf_interface->bdr == id) {
            ospf_interface_update_state(ospf_interface, OSPF_IFSTATE_BACKUP);
        } else if(ospf_interface->dr) {
            ospf_interface_update_state(ospf_interface, OSPF_IFSTATE_DR_OTHER);
        } else {
            ospf_interface_update_state(ospf_interface, OSPF_IFSTATE_WAITING);
        }
    }
}

void
ospf_interface_hello_job(timer_s *timer)
{
    ospf_interface_s *ospf_interface = timer->data;

    switch(ospf_interface->version) {
        case OSPF_VERSION_2:
            ospf_interface->interface->send_requests |= BBL_IF_SEND_OSPFV2_HELLO;
            break;
        case OSPF_VERSION_3:
            ospf_interface->interface->send_requests |= BBL_IF_SEND_OSPFV3_HELLO;
            break;
        default:
            break;
    }
}

/**
 * ospf_interface_init
 * 
 * This function inits the OSPF interface.
 *
 * @param interface network interface
 * @param config network interface configuration
 * @param version OSPF version (2 or 3)
 */
bool 
ospf_interface_init(bbl_network_interface_s *interface,
                    bbl_network_config_s *network_config,
                    uint8_t version)
{
    ospf_instance_s *ospf;
    ospf_interface_s *ospf_interface;
    uint16_t instance_id;
    uint8_t interface_type;

    static uint32_t interface_id = 1000000;

    switch(version) {
        case OSPF_VERSION_2:
            instance_id = network_config->ospfv2_instance_id;
            interface_type = network_config->ospfv2_type;
            break;
        case OSPF_VERSION_3:
            instance_id = network_config->ospfv3_instance_id;
            interface_type = network_config->ospfv3_type;
            break;
        default: 
            return false;
    }

    if(instance_id) {
        ospf = g_ctx->ospf_instances;
        while(ospf) {
            if(ospf->config->id == instance_id) {
                if(!(ospf->config->version == version)) {
                   LOG(ERROR, "Failed to enable OSPFv%u for network interface %s (version mismatch)\n", 
                       version, interface->name);
                    return false;
                }
                ospf_interface = calloc(1, sizeof(ospf_interface_s));
                ospf_interface->interface = interface;
                ospf_interface->instance = ospf;
                ospf_interface->version = version;
                ospf_interface->type = interface_type;
                ospf_interface->id = interface_id++;
                if(version == OSPF_VERSION_2) {
                    interface->ospfv2_interface = ospf_interface;
                    ospf_interface->metric = network_config->ospfv2_metric;
                    ospf_interface->frag_buf = malloc(OSPF_PDU_LEN_MAX);
                    ospf_interface->frag_id = 0;
                    ospf_interface->frag_off = 0;
                } else {
                    interface->ospfv3_interface = ospf_interface;
                    ospf_interface->metric = network_config->ospfv3_metric;
                }

                ospf_interface->next = ospf->interfaces;
                ospf->interfaces = ospf_interface;
                if(interface_type == OSPF_INTERFACE_P2P ||
                   interface_type == OSPF_INTERFACE_VIRTUAL) {
                    ospf_interface_update_state(ospf_interface, OSPF_IFSTATE_P2P);
                } else {
                    ospf_interface_update_state(ospf_interface, OSPF_IFSTATE_WAITING);
                }

                for(uint8_t type=OSPF_LSA_TYPE_1; type < OSPF_LSA_TYPE_MAX; type++) {
                    ospf_interface->lsa_flood_tree[type] = hb_tree_new((dict_compare_func)ospf_lsa_key_compare);
                    ospf_interface->lsa_ack_tree[type] = hb_tree_new((dict_compare_func)ospf_lsa_key_compare);
                }

                timer_add_periodic(&g_ctx->timer_root, &ospf_interface->timer_hello, 
                                   "OSPF HELLO", 
                                   ospf->config->hello_interval, 0,
                                   ospf_interface, 
                                   &ospf_interface_hello_job);

                return true;
            }
            ospf = ospf->next;
        }
        LOG(ERROR, "Failed to enable OSPFv%u for network interface %s (instance not found)\n", 
            version, interface->name);
        return false;
    }
    return true;
}
