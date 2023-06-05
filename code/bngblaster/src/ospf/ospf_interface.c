/*
 * BNG Blaster (BBL) - OSPF Interface
 * 
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

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
                interface->ospf_interface = ospf_interface;
                ospf_interface->interface = interface;
                ospf_interface->instance = ospf;
                ospf_interface->version = version;
                ospf_interface->type = interface_type;
                ospf_interface->next = ospf->interfaces;
                ospf->interfaces = ospf_interface;

                if(interface_type == OSPF_INTERFACE_P2P ||
                   interface_type == OSPF_INTERFACE_VIRTUAL) {
                    ospf_interface->state = OSPF_IFSTATE_P2P;
                } else {
                    ospf_interface->state = OSPF_IFSTATE_WAITING;
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