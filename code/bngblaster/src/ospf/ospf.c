/*
 * BNG Blaster (BBL) - OSPF Functions
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

/**
 * ospf_init
 * 
 * This function inits all OSPF instances. 
 */
bool
ospf_init() {
    ospf_config_s *config = g_ctx->config.ospf_config;
    ospf_instance_s *instance = NULL;

    while(config) {
        LOG(OSPF, "Init OSPFv%u instance %u\n", config->version, config->id);
        if(instance) {
            instance->next = calloc(1, sizeof(ospf_instance_s));
            instance = instance->next;
        } else {
            instance = calloc(1, sizeof(ospf_instance_s));
            g_ctx->ospf_instances = instance;
        }
        instance->config = config;
        instance->lsdb = hb_tree_new((dict_compare_func)ospf_lsa_id_compare);

        if(!ospf_lsa_self_update(instance)) {
            LOG(OSPF, "Failed to generate self originated LSA for OSPFv%u instance %u\n", 
                config->version, config->id);
            return false;
        }

        if(config->external_mrt_file) {
            if(!ospf_mrt_load(instance, config->external_mrt_file)) {
                LOG(OSPF, "Failed to load MRT file %s\n", 
                    config->external_mrt_file);
                return false;
            }
        }

        /* Start LSA garbage collection job. */
        timer_add_periodic(&g_ctx->timer_root, &instance->timer_lsa_gc, 
                           "OSPF LSA GC", OSPF_LSA_GC_INTERVAL, 0, instance,
                           &ospf_lsa_gc_job);

        config = config->next;
    }
    return true;
}

/**
 * ospf_handler_rx_ipv4
 *
 * This function handles IPv4 OSPFv2 packets received on network interfaces.
 *
 * @param interface pointer to interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 * @param ipv4 pointer to IPv4 header structure of received packet
 */
void
ospf_handler_rx_ipv4(bbl_network_interface_s *interface, 
                     bbl_ethernet_header_s *eth, 
                     bbl_ipv4_s *ipv4)
{
    protocol_error_t result;
    ospf_pdu_s pdu = {0};

    ospf_interface_s *ospf_interface = interface->ospf_interface;
    ospf_neighbor_s  *ospf_neighbor = ospf_interface->neighbors;

    bbl_ospf_s *ospf = ipv4->next;

    UNUSED(eth);

    if(ipv4->dst == IPV4_MC_ALL_DR_ROUTERS) {
        if(!(ospf_interface->state == OSPF_IFSTATE_DR || ospf_interface->state == OSPF_IFSTATE_BACKUP)) {
            return;
        }
    } else if(!(ipv4->dst == IPV4_MC_ALL_OSPF_ROUTERS || ipv4->dst == interface->ip.address)) {
        return;
    }

    interface->stats.ospf_rx++;
    result = ospf_pdu_load(&pdu, ospf->pdu, ospf->pdu_len);
    pdu.mac = eth->src;
    pdu.source = (void*)&ipv4->src;
    pdu.destination = (void*)&ipv4->dst;
    if(pdu.pdu_version != OSPF_VERSION_2) {
        LOG(OSPF, "OSPFv2 RX PDU version error on interface %s\n", interface->name);
        interface->stats.ospf_rx_error++;
        return;
    }
    if(result != PROTOCOL_SUCCESS) {
        LOG(OSPF, "OSPFv2 RX %s PDU decode error on interface %s\n", 
            ospf_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.ospf_rx_error++;
        return;
    }
    if(!ospf_pdu_validate_checksum(&pdu)) {
        LOG(OSPF, "OSPFv2 RX %s PDU checksum error on interface %s\n", 
            ospf_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.ospf_rx_error++;
        return;
    }

    LOG(PACKET, "OSPFv2 RX %s on interface %s\n",
        ospf_pdu_type_string(pdu.pdu_type), interface->name);

    while(ospf_neighbor) {
        if(ospf_neighbor->router_id == pdu.router_id) {
            break;
        }
        ospf_neighbor = ospf_neighbor->next;
    }

    switch(pdu.pdu_type) {
        case OSPF_PDU_HELLO:
            ospf_hello_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_DB_DESC:
            ospf_neighbor_dbd_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_LS_UPDATE:
            ospf_lsa_update_handler_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_LS_REQUEST:
            ospf_lsa_req_handler_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_LS_ACK:
            ospf_lsa_ack_handler_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        default:
            interface->stats.ospf_rx_error++;
            break;
    }
    return;
}

/**
 * ospf_handler_rx_ipv6
 *
 * This function handles IPv6 OSPFv3 packets received on network interfaces.
 *
 * @param interface pointer to interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 * @param ipv6 pointer to IPv6 header structure of received packet
 */
void
ospf_handler_rx_ipv6(bbl_network_interface_s *interface, 
                     bbl_ethernet_header_s *eth, 
                     bbl_ipv6_s *ipv6)
{

    protocol_error_t result;
    ospf_pdu_s pdu = {0};

    ospf_interface_s *ospf_interface = interface->ospf_interface;
    ospf_neighbor_s  *ospf_neighbor = ospf_interface->neighbors;

    bbl_ospf_s *ospf = ipv6->next;

    UNUSED(eth);

    interface->stats.ospf_rx++;
    result = ospf_pdu_load(&pdu, ospf->pdu, ospf->pdu_len);
    pdu.mac = eth->src;
    pdu.source = (void*)ipv6->src;
    pdu.destination = (void*)ipv6->dst;
    if(pdu.pdu_version != 3) {
        LOG(OSPF, "OSPFv3 RX PDU version error on interface %s\n", interface->name);
        interface->stats.ospf_rx_error++;
        return;
    }
    if(result != PROTOCOL_SUCCESS) {
        LOG(OSPF, "OSPFv3 RX %s PDU decode error on interface %s\n", 
            ospf_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.ospf_rx_error++;
        return;
    }
    if(!ospf_pdu_validate_checksum(&pdu)) {
        LOG(OSPF, "OSPFv3 RX %s PDU checksum error on interface %s\n", 
            ospf_pdu_type_string(pdu.pdu_type), interface->name);
        interface->stats.ospf_rx_error++;
        return;
    }

    LOG(PACKET, "OSPFv3 RX %s on interface %s\n",
        ospf_pdu_type_string(pdu.pdu_type), interface->name);

    while(ospf_neighbor) {
        if(ospf_neighbor->router_id == pdu.router_id) {
            break;
        }
        ospf_neighbor = ospf_neighbor->next;
    }

    switch(pdu.pdu_type) {
        case OSPF_PDU_HELLO:
            ospf_hello_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_DB_DESC:
            ospf_neighbor_dbd_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_LS_UPDATE:
            ospf_lsa_update_handler_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_LS_REQUEST:
            ospf_lsa_req_handler_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        case OSPF_PDU_LS_ACK:
            ospf_lsa_ack_handler_rx(ospf_interface, ospf_neighbor, &pdu);
            break;
        default:
            interface->stats.ospf_rx_error++;
            break;
    }
    return;
}

void
ospf_teardown_job(timer_s *timer) {
    ospf_instance_s *instance = timer->data;
    UNUSED(instance);
}

/**
 * ospf_teardown
 * 
 * This function stops all OSPF instances. 
 */
void
ospf_teardown()
{
    ospf_instance_s *instance = g_ctx->ospf_instances;
    while(instance) {
        if(!instance->teardown) {
            LOG(ISIS, "Teardown OSPFv%u instance %u\n", instance->config->version, instance->config->id);
            instance->teardown = true;
            ospf_lsa_self_update(instance);
            ospf_lsa_purge_all_external(instance);
            timer_add(&g_ctx->timer_root, &instance->timer_teardown, 
                      "OSPF TEARDOWN", instance->config->teardown_time, 0, instance,
                      &ospf_teardown_job);
        }
        instance = instance->next;
    }
}