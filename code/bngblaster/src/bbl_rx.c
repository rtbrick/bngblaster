/*
 * BNG Blaster (BBL) - RX
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

static bool
bbl_rx_stream_network(bbl_network_interface_s *interface, 
                      bbl_ethernet_header_s *eth) 
{
    bbl_stream_s *stream;
    if(!eth->bbl || memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
        return false;
    }
    stream = bbl_stream_rx(eth, NULL);
    if(stream) {
        if(stream->rx_network_interface == NULL) {
            stream->rx_network_interface = interface;
        }
        return true;
    }
    return false;
}

static bool
bbl_rx_stream_access(bbl_access_interface_s *interface, 
                     bbl_ethernet_header_s *eth) 
{
    bbl_stream_s *stream;
    bbl_session_s *session;
    uint32_t session_id = 0;

    if(!(eth->bbl && eth->bbl->type == BBL_TYPE_UNICAST)) {
        return false;
    }

    session_id |= eth->dst[5];
    session_id |= eth->dst[4] << 8;
    session_id |= eth->dst[3] << 16;

    session = bbl_session_get(session_id);
    if(session) {
        if(session->session_state != BBL_TERMINATED &&
           session->session_state != BBL_IDLE) {
            stream = bbl_stream_rx(eth, session);
            if(stream) {
                if(stream->rx_access_interface == NULL) {
                    stream->rx_access_interface = interface;
                }
                return true;
            }
        }
    }
    return false;
}

static bool
bbl_rx_stream_a10nsp(bbl_a10nsp_interface_s *interface, 
                     bbl_ethernet_header_s *eth) 
{
    bbl_stream_s *stream;
    if(!eth->bbl || memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
        return false;
    }
    stream = bbl_stream_rx(eth, NULL);
    if(stream) {
        if(stream->rx_a10nsp_interface == NULL) {
            stream->rx_a10nsp_interface = interface;
        }
        return true;
    }
    return false;
}

bool
bbl_rx_thread(bbl_interface_s *interface, 
              bbl_ethernet_header_s *eth)
{
    bbl_network_interface_s *network_interface = interface->network;
    while(network_interface) {
        if(network_interface->vlan == eth->vlan_outer) {
            return bbl_rx_stream_network(network_interface, eth);
        }
        network_interface = network_interface->next;
    }
    if(interface->access) {
        return bbl_rx_stream_access(interface->access, eth);
    } else if(interface->a10nsp) {
        return bbl_rx_stream_a10nsp(interface->a10nsp, eth);
    }
    return false;
}

void
bbl_rx_handler(bbl_interface_s *interface,
               bbl_ethernet_header_s *eth)
{
    bbl_network_interface_s *network_interface;

    /* Check for link/port protocols like LACP or LLDP */
    switch(eth->type) {
        case ETH_TYPE_LACP:
            bbl_lag_rx_lacp(interface, eth);
            return;
        default:
            break;
    }

    if(interface->type == LAG_MEMBER_INTERFACE) {
        bbl_rx_handler(interface->lag->interface, eth);
        return;
    }

    network_interface = interface->network_vlan[eth->vlan_outer];
    if(network_interface) {
        if(!bbl_rx_stream_network(network_interface, eth)) {
            bbl_network_rx_handler(network_interface, eth);
        }
     } else if(interface->access) {
        if(!bbl_rx_stream_access(interface->access, eth)) {
            bbl_access_rx_handler(interface->access, eth);
        }
    } else if(interface->a10nsp) {
        if(!bbl_rx_stream_a10nsp(interface->a10nsp, eth)) {
            bbl_a10nsp_rx_handler(interface->a10nsp, eth);
        }
    }
}