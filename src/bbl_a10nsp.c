/*
 * BNG Blaster (BBL) - A10NSP Functions
 *
 * Christian Giese, September 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"

#if 0
/**
 * bbl_a10nsp_pppoed_handler_rx
 *
 * This function handles all received PPPoE discovery traffic 
 * on network interfaces.
 *
 * @param eth Received ethernet packet.
 * @param pppoed PPPoE discovery header of received ethernet packet.
 * @param interface Receiving interface.
 */
void
bbl_a10nsp_pppoed_handler_rx(bbl_ethernet_header_t *eth, 
                                      bbl_pppoe_discovery_t *pppoed, 
                                      bbl_interface_s *interface) {
    bbl_ctx_s *ctx = interface->ctx;
    bbl_tx_queue_t *q;

    const char *service_name = "access";
    const char *ac_name = "BNG-Blaster";

    uint8_t ac_cookie[16];

    if(ctx->config.pppoe_server_enable == false) {
        return;
    }

    if(memcmp(eth->dst, (uint8_t*)broadcast_mac, ETH_ADDR_LEN) == 0) {
        /* Broadcast received */
        if(pppoed->code != PPPOE_PADI) {
            return;
        }
        pppoed->code = PPPOE_PADO;
        /* Init random AC-Cookie */
        for(int i = 0; i < sizeof(ac_cookie); i++) {
            ac_cookie[i] = rand();
        }
        pppoed->ac_cookie = ac_cookie;
        pppoed->ac_cookie_len = sizeof(ac_cookie); 
    } else if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) == 0) {
        if(pppoed->code == PPPOE_PADR) {
            pppoed->code = PPPOE_PADS;
        } else {
            if(pppoed->code == PPPOE_PADT) { 
                /* Terminate corresponding session */
            }
            return;
        }
    } else {
        /* Drop wrong MAC */
        return;
    }

    /* Send response ... */
    eth->dst = eth->src;
    eth->src = interface->mac;    
    pppoed->access_line = NULL;
    pppoed->service_name = (uint8_t*)service_name;
    pppoed->service_name_len = strlen(service_name);
    pppoed->ac_name = (uint8_t*)ac_name;
    pppoed->ac_name_len = strlen(ac_name);

    return;
}
#endif

void
bbl_a10nsp_rx(bbl_interface_s *interface, 
              bbl_session_s *session, 
              bbl_ethernet_header_t *eth)
{
    UNUSED(interface);
    UNUSED(session);
    UNUSED(eth);
    return;
}