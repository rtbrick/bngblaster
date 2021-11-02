/*
 * BNG Blaster (BBL) - PPPoE Server Functions
 *
 * Christian Giese, September 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_A10NSP_H__
#define __BBL_A10NSP_H__

#define A10NSP_PPPOE_SERVICE_NAME   "access"
#define A10NSP_PPPOE_AC_NAME        "BNG-Blaster-A10NSP"
#define A10NSP_REPLY_MESSAGE        "BNG-Blaster-A10NSP"

#define A10NSP_IP_LOCAL             168495882
#define A10NSP_IP_REMOTE            168430090
#define A10NSP_DNS1                 168561674
#define A10NSP_DNS2                 168627466

typedef struct bbl_a10nsp_session_
{
    bbl_session_s *session;
    bbl_interface_s *a10nsp_if;
    uint16_t s_vlan;

    bool qinq_received;

    char *pppoe_ari;
    char *pppoe_aci;

    struct {
        uint64_t packets_tx;
        uint64_t packets_rx;
    } stats;

} bbl_a10nsp_session_t;

void
bbl_a10nsp_session_free(bbl_session_s *session);

void
bbl_a10nsp_rx(bbl_interface_s *interface,
              bbl_session_s *session,
              bbl_ethernet_header_t *eth);

#endif
