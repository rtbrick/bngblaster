/*
* BNG Blaster (BBL) - ARP Client
*
* Christian Giese, March 2025
*
* Copyright (C) 2020-2025, RtBrick, Inc.
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef __BBL_ARP_CLIENT_H__
#define __BBL_ARP_CLIENT_H__

typedef struct bbl_arp_client_config_
{
    uint16_t arp_client_group_id;

    uint8_t interval;
    uint8_t vlan_priority;
    uint32_t target_ip;

    bbl_arp_client_config_s *next; /* Next arp client config */
} bbl_arp_client_config_s;

typedef struct bbl_arp_client_
{
    uint8_t vlan_priority;
    uint8_t target_mac[ETH_ADDR_LEN];
    uint32_t target_ip;
    uint32_t tx;
    uint32_t rx;

    bbl_session_s *session;
    bbl_arp_client_s *next; /* Next arp client of same session */
    
    struct timer_ *timer;
} bbl_arp_client_s;

void
bbl_arp_client_rx(bbl_session_s *session, bbl_arp_s *arp);

bool
bbl_arp_client_session_init(bbl_session_s *session);

int
bbl_arp_client_ctrl(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

int
bbl_arp_client_ctrl_reset(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)));

#endif
