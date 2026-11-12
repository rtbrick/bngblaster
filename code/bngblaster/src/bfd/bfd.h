/*
 * BNG Blaster (BBL) - BFD Main
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BFD_H__
#define __BBL_BFD_H__

#include "../bbl.h"
#include "bfd_def.h"
#include "bfd_packet.h"
#include "bfd_ctrl.h"

bfd_profile_config_s *
bfd_profile_get(uint16_t id);

bool
bfd_init();

void
bfd_teardown();

void
bfd_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth,
       bbl_ipv4_s *ipv4, bbl_ipv6_s *ipv6, bbl_udp_s *udp);

bfd_session_s *
bfd_session_get(bbl_network_interface_s *interface, uint16_t profile_id, bool multihop,
                uint8_t af, void *local, void *peer);

bfd_session_s *
bfd_session_client_add(bbl_network_interface_s *interface, uint16_t profile_id, bool multihop,
                       uint8_t af, void *local, void *peer,
                       uint8_t type, void *client, bfd_client_cb cb);

void
bfd_session_client_del(bfd_session_s *session, void *client);

bfd_session_s *
bfd_session_by_id(uint32_t id);

void
bfd_session_enable(bfd_session_s *session, bool enable);

void
bfd_session_update(bfd_session_s *session, uint32_t tx_interval, uint32_t rx_interval, uint8_t multiplier);

json_t *
bfd_session_json(bfd_session_s *session);

#endif
