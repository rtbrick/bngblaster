/*
 * BNG Blaster (BBL) - BGP L2VPN
 *
 * Christian Giese, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_L2VPN_H__
#define __BBL_BGP_L2VPN_H__

bool
bgp_l2vpn_init(bgp_session_s *session);

bool
bgp_l2vpn_update(bgp_session_s *session, bgp_update_s *update);

void
bgp_l2vpn_session_down(bgp_session_s *session);

bgp_l2vpn_entry_s *
bgp_l2vpn_lookup(uint8_t *rd, uint16_t ce_id, uint16_t local_ce_id);

bool
bgp_l2vpn_usable(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id);

uint32_t
bgp_l2vpn_label(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id);

bool
bgp_l2vpn_status_up(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id);

const char *
bgp_l2vpn_encap_string(uint8_t encap);

#endif
