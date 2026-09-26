/*
 * BNG Blaster (BBL) - BGP EVPN
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BGP_EVPN_H__
#define __BBL_BGP_EVPN_H__

bool
bgp_evpn_init(bgp_session_s *session);

bool
bgp_evpn_update(bgp_session_s *session, bgp_update_s *update);

void
bgp_evpn_session_down(bgp_session_s *session);

bgp_evpn_entry_s *
bgp_evpn_lookup(bgp_evpn_key_s *key);

bool
bgp_evpn_scan_rd(const char *str, uint8_t *rd);

char *
bgp_evpn_format_rd(uint8_t *rd);

bool
bgp_evpn_scan_esi(const char *str, uint8_t *esi);

char *
bgp_evpn_format_esi(uint8_t *esi);

char *
bgp_evpn_format_rt(uint8_t *rt);

const char *
bgp_evpn_encap_string(uint16_t encap);

void
bgp_evpn_mask_ip(uint8_t *ip, uint8_t af, uint8_t len);

#endif
