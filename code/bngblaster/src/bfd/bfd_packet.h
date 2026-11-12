/*
 * BNG Blaster (BBL) - BFD Packet Encoding and Authentication
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_BFD_PACKET_H__
#define __BBL_BFD_PACKET_H__

uint8_t
bfd_auth_len(uint8_t auth_type, uint8_t key_len);

bool
bfd_auth_meticulous(uint8_t auth_type);

uint16_t
bfd_packet_encode(uint8_t *buf, bbl_bfd_s *bfd, uint32_t auth_seq,
                  const uint8_t *key, uint8_t key_len);

bool
bfd_packet_valid(bbl_bfd_s *bfd);

bool
bfd_packet_auth_verify(bbl_bfd_s *bfd, uint8_t auth_type, uint8_t key_id,
                       const uint8_t *key, uint8_t key_len, uint32_t *seq);

bool
bfd_auth_seq_check(uint8_t auth_type, bool known, uint32_t last,
                   uint32_t seq, uint8_t detect_mult);

const char *
bfd_state_string(uint8_t state);

const char *
bfd_diag_string(uint8_t diag);

const char *
bfd_auth_type_string(uint8_t auth_type);

#endif
