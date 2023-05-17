/*
 * BNG Blaster (BBL) - OSPF PDU
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_PDU_H__
#define __BBL_OSPF_PDU_H__

protocol_error_t
ospf_pdu_load(bbl_pdu_s *pdu, uint8_t *buf, uint16_t len);

#endif