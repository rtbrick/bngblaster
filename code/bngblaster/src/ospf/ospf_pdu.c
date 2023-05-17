/*
 * BNG Blaster (BBL) - OSPF PDU
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

protocol_error_t
ospf_pdu_load(bbl_pdu_s *pdu, uint8_t *buf, uint16_t len)
{
    UNUSED(pdu);
    UNUSED(buf);
    UNUSED(len);

    /* Reset cursor and return */
    PDU_CURSOR_RST(pdu);
    return PROTOCOL_SUCCESS;
}