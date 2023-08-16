/*
 * BNG Blaster (BBL) - IS-IS P2P Hello
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

/**
 * ospf_hello_v2_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ospf_hello_v2_encode(bbl_network_interface_s *interface, 
                     uint8_t *buf, uint16_t *len, 
                     bbl_ethernet_header_s *eth)
{
    UNUSED(interface);
    UNUSED(buf);
    UNUSED(len);
    UNUSED(eth);
    return PROTOCOL_SUCCESS;
}

/**
 * ospf_hello_v3_encode
 *
 * @param interface send interface
 * @param buf send buffer
 * @param len send buffer length
 * @param eth send ethernet parent structure
 * @return PROTOCOL_SUCCESS on success
 */
protocol_error_t
ospf_hello_v3_encode(bbl_network_interface_s *interface, 
                     uint8_t *buf, uint16_t *len, 
                     bbl_ethernet_header_s *eth)
{
    UNUSED(interface);
    UNUSED(buf);
    UNUSED(len);
    UNUSED(eth);
    return PROTOCOL_SUCCESS;
}

/**
 * ospf_hello_handler_rx
 *
 * @param interface receive interface
 * @param pdu received OSPF PDU
 */
void
ospf_hello_handler_rx(bbl_network_interface_s *interface,
                      ospf_pdu_s *pdu)
{
    UNUSED(interface);
    UNUSED(pdu);
}