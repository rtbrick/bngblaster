/*
 * BNG Blaster (BBL) - LI Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_LI_H__
#define __BBL_LI_H__

typedef struct bbl_interface_ bbl_interface_s;

typedef struct bbl_li_flow_
{
    uint32_t     src_ipv4;
    uint32_t     dst_ipv4;
    uint32_t     src_port;
    uint32_t     dst_port;

    uint8_t      direction;
    uint8_t      packet_type;
    uint8_t      sub_packet_type;
    uint32_t     liid;

    uint64_t     packets_rx;
    uint64_t     bytes_rx;
    uint64_t     packets_rx_ipv4;
    uint64_t     packets_rx_ipv4_tcp;
    uint64_t     packets_rx_ipv4_udp;
    uint64_t     packets_rx_ipv4_internal;
} bbl_li_flow_t;

const char* bbl_li_direction_string(uint8_t direction);
const char* bbl_li_packet_type_string(uint8_t packet_type);
const char* bbl_li_sub_packet_type_string(uint8_t sub_packet_type);

void bbl_qmx_li_handler_rx(bbl_ethernet_header_t *eth, bbl_qmx_li_t *qmx_li, bbl_interface_s *interface);

#endif