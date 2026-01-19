/*
 * BNG Blaster (BBL) - LI Functions
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
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
    uint64_t     packets_rx_bbl;
    uint64_t     packets_rx_ipv4;
    uint64_t     packets_rx_ipv4_tcp;
    uint64_t     packets_rx_ipv4_udp;
    uint64_t     packets_rx_ipv4_internal;
    uint64_t     packets_rx_ipv6;
    uint64_t     packets_rx_ipv6_tcp;
    uint64_t     packets_rx_ipv6_udp;
    uint64_t     packets_rx_ipv6_internal;
    uint64_t     packets_rx_ipv6_no_next_header;
} bbl_li_flow_t;

void 
bbl_qmx_li_handler_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_qmx_li_s *qmx_li);

int
bbl_li_ctrl_flows(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)));

#endif