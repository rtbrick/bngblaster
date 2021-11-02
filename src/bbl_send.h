/*
 * BNG Blaster (BBL) - Send Functions
 *
 * This interface allows to "directly" send
 * packets to an interface. 
 * 
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_TXQ_H__
#define __BBL_TXQ_H__

#define BBL_SEND_DEFAULT_SIZE 2048

typedef enum bbl_send_result_ {
    BBL_SEND_OK = 0,
    BBL_SEND_ENCODE_ERROR,
    BBL_SEND_FULL
} bbl_send_result_t;

typedef struct bbl_send_slot_ {
    uint8_t packet[IO_BUFFER_LEN];
    uint16_t packet_len;
} bbl_send_slot_t;

bool
bbl_send_init_interface(bbl_interface_s *interface, uint16_t slots);

bool
bbl_send_is_empty(bbl_interface_s *interface);

bool
bbl_send_is_full(bbl_interface_s *interface);

uint16_t
bbl_send_from_buffer(bbl_interface_s *interface, uint8_t *buf);

bbl_send_result_t
bbl_send_to_buffer(bbl_interface_s *interface, bbl_ethernet_header_t *eth);

bbl_send_result_t 
bbl_send_arp_reply(bbl_interface_s *interface,
                   bbl_session_s *session,
                   bbl_ethernet_header_t *eth, 
                   bbl_arp_t *arp);

bbl_send_result_t 
bbl_send_icmpv6_na(bbl_interface_s *interface,
                   bbl_session_s *session,
                   bbl_ethernet_header_t *eth, 
                   bbl_ipv6_t *ipv6, 
                   bbl_icmpv6_t *icmpv6);

bbl_send_result_t 
bbl_send_icmp_reply(bbl_interface_s *interface,
                    bbl_session_s *session,
                    bbl_ethernet_header_t *eth, 
                    bbl_ipv4_t *ipv4, 
                    bbl_icmp_t *icmp);

bbl_send_result_t 
bbl_send_icmpv6_echo_reply(bbl_interface_s *interface,
                           bbl_session_s *session,
                           bbl_ethernet_header_t *eth, 
                           bbl_ipv6_t *ipv6, 
                           bbl_icmpv6_t *icmpv6);

#endif