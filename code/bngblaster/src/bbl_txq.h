/*
 * BNG Blaster (BBL) - TXQ Functions
 *
 * This interface allows to "directly" send
 * packets via ring buffer.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_TXQ_H__
#define __BBL_TXQ_H__

#define BBL_TXQ_DEFAULT_SIZE 4096
#define BBL_TXQ_BUFFER_LEN 4074

typedef enum bbl_ring_result_ {
    BBL_TXQ_OK = 0,
    BBL_TXQ_ENCODE_ERROR,
    BBL_TXQ_FULL
} bbl_txq_result_t;

typedef struct bbl_txq_slot_ {
    struct timespec timestamp;
    uint16_t vlan_tci;
    uint16_t vlan_tpid;
    uint16_t packet_len;
    uint8_t packet[BBL_TXQ_BUFFER_LEN];
} bbl_txq_slot_t;

typedef struct bbl_txq_ {
    bbl_txq_slot_t *ring; /* ring buffer */
    uint16_t size; /* number of send slots */

    char _pad0 __attribute__((__aligned__(CACHE_LINE_SIZE))); /* empty cache line */

    atomic_uint_least16_t write; /* current write slot */
    atomic_uint_least16_t next; /* next write slot */
    struct {
        uint32_t full; 
        uint32_t encode_error;
    } stats;

    char _pad1 __attribute__((__aligned__(CACHE_LINE_SIZE))); /* empty cache line */

    atomic_uint_least16_t read; /* current read slot */
} bbl_txq_s;

bool
bbl_txq_init(bbl_txq_s *txq, uint16_t slots);

bool
bbl_txq_is_empty(bbl_txq_s *txq);

bool
bbl_txq_is_full(bbl_txq_s *txq);

uint16_t
bbl_txq_from_buffer(bbl_txq_s *txq, uint8_t *buf);

bbl_txq_result_t
bbl_txq_to_buffer(bbl_txq_s *txq, bbl_ethernet_header_s *eth);

bbl_txq_slot_t *
bbl_txq_read_slot(bbl_txq_s *txq);

void
bbl_txq_read_next(bbl_txq_s *txq);

bbl_txq_slot_t *
bbl_txq_write_slot(bbl_txq_s *txq);

void
bbl_txq_write_next(bbl_txq_s *txq);

#endif