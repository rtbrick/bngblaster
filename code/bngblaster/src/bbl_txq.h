/*
 * BNG Blaster (BBL) - TXQ Functions
 *
 * This interface allows to "directly" send
 * packets via ring buffer.
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_TXQ_H__
#define __BBL_TXQ_H__

#define BBL_TXQ_DEFAULT_SIZE 4096
#define BBL_TXQ_BUFFER_LEN 4092

typedef enum bbl_ring_result_ {
    BBL_TXQ_OK = 0,
    BBL_TXQ_ENCODE_ERROR,
    BBL_TXQ_FULL
} bbl_txq_result_t;

typedef struct bbl_txq_slot_ {
    uint16_t packet_len;
    uint8_t packet[BBL_TXQ_BUFFER_LEN];
} bbl_txq_slot_t;

typedef struct bbl_txq_ {
    bbl_txq_slot_t *ring; /* ring buffer */
    uint16_t size;  /* number of send slots */
    uint16_t read;  /* current read slot */
    uint16_t write; /* current write slot */
    uint16_t next;  /* next write slot */
    struct {
        uint32_t full; 
        uint32_t encode_error;
    } stats;
} bbl_txq_t;

bool
bbl_txq_init(bbl_txq_t *txq, uint16_t slots);

bool
bbl_txq_is_empty(bbl_txq_t *txq);

bool
bbl_txq_is_full(bbl_txq_t *txq);

uint16_t
bbl_txq_from_buffer(bbl_txq_t *txq, uint8_t *buf);

bbl_txq_result_t
bbl_txq_to_buffer(bbl_txq_t *txq, bbl_ethernet_header_t *eth);

#endif