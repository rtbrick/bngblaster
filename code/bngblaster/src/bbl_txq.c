/*
 * BNG Blaster (BBL) - BBL RING Functions
 * 
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_session.h"

bool
bbl_txq_init(bbl_txq_s *txq, uint16_t size)
{
    txq->ring = calloc(1, size * sizeof(bbl_txq_slot_t));
    if(!txq->ring) {
        return false;
    }
    txq->size   = size;
    txq->read   = 0;
    txq->write  = 0;
    txq->next   = 1;
    return true;
}

bool
bbl_txq_is_empty(bbl_txq_s *txq)
{
    if(txq->read == txq->write) {
        return true;
    }
    return false;
}

bool
bbl_txq_is_full(bbl_txq_s *txq)
{
    if(txq->read == txq->next) {
        return true;
    }
    return false;
}

/**
 * @brief Receive packet from TXQ 
 * and copy to target buffer (buf).
 *
 * @param txq TXQ
 * @param buf target buffer
 * @return number of bytes copied
 */
uint16_t
bbl_txq_from_buffer(bbl_txq_s *txq, uint8_t *buf)
{
    bbl_txq_slot_t *slot;

    if(txq->read == txq->write) {
        /* Empty! */
        return 0;
    }

    slot = txq->ring + txq->read;
    memcpy(buf, slot->packet, slot->packet_len);

    txq->read++;
    if(txq->read == txq->size) {
        txq->read = 0;
    }
    return slot->packet_len;
}

/**
 * @brief Encode packet to TXQ.
 *
 * @param txq TXQ
 * @param eth ethernet structure
 * @return bbl_txq_result_t
 */
bbl_txq_result_t
bbl_txq_to_buffer(bbl_txq_s *txq, bbl_ethernet_header_s *eth)
{
    bbl_txq_slot_t *slot;

    if(txq->read == txq->next) {
        txq->stats.full++;
        return BBL_TXQ_FULL;
    }
    slot = txq->ring + txq->write;
    slot->packet_len = 0;
    if(encode_ethernet(slot->packet, &slot->packet_len, eth) == PROTOCOL_SUCCESS) {
        txq->write = txq->next++;
        if(txq->next == txq->size) {
            txq->next = 0;
        }
        return BBL_TXQ_OK;
    } else {
        txq->stats.encode_error++;
        return BBL_TXQ_ENCODE_ERROR;
    }
}

bbl_txq_slot_t *
bbl_txq_read_slot(bbl_txq_s *txq)
{
    if(txq->read == txq->write) {
        return NULL;
    }
    return txq->ring + txq->read;
}

void
bbl_txq_read_next(bbl_txq_s *txq) 
{
    txq->read++;
    if(txq->read == txq->size) {
        txq->read = 0;
    }
}

bbl_txq_slot_t *
bbl_txq_write_slot(bbl_txq_s *txq)
{
    if(txq->read == txq->next) {
        txq->stats.full++;
        return NULL;
    }

    return txq->ring + txq->write;
}

void
bbl_txq_write_next(bbl_txq_s *txq) 
{
    txq->write = txq->next++;
    if(txq->next == txq->size) {
        txq->next = 0;
    }
}