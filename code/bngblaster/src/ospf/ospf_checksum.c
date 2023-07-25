/*
 * BNG Blaster (BBL) - OSPF Checksum
 * 
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX    4102 /* 5802 should be fine */

/**
 * ospf_checksum_fletcher16
 *
 * This function is based on the implementation from 
 * the famous FRR project (https://github.com/FRRouting/frr).
 * 
 * To be consistent, offset is 0-based index, rather than the 1-based 
 * index required in the specification ISO 8473, Annex C.1.
 */
uint16_t 
ospf_checksum_fletcher16(uint8_t *buf, uint16_t len, uint16_t offset)
{
    uint8_t *p;
    uint16_t *csum;
    int32_t x, y, c0, c1;
    uint32_t partial_len, i, left = len;

    p = buf;
    c0 = 0;
    c1 = 0;

    /* Zero the checksum in the packet. */
    csum = (uint16_t*)(buf + offset);
    *csum = 0;

    while (left != 0) {
        if(left < MODX) {
            partial_len = left;
        } else {
            partial_len = MODX;
        }
        for (i = 0; i < partial_len; i++) {
            c0 = c0 + *(p++);
            c1 += c0;
        }
        c0 = c0 % 255;
        c1 = c1 % 255;
        left -= partial_len;
    }

    /* The cast is important, to ensure the mod 
     * is taken as a signed value. */
    x = (int)((len - offset - 1) * c0 - c1) % 255;

    if(x <= 0) {
        x += 255;
    }
    y = 510 - c0 - x;
    if(y > 255) {
        y -= 255;
    }

    /* Now we write this to the packet.
     * We could skip this step too, since the checksum returned would
     * be stored into the checksum field by the caller. */
    buf[offset] = x;
    buf[offset + 1] = y;
    return htobe16((x << 8) | (y & 0xFF));
}