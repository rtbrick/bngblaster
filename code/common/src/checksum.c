/*
 * Checksum Library
 *
 * Hannes Gredler, February 2024
 * Christian Giese, October 2024
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "checksum.h"

/**
 * @brief validate_fletcher_checksum
 * 
 * Fletcher checksum verification. should return 0 if embedded checksum is correct.
 * Only used for debug purposes here.
 */
uint16_t
validate_fletcher_checksum(const uint8_t *pptr, uint length)
{

    uint64_t c0, c1;
    uint idx;

    c0 = 0;
    c1 = 0;

    for(idx = 0; idx < length; idx++) {
        c0 = c0 + *(pptr++);
        c1 += c0;
    }

    c0 = c0 % 255;
    c1 = c1 % 255;

    return (c1 << 8 | c0);
}

/**
 * @brief calculate_fletcher_checksum
 * 
 * Creates the OSI Fletcher checksum. See 8473-1, Appendix C, section C.3.
 * The checksum field of the passed PDU does not need to be reset to zero.
 */
uint16_t
calculate_fletcher_checksum(uint8_t *pptr, uint checksum_offset, uint length)
{
    int64_t c0, c1;
    int tlen;

    c0 = 0;
    c1 = 0;

    /* reset checksum field */
    *(pptr + checksum_offset) = 0;
    *(pptr + checksum_offset + 1) = 0;

    /* 10x loop unrolling */
    tlen = length;
    while(tlen >= 10) {
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;
        c0 += *pptr++;
        c1 += c0;

        tlen -= 10;
    }

    /* remainder */
    while (--tlen >= 0) {
        c0 += *pptr++;
        c1 += c0;
    }

    c0 = c0 % 255;
    c1 = (c1 - (length - checksum_offset) * c0) % 255;
    if (c1 <= 0) {
        c1 += 255;
    }

    c0 = 255 - c1 - c0;
    if (c0 <= 0 ) {
        c0 += 255;
    }

    return (c0 << 8 | c1);
}
