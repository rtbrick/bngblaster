/*
 * Common Defines
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __COMMON_H__
#define __COMMON_H__

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <arpa/inet.h>

/* Common Definitions */

#define ETH_ADDR_LEN                6
#define IPV4_ADDR_LEN               4
#define IPV6_ADDR_LEN               16
#define ISO_ADDR_LEN                20

#define MAC_STR_LEN                 sizeof("00:00:00:00:00:00")
#define IPV4_DOTTED_STR_LEN         sizeof("255.255.255.255")
#define IPV4_DOTTED_PREFIX_STR_LEN  sizeof("255.255.255.255/32")
#define IPV6_STR_LEN                sizeof("0000:0000:0000:0000:0000:0000:0000:0000")
#define IPV6_PREFIX_STR_LEN         sizeof("0000:0000:0000:0000:0000:0000:0000:0000/128")
#define ISO_STR_LEN                 64
#define SUB_STR_LEN                 256

/* Macro Definitions */

#define BITS_TO_BYTES(_len) ((_len+7) >> 3)
#define UNUSED(x)    (void)x

/* Key-Value structure. */
typedef struct keyval_ {
    uint32_t val;    /* value */
    const char *key; /* key */
} keyval_t;

/* Reusable data structure for 
 * reading and writing data */
typedef struct io_buffer_ {
    uint8_t *data;
    uint32_t start_idx;
    uint32_t idx; /* end idx */
    uint32_t size;
} io_buffer_t;

/* Address Types */

typedef uint32_t ipv4addr_t;

typedef struct ipv4_prefix_ {
    uint8_t         len;
    ipv4addr_t      address;
} ipv4_prefix;

typedef uint8_t ipv6addr_t[IPV6_ADDR_LEN];

typedef struct ipv6_prefix_ {
    uint8_t         len;
    ipv6addr_t      address;
} ipv6_prefix;

typedef uint8_t iso_addr_t[ISO_ADDR_LEN];

typedef struct iso_prefix_ {
    uint8_t         len;
    iso_addr_t      address;
} iso_prefix;

#endif