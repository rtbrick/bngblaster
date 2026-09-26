/*
 * BNG Blaster (BBL) - TCP Authentication Option (RFC 5925/5926)
 * and legacy TCP MD5 Signature Option (RFC 2385)
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_TCP_AO_H__
#define __BBL_TCP_AO_H__

#include <stdbool.h>
#include <stdint.h>
#include "lwip/tcp.h"

/* TCP-AO option kind (RFC 5925): Kind + Length + KeyID + RNextKeyID + MAC */
#define TCP_AO_KIND         29
#define TCP_AO_HDR_LEN      4
/* Largest MAC length of all supported TCP-AO algorithms (HMAC-SHA-256-128) */
#define TCP_AO_MAX_MAC_LEN  16

/* Legacy TCP MD5 Signature Option (RFC 2385): Kind + Length + 16 byte digest */
#define TCP_MD5_KIND         19
#define TCP_MD5_HDR_LEN      2
#define TCP_MD5_DIGEST_LEN   16
#define TCP_MD5_OPT_LEN      (TCP_MD5_HDR_LEN + TCP_MD5_DIGEST_LEN)
/* TCP_MD5_OPT_LEN (18) is not a multiple of 4, but the TCP header's Data
 * Offset field can only express the header length in 4-byte words, so the
 * total option space must always be padded to one. Two leading NOPs (the
 * conventional placement other implementations use) bring it to 20. */
#define TCP_MD5_OPT_PAD_LEN  2
#define TCP_MD5_OPT_TOTAL_LEN (TCP_MD5_OPT_PAD_LEN + TCP_MD5_OPT_LEN)

typedef enum bbl_tcp_ao_algo_ {
    TCP_AO_ALGO_HMAC_SHA1_96 = 0,
    TCP_AO_ALGO_HMAC_SHA256_128,
    TCP_AO_ALGO_AES128_CMAC_96,
    TCP_AO_ALGO_MD5,
} bbl_tcp_ao_algo_t;

/*
 * TCP-AO/MD5 key material for a single static key (no key rollover /
 * multiple MKTs). key_id/rnext_key_id are ignored for TCP_AO_ALGO_MD5
 * (RFC 2385 has no KeyID field).
 */
typedef struct bbl_tcp_ao_key_ {
    uint8_t *key;
    uint16_t key_len;
    uint8_t  key_id;
    uint8_t  rnext_key_id;
    bbl_tcp_ao_algo_t algo;
} bbl_tcp_ao_key_s;

void
bbl_tcp_ao_init(void);

bool
bbl_tcp_ao_enable(struct tcp_pcb *pcb, bbl_tcp_ao_key_s *ao);

bool
bbl_tcp_ao_set_remote_isn(struct tcp_pcb *pcb, uint32_t remote_isn);

/* Lookup of the TCP-AO/MD5 key for a connection request received on a
 * shared listen socket, returns false if no key is configured. */
typedef bool (*bbl_tcp_ao_lookup_fn)(const ip_addr_t *local, const ip_addr_t *remote,
                                     bbl_tcp_ao_key_s *ao);

bool
bbl_tcp_ao_listen(struct tcp_pcb *lpcb, bbl_tcp_ao_lookup_fn lookup);

bool
bbl_tcp_ao_selftest(void);

bool
bbl_tcp_ao_algo_from_string(const char *s, bbl_tcp_ao_algo_t *algo);

const char *
bbl_tcp_ao_algo_string(bbl_tcp_ao_algo_t algo);

uint16_t
bbl_tcp_ao_min_key_len(bbl_tcp_ao_algo_t algo);

#endif
