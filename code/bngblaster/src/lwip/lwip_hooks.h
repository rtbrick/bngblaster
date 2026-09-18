/*
 * BNG Blaster (BBL) - LwIP Hooks
 *
 * Wires the TCP-AO (RFC 5925) TX/RX hook points into bbl_tcp_ao.c. Included
 * via LWIP_HOOK_FILENAME from several otherwise unrelated lwIP core files,
 * so this header must stay self-contained (only forward declarations plus
 * lightweight lwIP arch/err headers) rather than relying on TCP-specific
 * headers already being included by the including file.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __LWIP_HOOKS_H__
#define __LWIP_HOOKS_H__

#include "lwip/arch.h"
#include "lwip/err.h"

struct tcp_pcb;
struct tcp_hdr;
struct pbuf;

u8_t
bbl_tcp_ao_hook_tcpopt_length(const struct tcp_pcb *pcb, u8_t internal_len);

u32_t *
bbl_tcp_ao_hook_add_tcpopts(struct pbuf *p, struct tcp_hdr *hdr,
                            const struct tcp_pcb *pcb, u32_t *opts);

err_t
bbl_tcp_ao_hook_inpacket_pcb(struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                             u16_t optlen, u16_t opt1len, u8_t *opt2, struct pbuf *p);

#define LWIP_HOOK_TCP_OUT_TCPOPT_LENGTH(pcb, internal_len) \
    bbl_tcp_ao_hook_tcpopt_length(pcb, internal_len)

#define LWIP_HOOK_TCP_OUT_ADD_TCPOPTS(p, hdr, pcb, opts) \
    bbl_tcp_ao_hook_add_tcpopts(p, hdr, pcb, opts)

#define LWIP_HOOK_TCP_INPACKET_PCB(pcb, hdr, optlen, opt1len, opt2, p) \
    bbl_tcp_ao_hook_inpacket_pcb(pcb, hdr, optlen, opt1len, opt2, p)

#endif
