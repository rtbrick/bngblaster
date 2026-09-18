/*
 * BNG Blaster (BBL) - TCP Authentication Option (RFC 5925/5926)
 * and legacy TCP MD5 Signature Option (RFC 2385)
 *
 * Supported algorithms:
 *  - HMAC-SHA-1-96     (RFC 5926, TCP-AO option kind 29)
 *  - HMAC-SHA-256-128  (draft-ietf-tcpm-tcp-ao-algs, TCP-AO option kind 29)
 *  - AES-128-CMAC-96   (RFC 5926, TCP-AO option kind 29)
 *  - MD5               (RFC 2385, legacy TCP MD5 Signature option kind 19,
 *                        not TCP-AO: no KeyID/RNextKeyID, no KDF, no SNE)
 *
 * This module plugs into lwIP purely through the TX/RX hooks declared in
 * lwip/lwip_hooks.h (LWIP_HOOK_TCP_OUT_TCPOPT_LENGTH, LWIP_HOOK_TCP_OUT_ADD_TCPOPTS,
 * LWIP_HOOK_TCP_INPACKET_PCB) and lwIP's tcp_ext_arg mechanism for per-connection
 * state, so no vendored lwIP core file needs to be patched.
 *
 * Only a single static key (Master Key Tuple) per connection is supported, i.e.
 * no key rollover. Both the active-open (connect) and passive-open (listen/accept)
 * sides are exercised by BGP, using the Send/Receive x SYN/other key derivation
 * of the TCP-AO algorithms implemented generically per RFC 5925.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl_tcp_ao.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/ip.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdlib.h>

#include "logging.h"
#include "utils.h"

/* Largest traffic-key length of all supported TCP-AO KDFs (HKDF-SHA256) */
#define TCP_AO_MAX_TKEY_LEN 32
#define TCP_AO_MAX_CONTEXT  44 /* IPv6: 16+16+2+2+4+4 */
#define TCP_AO_MAX_MSG      2048

/* RFC 5926 3.1.1: generic KDF input is (i || Label || Context || Output_Length) */
#define TCP_AO_KDF_LABEL     "TCP-AO"
#define TCP_AO_KDF_LABEL_LEN 6

typedef enum bbl_tcp_ao_key_idx_ {
    TCP_AO_KEY_SEND_SYN = 0,
    TCP_AO_KEY_SEND_OTHER,
    TCP_AO_KEY_RECV_SYN,
    TCP_AO_KEY_RECV_OTHER,
    TCP_AO_KEY_MAX
} bbl_tcp_ao_key_idx_t;

typedef struct bbl_tcp_ao_sne_ {
    bool     have_prev;
    uint32_t prev_seq;
    uint32_t sne;
} bbl_tcp_ao_sne_s;

typedef struct bbl_tcp_ao_ctx_ {
    bbl_tcp_ao_algo_t algo;
    uint8_t  mac_len; /* wire MAC/digest length for this algo */

    uint8_t *master_key;
    uint16_t master_key_len;
    uint8_t  key_id;
    uint8_t  rnext_key_id;

    bool     have_local_isn;
    uint32_t local_isn;
    bool     have_remote_isn;
    uint32_t remote_isn;

    bool     have_key[TCP_AO_KEY_MAX];
    uint8_t  key[TCP_AO_KEY_MAX][TCP_AO_MAX_TKEY_LEN];

    bbl_tcp_ao_sne_s snd; /* SNE state for segments we send (TCP-AO only) */
    bbl_tcp_ao_sne_s rcv; /* SNE state for segments we receive (TCP-AO only) */
} bbl_tcp_ao_ctx_s;

static u8_t g_tcp_ao_ext_id = LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID;

/* --------------------------------------------------------------------- */
/* Algorithm metadata */

bool
bbl_tcp_ao_algo_from_string(const char *s, bbl_tcp_ao_algo_t *algo)
{
    if(strcmp(s, "hmac-sha-1-96") == 0) {
        *algo = TCP_AO_ALGO_HMAC_SHA1_96;
    } else if(strcmp(s, "hmac-sha-256-128") == 0) {
        *algo = TCP_AO_ALGO_HMAC_SHA256_128;
    } else if(strcmp(s, "aes-128-cmac-96") == 0) {
        *algo = TCP_AO_ALGO_AES128_CMAC_96;
    } else if(strcmp(s, "md5") == 0) {
        *algo = TCP_AO_ALGO_MD5;
    } else {
        return false;
    }
    return true;
}

const char *
bbl_tcp_ao_algo_string(bbl_tcp_ao_algo_t algo)
{
    switch(algo) {
        case TCP_AO_ALGO_HMAC_SHA1_96: return "hmac-sha-1-96";
        case TCP_AO_ALGO_HMAC_SHA256_128: return "hmac-sha-256-128";
        case TCP_AO_ALGO_AES128_CMAC_96: return "aes-128-cmac-96";
        case TCP_AO_ALGO_MD5: return "md5";
        default: return "unknown";
    }
}

uint16_t
bbl_tcp_ao_min_key_len(bbl_tcp_ao_algo_t algo)
{
    switch(algo) {
        case TCP_AO_ALGO_HMAC_SHA1_96: return 20;     /* RFC 5926 Key_Length: 160 bits */
        case TCP_AO_ALGO_HMAC_SHA256_128: return 32;  /* draft-ietf-tcpm-tcp-ao-algs: MUST be >= 256 bits */
        case TCP_AO_ALGO_AES128_CMAC_96: return 16;   /* RFC 5926 Key_Length: 128 bits */
        case TCP_AO_ALGO_MD5: return 1;               /* RFC 2385 defines no minimum */
        default: return 0;
    }
}

static uint8_t
tcp_ao_mac_len(bbl_tcp_ao_algo_t algo)
{
    switch(algo) {
        case TCP_AO_ALGO_HMAC_SHA1_96: return 12;
        case TCP_AO_ALGO_HMAC_SHA256_128: return 16;
        case TCP_AO_ALGO_AES128_CMAC_96: return 12;
        case TCP_AO_ALGO_MD5: return TCP_MD5_DIGEST_LEN;
        default: return 0;
    }
}

/* --------------------------------------------------------------------- */

static void
bbl_tcp_ao_destroy_cb(u8_t id, void *data)
{
    bbl_tcp_ao_ctx_s *ctx = data;
    (void)id;
    if(ctx) {
        if(ctx->master_key) {
            free(ctx->master_key);
        }
        free(ctx);
    }
}

static const struct tcp_ext_arg_callbacks bbl_tcp_ao_ext_callbacks = {
    .destroy = bbl_tcp_ao_destroy_cb,
    .passive_open = NULL,
};

static inline bbl_tcp_ao_ctx_s *
bbl_tcp_ao_get(const struct tcp_pcb *pcb)
{
    if(!pcb || g_tcp_ao_ext_id == LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID) {
        return NULL;
    }
    return (bbl_tcp_ao_ctx_s*)tcp_ext_arg_get(pcb, g_tcp_ao_ext_id);
}

/* --------------------------------------------------------------------- */

static uint8_t
tcp_ao_af(const struct tcp_pcb *pcb)
{
    return IP_IS_V6_VAL(pcb->local_ip) ? 6 : 4;
}

static const void *
tcp_ao_addr(const struct tcp_pcb *pcb, uint8_t af, bool local)
{
    const ip_addr_t *a = local ? &pcb->local_ip : &pcb->remote_ip;
    if(af == 6) {
        return ip_2_ip6(a)->addr;
    }
    return &ip_2_ip4(a)->addr;
}

/* Decodes TCP header flags (e.g. "SYN,ACK") for log messages. */
static const char *
tcp_ao_flags_string(uint8_t flags)
{
    static char buf[8][24];
    static int idx = 0;
    char *ret = buf[idx];
    idx = (idx + 1) & 7;

    ret[0] = '\0';
    if(flags & TCP_SYN) strcat(ret, ret[0] ? ",SYN" : "SYN");
    if(flags & TCP_ACK) strcat(ret, ret[0] ? ",ACK" : "ACK");
    if(flags & TCP_RST) strcat(ret, ret[0] ? ",RST" : "RST");
    if(flags & TCP_FIN) strcat(ret, ret[0] ? ",FIN" : "FIN");
    if(flags & TCP_PSH) strcat(ret, ret[0] ? ",PSH" : "PSH");
    if(!ret[0]) {
        strcpy(ret, "none");
    }
    return ret;
}

/* Formats "local:port - remote:port flags" for log messages, so RX
 * rejections can be told apart between the active-connect and
 * passive-accept paths, and what kind of segment was actually rejected. */
static const char *
tcp_ao_conn_string(const struct tcp_pcb *pcb, const struct tcp_hdr *hdr)
{
    static char buf[8][128];
    static int idx = 0;
    char *ret = buf[idx];
    idx = (idx + 1) & 7;

    if(tcp_ao_af(pcb) == 6) {
        snprintf(ret, sizeof(buf[0]), "[%s]:%u - [%s]:%u %s",
                  format_ipv6_address((ipv6addr_t*)tcp_ao_addr(pcb, 6, true)), pcb->local_port,
                  format_ipv6_address((ipv6addr_t*)tcp_ao_addr(pcb, 6, false)), pcb->remote_port,
                  tcp_ao_flags_string(TCPH_FLAGS(hdr)));
    } else {
        snprintf(ret, sizeof(buf[0]), "%s:%u - %s:%u %s",
                  format_ipv4_address((uint32_t*)tcp_ao_addr(pcb, 4, true)), pcb->local_port,
                  format_ipv4_address((uint32_t*)tcp_ao_addr(pcb, 4, false)), pcb->remote_port,
                  tcp_ao_flags_string(TCPH_FLAGS(hdr)));
    }
    return ret;
}

/*
 * RFC 5925 5.2 KDF Context. Also reused as the input to the (KDF-less)
 * RFC 2385 MD5 signature, which just needs the pseudo-header/header helpers
 * below, not this Context layout.
 */
static uint16_t
tcp_ao_context(uint8_t af, const void *src_addr, const void *dst_addr,
               uint16_t src_port, uint16_t dst_port,
               uint32_t src_isn, uint32_t dst_isn, uint8_t *out)
{
    uint16_t alen = (af == 6) ? 16 : 4;
    uint8_t *p = out;

    memcpy(p, src_addr, alen); p += alen;
    memcpy(p, dst_addr, alen); p += alen;
    write_be_uint(p, 2, src_port); p += 2;
    write_be_uint(p, 2, dst_port); p += 2;
    write_be_uint(p, 4, src_isn); p += 4;
    write_be_uint(p, 4, dst_isn); p += 4;
    return (uint16_t)(p - out);
}

/*
 * By the time our RX hooks run, lwip_tcp_input() has already converted
 * src/dest/seqno/ackno/wnd of the received header to host byte order in
 * place (tcp_in.c), but the MAC/digest must cover the header exactly as it
 * appeared on the wire (network byte order), matching what the sender
 * actually signed. Reconstruct that wire-order copy here; chksum is always
 * zeroed as required by RFC 5925/RFC 2385 regardless of byte order.
 */
static struct tcp_hdr
tcp_ao_wire_order_hdr(const struct tcp_hdr *hdr)
{
    struct tcp_hdr wire = *hdr;
    wire.src = lwip_htons(hdr->src);
    wire.dest = lwip_htons(hdr->dest);
    wire.seqno = lwip_htonl(hdr->seqno);
    wire.ackno = lwip_htonl(hdr->ackno);
    wire.wnd = lwip_htons(hdr->wnd);
    wire.chksum = 0;
    return wire;
}

/*
 * RFC 5925 5.1 / RFC 2385 pseudo-header (same layout as the standard TCP/IP
 * checksum pseudo-header for both address families).
 */
static uint16_t
tcp_ao_pseudo_header(uint8_t af, const void *src_addr, const void *dst_addr,
                      uint16_t tcp_len, uint8_t *out)
{
    uint8_t *p = out;

    if(af == 6) {
        memcpy(p, src_addr, 16); p += 16;
        memcpy(p, dst_addr, 16); p += 16;
        write_be_uint(p, 4, tcp_len); p += 4;
        *p++ = 0;
        *p++ = 0;
        *p++ = 0;
        *p++ = IP_PROTO_TCP;
    } else {
        memcpy(p, src_addr, 4); p += 4;
        memcpy(p, dst_addr, 4); p += 4;
        *p++ = 0;
        *p++ = IP_PROTO_TCP;
        write_be_uint(p, 2, tcp_len); p += 2;
    }
    return (uint16_t)(p - out);
}

/* --------------------------------------------------------------------- */
/* Crypto primitives */

static void
tcp_ao_hmac(const EVP_MD *md, const uint8_t *key, uint16_t key_len,
            const uint8_t *data, uint16_t data_len, uint8_t *out)
{
    HMAC_CTX *hmac = HMAC_CTX_new();
    HMAC_Init_ex(hmac, key, key_len, md, NULL);
    HMAC_Update(hmac, data, data_len);
    HMAC_Final(hmac, out, NULL);
    HMAC_CTX_free(hmac);
}

static void
tcp_ao_aes_cmac(const uint8_t key[16], const uint8_t *data, uint16_t data_len,
                uint8_t out[16])
{
    CMAC_CTX *cmac = CMAC_CTX_new();
    size_t out_len = 0;
    CMAC_Init(cmac, key, 16, EVP_aes_128_cbc(), NULL);
    CMAC_Update(cmac, data, data_len);
    CMAC_Final(cmac, out, &out_len);
    CMAC_CTX_free(cmac);
}

static void
tcp_md5_digest(const uint8_t *data, uint16_t data_len, uint8_t out[TCP_MD5_DIGEST_LEN])
{
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, data, data_len);
    MD5_Final(out, &md5_ctx);
}

/*
 * HKDF-SHA256 (RFC 5869) as used by TCP-AO HMAC-SHA-256-128
 * (draft-ietf-tcpm-tcp-ao-algs). L (output length) is 32 bytes, exactly one
 * SHA-256 block, so HKDF-Expand is a single HMAC iteration:
 * T(1) = HMAC(PRK, info || 0x01).
 */
static void
tcp_ao_kdf_hkdf_sha256(const uint8_t *master_key, uint16_t master_key_len,
                        const uint8_t *context, uint16_t context_len,
                        uint8_t traffic_key[32])
{
    uint8_t salt[32] = {0};
    uint8_t prk[32];
    uint8_t info[TCP_AO_MAX_CONTEXT + 1];

    tcp_ao_hmac(EVP_sha256(), salt, sizeof(salt), master_key, master_key_len, prk);

    memcpy(info, context, context_len);
    info[context_len] = 0x01;
    tcp_ao_hmac(EVP_sha256(), prk, sizeof(prk), info, (uint16_t)(context_len + 1), traffic_key);
}

/*
 * KDF_HMAC_SHA1 (RFC 5926 3.1.1.1): traffic_key = HMAC-SHA1(Master_Key,
 * i || Label || Context || Output_Length), i=1 (one octet), Label="TCP-AO",
 * Output_Length=160 (two octets, in bits). A single iteration produces the
 * full 160-bit Key_Length needed.
 */
static void
tcp_ao_kdf_hmac_sha1(const uint8_t *master_key, uint16_t master_key_len,
                      const uint8_t *context, uint16_t context_len,
                      uint8_t traffic_key[20])
{
    uint8_t input[1 + TCP_AO_KDF_LABEL_LEN + TCP_AO_MAX_CONTEXT + 2];
    uint8_t *p = input;

    *p++ = 0x01;
    memcpy(p, TCP_AO_KDF_LABEL, TCP_AO_KDF_LABEL_LEN); p += TCP_AO_KDF_LABEL_LEN;
    memcpy(p, context, context_len); p += context_len;
    write_be_uint(p, 2, 160); p += 2;

    tcp_ao_hmac(EVP_sha1(), master_key, master_key_len, input, (uint16_t)(p - input), traffic_key);
}

/*
 * KDF_AES_128_CMAC (RFC 5926 3.1.1.2): same (i || Label || Context ||
 * Output_Length) input as KDF_HMAC_SHA1 (Output_Length=128), but keyed with
 * AES-CMAC. If Master_Key is not exactly 128 bits, it is first compressed to
 * 128 bits via AES-CMAC with an all-zero key (Figure 1, steps 1/2).
 */
static void
tcp_ao_kdf_aes_cmac(const uint8_t *master_key, uint16_t master_key_len,
                     const uint8_t *context, uint16_t context_len,
                     uint8_t traffic_key[16])
{
    static const uint8_t zero_key[16] = {0};
    uint8_t derived_key[16];
    const uint8_t *k;
    uint8_t input[1 + TCP_AO_KDF_LABEL_LEN + TCP_AO_MAX_CONTEXT + 2];
    uint8_t *p = input;

    if(master_key_len == 16) {
        k = master_key;
    } else {
        tcp_ao_aes_cmac(zero_key, master_key, master_key_len, derived_key);
        k = derived_key;
    }

    *p++ = 0x01;
    memcpy(p, TCP_AO_KDF_LABEL, TCP_AO_KDF_LABEL_LEN); p += TCP_AO_KDF_LABEL_LEN;
    memcpy(p, context, context_len); p += context_len;
    write_be_uint(p, 2, 128); p += 2;

    tcp_ao_aes_cmac(k, input, (uint16_t)(p - input), traffic_key);
}

static void
tcp_ao_derive_key(bbl_tcp_ao_ctx_s *ctx, const uint8_t *context, uint16_t context_len,
                   uint8_t *traffic_key)
{
    switch(ctx->algo) {
        case TCP_AO_ALGO_HMAC_SHA256_128:
            tcp_ao_kdf_hkdf_sha256(ctx->master_key, ctx->master_key_len, context, context_len, traffic_key);
            break;
        case TCP_AO_ALGO_HMAC_SHA1_96:
            tcp_ao_kdf_hmac_sha1(ctx->master_key, ctx->master_key_len, context, context_len, traffic_key);
            break;
        case TCP_AO_ALGO_AES128_CMAC_96:
            tcp_ao_kdf_aes_cmac(ctx->master_key, ctx->master_key_len, context, context_len, traffic_key);
            break;
        default:
            break;
    }
}

/* MAC = MACalg(traffic_key, message), truncated to the leftmost mac_len bytes. */
static void
tcp_ao_compute_mac(bbl_tcp_ao_ctx_s *ctx, const uint8_t *tkey,
                    const uint8_t *msg, uint16_t msg_len, uint8_t *mac_out)
{
    uint8_t full[32];

    switch(ctx->algo) {
        case TCP_AO_ALGO_HMAC_SHA256_128:
            tcp_ao_hmac(EVP_sha256(), tkey, 32, msg, msg_len, full);
            break;
        case TCP_AO_ALGO_HMAC_SHA1_96:
            tcp_ao_hmac(EVP_sha1(), tkey, 20, msg, msg_len, full);
            break;
        case TCP_AO_ALGO_AES128_CMAC_96:
            tcp_ao_aes_cmac(tkey, msg, msg_len, full);
            break;
        default:
            memset(full, 0, sizeof(full));
            break;
    }
    memcpy(mac_out, full, ctx->mac_len);
}

/*
 * Lazily derive (and cache) the traffic key for this segment direction/kind.
 * Returns false if the ISN(s) required for the context are not known yet.
 */
static bool
tcp_ao_get_key(bbl_tcp_ao_ctx_s *ctx, const struct tcp_pcb *pcb,
               bool outbound, bool bare_syn, const uint8_t **key_out)
{
    uint8_t af = tcp_ao_af(pcb);
    bbl_tcp_ao_key_idx_t idx;
    uint8_t context[TCP_AO_MAX_CONTEXT];
    uint16_t context_len;
    const void *local_addr, *remote_addr;

    if(outbound) {
        idx = bare_syn ? TCP_AO_KEY_SEND_SYN : TCP_AO_KEY_SEND_OTHER;
    } else {
        idx = bare_syn ? TCP_AO_KEY_RECV_SYN : TCP_AO_KEY_RECV_OTHER;
    }

    if(ctx->have_key[idx]) {
        *key_out = ctx->key[idx];
        return true;
    }

    if(!ctx->have_local_isn || !ctx->have_remote_isn) {
        /* The special "bare SYN" context only ever needs the ISN of the
         * segment's own sender, the peer's is forced to 0. Any other segment
         * kind needs both ISNs. */
        if(!(bare_syn && ((outbound && ctx->have_local_isn) ||
                          (!outbound && ctx->have_remote_isn)))) {
            return false;
        }
    }

    local_addr = tcp_ao_addr(pcb, af, true);
    remote_addr = tcp_ao_addr(pcb, af, false);

    if(outbound) {
        context_len = tcp_ao_context(af, local_addr, remote_addr,
                                      pcb->local_port, pcb->remote_port,
                                      ctx->local_isn, bare_syn ? 0 : ctx->remote_isn,
                                      context);
    } else {
        context_len = tcp_ao_context(af, remote_addr, local_addr,
                                      pcb->remote_port, pcb->local_port,
                                      ctx->remote_isn, bare_syn ? 0 : ctx->local_isn,
                                      context);
    }

    tcp_ao_derive_key(ctx, context, context_len, ctx->key[idx]);
    ctx->have_key[idx] = true;
    *key_out = ctx->key[idx];
    return true;
}

/*
 * RFC 5925 6.2 sequence-number-extension tracking. SNE starts at 0 and is
 * incremented whenever the 32-bit sequence space wraps. `prev_seq` tracks the
 * highest sequence number observed so far (not simply the last one processed),
 * so retransmissions/reordering within the normal window never move it
 * backwards or falsely trigger a wrap. TCP_SEQ_GT is lwIP's own signed-delta
 * serial-number comparison (lwip/priv/tcp_priv.h), reused here so the notion
 * of "after" is identical to the one lwIP itself uses for sequence numbers.
 */
static uint32_t
tcp_ao_sne_update(bbl_tcp_ao_sne_s *st, uint32_t seq)
{
    if(!st->have_prev) {
        st->have_prev = true;
        st->prev_seq = seq;
        return st->sne;
    }
    if(TCP_SEQ_GT(seq, st->prev_seq)) {
        if(st->prev_seq > 0xC0000000u && seq < 0x40000000u) {
            /* prev_seq was near the top of the space and seq wrapped into the
             * bottom quarter: this is a genuine wraparound, not routine
             * forward progress. */
            st->sne++;
        }
        st->prev_seq = seq;
    }
    return st->sne;
}

/*
 * Same as tcp_ao_sne_update() but without committing: the updated state is
 * written to `next` for the caller to apply only once the segment has been
 * authenticated. Used on receive so an unauthenticated (e.g. spoofed or
 * off-path) segment cannot advance the SNE and lock out the real peer.
 */
static uint32_t
tcp_ao_sne_peek(const bbl_tcp_ao_sne_s *st, uint32_t seq, bbl_tcp_ao_sne_s *next)
{
    *next = *st;
    return tcp_ao_sne_update(next, seq);
}

/* --------------------------------------------------------------------- */
/* TCP-AO (RFC 5925): TX MAC compute / RX MAC verify */

static bool
tcp_ao_tx_mac(bbl_tcp_ao_ctx_s *ctx, const struct tcp_pcb *pcb,
              struct tcp_hdr *hdr, struct pbuf *p, uint8_t *mac_out)
{
    uint8_t af = tcp_ao_af(pcb);
    uint8_t flags = TCPH_FLAGS(hdr);
    bool bare_syn = (flags & TCP_SYN) && !(flags & TCP_ACK);
    const uint8_t *tkey;
    uint16_t hdr_len = TCPH_HDRLEN_BYTES(hdr);
    uint16_t payload_len = (uint16_t)(p->tot_len - hdr_len);
    uint16_t tcp_len = (uint16_t)p->tot_len;
    uint8_t msg[TCP_AO_MAX_MSG];
    uint8_t *m = msg;
    uint32_t sne;

    /* Bound the message buffer: 44 covers the 4-byte SNE plus the largest
     * (IPv6) pseudo-header. A segment we cannot sign is dropped rather than
     * sent unauthenticated (the caller leaves the MAC field zeroed). */
    if((size_t)hdr_len + payload_len + 44 > sizeof(msg)) {
        LOG(TCP, "TCP-AO (%s) segment too large to sign (%u bytes)\n",
            tcp_ao_conn_string(pcb, hdr), tcp_len);
        return false;
    }

    if(!tcp_ao_get_key(ctx, pcb, true, bare_syn, &tkey)) {
        return false;
    }

    sne = tcp_ao_sne_update(&ctx->snd, lwip_ntohl(hdr->seqno));

    write_be_uint(m, 4, sne);
    m += 4;
    m += tcp_ao_pseudo_header(af, tcp_ao_addr(pcb, af, true), tcp_ao_addr(pcb, af, false),
                               tcp_len, m);
    /* hdr+options as currently built: chksum already 0, our MAC placeholder
     * already 0 (written by the caller before this function runs). */
    memcpy(m, (uint8_t*)hdr, hdr_len);
    m += hdr_len;
    if(payload_len) {
        pbuf_copy_partial(p, m, payload_len, hdr_len);
        m += payload_len;
    }

    tcp_ao_compute_mac(ctx, tkey, msg, (uint16_t)(m - msg), mac_out);
    return true;
}

/* `opts` is the linearized option area (optlen bytes) with the TCP-AO MAC
 * field already zeroed by the caller. `p` contains only the TCP payload (per
 * the LWIP_HOOK_TCP_INPACKET_PCB contract). */
static bool
tcp_ao_rx_verify(bbl_tcp_ao_ctx_s *ctx, struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                  const uint8_t *opts, uint16_t optlen, struct pbuf *p,
                  const uint8_t *recv_mac)
{
    uint8_t af = tcp_ao_af(pcb);
    uint8_t flags = TCPH_FLAGS(hdr);
    bool bare_syn = (flags & TCP_SYN) && !(flags & TCP_ACK);
    const uint8_t *tkey;
    uint16_t hdr_len = (uint16_t)(sizeof(struct tcp_hdr) + optlen);
    uint16_t payload_len = p->tot_len;
    uint16_t tcp_len = (uint16_t)(hdr_len + payload_len);
    struct tcp_hdr hdr_copy;
    uint8_t msg[TCP_AO_MAX_MSG];
    uint8_t *m = msg;
    uint8_t mac[TCP_AO_MAX_MAC_LEN];
    uint32_t sne;
    bbl_tcp_ao_sne_s rcv_pending;

    /* The message buffer is fixed size and everything below it is attacker
     * controlled and NOT yet authenticated, so bound it first. 64 covers the
     * 4-byte SNE plus the largest (IPv6) pseudo-header and the fixed header. */
    if((size_t)optlen + payload_len + 64 > sizeof(msg)) {
        LOG(TCP, "TCP-AO (%s) segment too large to authenticate (%u bytes payload)\n",
            tcp_ao_conn_string(pcb, hdr), payload_len);
        return false;
    }

    if(!tcp_ao_get_key(ctx, pcb, false, bare_syn, &tkey)) {
        return false;
    }

    /* hdr->seqno is already host byte order here (converted in place by
     * lwip_tcp_input() before this hook runs), so no further ntohl needed.
     * The SNE state is only advanced once this segment has been
     * authenticated (see below), so a spoofed segment cannot desynchronise
     * it and lock out the genuine peer. */
    sne = tcp_ao_sne_peek(&ctx->rcv, hdr->seqno, &rcv_pending);

    hdr_copy = tcp_ao_wire_order_hdr(hdr);

    write_be_uint(m, 4, sne);
    m += 4;
    m += tcp_ao_pseudo_header(af, tcp_ao_addr(pcb, af, false), tcp_ao_addr(pcb, af, true),
                               tcp_len, m);
    memcpy(m, &hdr_copy, sizeof(hdr_copy));
    m += sizeof(hdr_copy);
    memcpy(m, opts, optlen);
    m += optlen;
    if(payload_len) {
        pbuf_copy_partial(p, m, payload_len, 0);
        m += payload_len;
    }

    tcp_ao_compute_mac(ctx, tkey, msg, (uint16_t)(m - msg), mac);
    if(memcmp(mac, recv_mac, ctx->mac_len) != 0) {
        return false;
    }
    /* Authentic: now it is safe to commit the receive SNE state. */
    ctx->rcv = rcv_pending;
    return true;
}

/* Scan a received segment's linearized options for the TCP-AO option, verify
 * its MAC and roll back any tentatively-learned peer ISN on any failure (see
 * comment below) so a spoofed/unauthenticated segment can never poison the
 * connection's long-term state. */
static err_t
tcp_ao_verify_segment(bbl_tcp_ao_ctx_s *ctx, struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                       uint8_t *opts, uint16_t optlen, struct pbuf *p)
{
    uint16_t o;
    uint8_t kind, len;
    uint16_t ao_off = 0;
    bool found = false;
    uint8_t recv_mac[TCP_AO_MAX_MAC_LEN];
    uint8_t recv_key_id = 0;
    bool learned_remote_isn = false;

    /* Tentatively learn the peer's ISN from the first SYN-flagged segment.
     * It is only committed (kept in ctx) once this very segment's MAC has
     * been verified below (see the failure path), so a spoofed/unauthenticated
     * segment can never poison the ISN used to key the rest of the connection. */
    if((TCPH_FLAGS(hdr) & TCP_SYN) && !ctx->have_remote_isn) {
        /* hdr->seqno is already host byte order here (converted in place by
         * lwip_tcp_input() before this hook runs), so no further ntohl needed. */
        ctx->remote_isn = hdr->seqno;
        ctx->have_remote_isn = true;
        learned_remote_isn = true;
    }

    o = 0;
    while((uint16_t)(o + 2u) <= optlen) {
        kind = opts[o];
        if(kind == 0) {
            break; /* end of option list */
        }
        if(kind == 1) {
            o += 1; /* NOP */
            continue;
        }
        len = opts[o + 1];
        if(len < 2 || (uint16_t)(o + len) > optlen) {
            break; /* malformed options */
        }
        if(kind == TCP_AO_KIND) {
            if(len != (uint16_t)(TCP_AO_HDR_LEN + ctx->mac_len)) {
                LOG(TCP, "TCP-AO (%s) option with unsupported length %u received\n",
                    tcp_ao_conn_string(pcb, hdr), len);
                goto reject;
            }
            ao_off = o;
            recv_key_id = opts[o + 2];
            memcpy(recv_mac, &opts[o + 4], ctx->mac_len);
            found = true;
            break;
        }
        o += len;
    }

    if(!found) {
        LOG(TCP, "TCP-AO (%s) required but missing on received segment\n",
            tcp_ao_conn_string(pcb, hdr));
        goto reject;
    }
    if(recv_key_id != ctx->key_id) {
        LOG(TCP, "TCP-AO (%s) KeyID mismatch (received %u, expected %u)\n",
            tcp_ao_conn_string(pcb, hdr), recv_key_id, ctx->key_id);
        goto reject;
    }

    memset(&opts[ao_off + 4], 0, ctx->mac_len);

    if(!tcp_ao_rx_verify(ctx, pcb, hdr, opts, optlen, p, recv_mac)) {
        LOG(TCP, "TCP-AO (%s) MAC verification failed\n", tcp_ao_conn_string(pcb, hdr));
        goto reject;
    }

    return ERR_OK;

reject:
    if(learned_remote_isn) {
        /* Roll back the tentative ISN and EVERY key derived from it so a
         * rejected segment cannot poison the connection's long-term state.
         * All four must be cleared, not just the "other" pair: verifying
         * this rejected segment already derived and cached the SYN key from
         * the bogus ISN, which would otherwise make every later genuine SYN
         * fail forever. */
        ctx->have_remote_isn = false;
        ctx->remote_isn = 0;
        memset(ctx->have_key, 0, sizeof(ctx->have_key));
    }
    return ERR_VAL;
}

/* --------------------------------------------------------------------- */
/* Legacy TCP MD5 Signature Option (RFC 2385). Unlike TCP-AO, the digest
 * input has no KDF/KeyID/SNE: the shared secret is used directly, and only
 * the fixed 20-byte TCP header (excluding all options) is covered. */

static bool
tcp_md5_tx_digest(bbl_tcp_ao_ctx_s *ctx, const struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                   struct pbuf *p, uint8_t digest_out[TCP_MD5_DIGEST_LEN])
{
    uint8_t af = tcp_ao_af(pcb);
    uint16_t hdr_len = TCPH_HDRLEN_BYTES(hdr); /* incl. all options, for pseudo-header length */
    uint16_t payload_len = (uint16_t)(p->tot_len - hdr_len);
    uint16_t tcp_len = (uint16_t)p->tot_len;
    struct tcp_hdr hdr_copy;
    uint8_t msg[TCP_AO_MAX_MSG];
    uint8_t *m = msg;

    /* 60 covers the largest (IPv6) pseudo-header plus the fixed 20-byte
     * header; the shared secret is appended too, so it counts as well. */
    if((size_t)payload_len + ctx->master_key_len + 60 > sizeof(msg)) {
        LOG(TCP, "TCP MD5 (%s) segment too large to sign (%u bytes)\n",
            tcp_ao_conn_string(pcb, hdr), tcp_len);
        return false;
    }

    hdr_copy = *hdr;
    hdr_copy.chksum = 0;

    m += tcp_ao_pseudo_header(af, tcp_ao_addr(pcb, af, true), tcp_ao_addr(pcb, af, false),
                               tcp_len, m);
    memcpy(m, &hdr_copy, sizeof(hdr_copy));
    m += sizeof(hdr_copy);
    if(payload_len) {
        pbuf_copy_partial(p, m, payload_len, hdr_len);
        m += payload_len;
    }
    memcpy(m, ctx->master_key, ctx->master_key_len);
    m += ctx->master_key_len;

    tcp_md5_digest(msg, (uint16_t)(m - msg), digest_out);
    return true;
}

static bool
tcp_md5_rx_verify(bbl_tcp_ao_ctx_s *ctx, struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                   uint16_t optlen, struct pbuf *p, const uint8_t *recv_digest)
{
    uint8_t af = tcp_ao_af(pcb);
    uint16_t hdr_len = (uint16_t)(sizeof(struct tcp_hdr) + optlen);
    uint16_t payload_len = p->tot_len;
    uint16_t tcp_len = (uint16_t)(hdr_len + payload_len);
    struct tcp_hdr hdr_copy;
    uint8_t msg[TCP_AO_MAX_MSG];
    uint8_t *m = msg;
    uint8_t digest[TCP_MD5_DIGEST_LEN];

    /* Bound the buffer before copying any unauthenticated wire data. */
    if((size_t)payload_len + ctx->master_key_len + 60 > sizeof(msg)) {
        LOG(TCP, "TCP MD5 (%s) segment too large to authenticate (%u bytes payload)\n",
            tcp_ao_conn_string(pcb, hdr), payload_len);
        return false;
    }

    hdr_copy = tcp_ao_wire_order_hdr(hdr);

    m += tcp_ao_pseudo_header(af, tcp_ao_addr(pcb, af, false), tcp_ao_addr(pcb, af, true),
                               tcp_len, m);
    memcpy(m, &hdr_copy, sizeof(hdr_copy));
    m += sizeof(hdr_copy);
    if(payload_len) {
        pbuf_copy_partial(p, m, payload_len, 0);
        m += payload_len;
    }
    memcpy(m, ctx->master_key, ctx->master_key_len);
    m += ctx->master_key_len;

    tcp_md5_digest(msg, (uint16_t)(m - msg), digest);
    return memcmp(digest, recv_digest, TCP_MD5_DIGEST_LEN) == 0;
}

static err_t
tcp_md5_verify_segment(bbl_tcp_ao_ctx_s *ctx, struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                        uint8_t *opts, uint16_t optlen, struct pbuf *p)
{
    uint16_t o = 0;
    uint8_t kind, len;
    bool found = false;
    uint8_t recv_digest[TCP_MD5_DIGEST_LEN];

    while((uint16_t)(o + 2u) <= optlen) {
        kind = opts[o];
        if(kind == 0) {
            break;
        }
        if(kind == 1) {
            o += 1;
            continue;
        }
        len = opts[o + 1];
        if(len < 2 || (uint16_t)(o + len) > optlen) {
            break;
        }
        if(kind == TCP_MD5_KIND) {
            if(len != TCP_MD5_OPT_LEN) {
                LOG(TCP, "TCP MD5 (%s) option with unsupported length %u received\n",
                    tcp_ao_conn_string(pcb, hdr), len);
                return ERR_VAL;
            }
            memcpy(recv_digest, &opts[o + 2], TCP_MD5_DIGEST_LEN);
            found = true;
            break;
        }
        o += len;
    }

    if(!found) {
        LOG(TCP, "TCP MD5 (%s) signature required but missing on received segment\n",
            tcp_ao_conn_string(pcb, hdr));
        return ERR_VAL;
    }

    if(!tcp_md5_rx_verify(ctx, pcb, hdr, optlen, p, recv_digest)) {
        LOG(TCP, "TCP MD5 (%s) signature verification failed\n", tcp_ao_conn_string(pcb, hdr));
        return ERR_VAL;
    }
    return ERR_OK;
}

/* --------------------------------------------------------------------- */
/* lwIP hooks (declared in lwip/lwip_hooks.h) */

u8_t
bbl_tcp_ao_hook_tcpopt_length(const struct tcp_pcb *pcb, u8_t internal_len)
{
    bbl_tcp_ao_ctx_s *ctx = bbl_tcp_ao_get(pcb);
    if(!ctx) {
        return internal_len;
    }
    if(ctx->algo == TCP_AO_ALGO_MD5) {
        return (u8_t)(internal_len + TCP_MD5_OPT_TOTAL_LEN);
    }
    return (u8_t)(internal_len + TCP_AO_HDR_LEN + ctx->mac_len);
}

u32_t *
bbl_tcp_ao_hook_add_tcpopts(struct pbuf *p, struct tcp_hdr *hdr,
                            const struct tcp_pcb *pcb, u32_t *opts)
{
    bbl_tcp_ao_ctx_s *ctx;
    uint8_t *o = (uint8_t*)opts;

    ctx = bbl_tcp_ao_get(pcb);
    if(!ctx) {
        return opts;
    }

    if(ctx->algo == TCP_AO_ALGO_MD5) {
        uint8_t digest[TCP_MD5_DIGEST_LEN];

        /* Two leading NOPs pad the total to a 4-byte boundary (see
         * TCP_MD5_OPT_TOTAL_LEN); they fall outside the option itself and
         * are excluded from the RFC 2385 digest, which only ever covered
         * the fixed 20-byte header, never any options. */
        o[0] = 0x01;
        o[1] = 0x01;
        o[2] = TCP_MD5_KIND;
        o[3] = TCP_MD5_OPT_LEN;
        memset(&o[4], 0, TCP_MD5_DIGEST_LEN);
        if(tcp_md5_tx_digest(ctx, pcb, hdr, p, digest)) {
            memcpy(&o[4], digest, TCP_MD5_DIGEST_LEN);
        }

        return (u32_t*)(void*)(o + TCP_MD5_OPT_TOTAL_LEN);
    }

    {
        uint8_t mac[TCP_AO_MAX_MAC_LEN];

        o[0] = TCP_AO_KIND;
        o[1] = (uint8_t)(TCP_AO_HDR_LEN + ctx->mac_len);
        o[2] = ctx->key_id;
        o[3] = ctx->rnext_key_id;
        memset(&o[4], 0, ctx->mac_len);

        if((TCPH_FLAGS(hdr) & TCP_SYN) && !ctx->have_local_isn) {
            ctx->local_isn = lwip_ntohl(hdr->seqno);
            ctx->have_local_isn = true;
        }

        if(tcp_ao_tx_mac(ctx, pcb, hdr, p, mac)) {
            memcpy(&o[4], mac, ctx->mac_len);
        }

        return (u32_t*)(void*)(o + TCP_AO_HDR_LEN + ctx->mac_len);
    }
}

err_t
bbl_tcp_ao_hook_inpacket_pcb(struct tcp_pcb *pcb, struct tcp_hdr *hdr,
                             u16_t optlen, u16_t opt1len, u8_t *opt2, struct pbuf *p)
{
    bbl_tcp_ao_ctx_s *ctx;
    uint8_t opts[TCP_MAX_OPTION_BYTES];

    ctx = bbl_tcp_ao_get(pcb);
    if(!ctx) {
        return ERR_OK;
    }

    if(optlen > sizeof(opts) || optlen < opt1len) {
        LOG(TCP, "TCP-AO (%s) received segment with invalid option length %u\n",
            tcp_ao_conn_string(pcb, hdr), optlen);
        return ERR_VAL;
    }

    memcpy(opts, (uint8_t*)(hdr + 1), opt1len);
    if(opt2 && optlen > opt1len) {
        memcpy(opts + opt1len, opt2, (size_t)(optlen - opt1len));
    }

    if(ctx->algo == TCP_AO_ALGO_MD5) {
        return tcp_md5_verify_segment(ctx, pcb, hdr, opts, optlen, p);
    }
    return tcp_ao_verify_segment(ctx, pcb, hdr, opts, optlen, p);
}

/* --------------------------------------------------------------------- */
/* Public API */

void
bbl_tcp_ao_init(void)
{
    if(g_tcp_ao_ext_id == LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID) {
        g_tcp_ao_ext_id = tcp_ext_arg_alloc_id();
    }
    if(!bbl_tcp_ao_selftest()) {
        LOG(ERROR, "TCP-AO/MD5 self-test failed\n");
    }
}

bool
bbl_tcp_ao_enable(struct tcp_pcb *pcb, bbl_tcp_ao_key_s *ao)
{
    bbl_tcp_ao_ctx_s *ctx;

    if(!pcb || !ao || !ao->key || !ao->key_len) {
        return false;
    }
    if(g_tcp_ao_ext_id == LWIP_TCP_PCB_NUM_EXT_ARG_ID_INVALID) {
        return false;
    }

    ctx = calloc(1, sizeof(bbl_tcp_ao_ctx_s));
    if(!ctx) {
        return false;
    }
    ctx->master_key = malloc(ao->key_len);
    if(!ctx->master_key) {
        free(ctx);
        return false;
    }
    memcpy(ctx->master_key, ao->key, ao->key_len);
    ctx->master_key_len = ao->key_len;
    ctx->algo = ao->algo;
    ctx->mac_len = tcp_ao_mac_len(ao->algo);
    ctx->key_id = ao->key_id;
    ctx->rnext_key_id = ao->rnext_key_id;

    tcp_ext_arg_set_callbacks(pcb, g_tcp_ao_ext_id, &bbl_tcp_ao_ext_callbacks);
    tcp_ext_arg_set(pcb, g_tcp_ao_ext_id, ctx);
    return true;
}

/*
 * For a passively-accepted connection, the peer's ISN is already known
 * (lwIP's tcp_listen_input() sets pcb->rcv_nxt = seqno + 1 before creating
 * the pcb) at the point bbl_tcp_ao_enable() is called on it (from a
 * "passive_open" hook, before the SYN-ACK is built), but that ISN was never
 * learned by tcp_ao_verify_segment()'s SYN-tracking logic, since the
 * original SYN was necessarily verified (if at all) against the *listen*
 * pcb, which has no per-connection ctx of its own. Without this, every
 * segment after the handshake fails verification, since tcp_ao_get_key()
 * for the non-bare-SYN "OTHER" traffic keys requires both ISNs to be known.
 * Must be called after bbl_tcp_ao_enable() on the same pcb.
 */
bool
bbl_tcp_ao_set_remote_isn(struct tcp_pcb *pcb, uint32_t remote_isn)
{
    bbl_tcp_ao_ctx_s *ctx = bbl_tcp_ao_get(pcb);
    if(!ctx) {
        return false;
    }
    ctx->remote_isn = remote_isn;
    ctx->have_remote_isn = true;
    return true;
}

/*
 * Known-answer tests for the 3 KDF-based algorithms, using the published
 * test vectors:
 *  - HMAC-SHA-256-128: draft-ietf-tcpm-tcp-ao-algs Appendix A.1.1.1
 *  - HMAC-SHA-1-96 and AES-128-CMAC-96: RFC 9235 sections 4.1.1 and 5.1.1
 * Exercises both the Context byte layout and each KDF's derivation. MD5
 * (RFC 2385) has no KDF and relies on the well-known/independently-verified
 * OpenSSL MD5 implementation, so it has no dedicated vector here.
 */
bool
bbl_tcp_ao_selftest(void)
{
    bool ok = true;
    static const uint8_t src_addr[4] = {0x0a, 0x0b, 0x0c, 0x0d};
    static const uint8_t dst_addr[4] = {0xac, 0x1b, 0x1c, 0x1d};
    uint8_t context[20];
    uint16_t context_len;

    {
        static const uint8_t master_key[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        };
        static const uint8_t expected_key[32] = {
            0xeb, 0x5a, 0x40, 0x32, 0xe9, 0x3e, 0x6c, 0x78,
            0x02, 0xa7, 0x41, 0xac, 0x89, 0x9a, 0x63, 0x12,
            0xd3, 0x46, 0xa9, 0xdc, 0x1d, 0x2b, 0xed, 0x62,
            0xe2, 0xb6, 0xde, 0x94, 0x7f, 0x6c, 0x5c, 0x7d
        };
        uint8_t traffic_key[32];

        context_len = tcp_ao_context(4, src_addr, dst_addr, 0xe9d7, 0x00b3,
                                      0xfbfbab5a, 0, context);
        tcp_ao_kdf_hkdf_sha256(master_key, sizeof(master_key), context, context_len, traffic_key);
        if(context_len != sizeof(context) || memcmp(traffic_key, expected_key, sizeof(expected_key)) != 0) {
            LOG(ERROR, "TCP-AO self-test failed for hmac-sha-256-128\n");
            ok = false;
        }
    }

    {
        static const uint8_t master_key[] = "testvector";
        static const uint8_t expected_key[20] = {
            0x6d, 0x63, 0xef, 0x1b, 0x02, 0xfe, 0x15, 0x09, 0xd4, 0xb1,
            0x40, 0x27, 0x07, 0xfd, 0x7b, 0x04, 0x16, 0xab, 0xb7, 0x4f
        };
        uint8_t traffic_key[20];

        context_len = tcp_ao_context(4, src_addr, dst_addr, 0xe9d7, 0x00b3,
                                      0xfbfbab5a, 0, context);
        tcp_ao_kdf_hmac_sha1(master_key, sizeof(master_key) - 1, context, context_len, traffic_key);
        if(context_len != sizeof(context) || memcmp(traffic_key, expected_key, sizeof(expected_key)) != 0) {
            LOG(ERROR, "TCP-AO self-test failed for hmac-sha-1-96\n");
            ok = false;
        }
    }

    {
        static const uint8_t master_key[] = "testvector";
        static const uint8_t expected_key[16] = {
            0xf5, 0xb8, 0xb3, 0xd5, 0xf3, 0x4f, 0xdb, 0xb6,
            0xeb, 0x8d, 0x4a, 0xb9, 0x66, 0x0e, 0x60, 0xe3
        };
        uint8_t traffic_key[16];

        context_len = tcp_ao_context(4, src_addr, dst_addr, 0xc4fa, 0x00b3,
                                      0x787a1ddf, 0, context);
        tcp_ao_kdf_aes_cmac(master_key, sizeof(master_key) - 1, context, context_len, traffic_key);
        if(context_len != sizeof(context) || memcmp(traffic_key, expected_key, sizeof(expected_key)) != 0) {
            LOG(ERROR, "TCP-AO self-test failed for aes-128-cmac-96\n");
            ok = false;
        }
    }

    return ok;
}
