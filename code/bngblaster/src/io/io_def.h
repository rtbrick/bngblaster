/*
 * BNG Blaster (BBL) - IO Definitions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_DEF_H__
#define __BBL_IO_DEF_H__

#define IO_TOKENS_PER_PACKET 1000

typedef struct io_handle_ io_handle_s;
typedef struct io_thread_ io_thread_s;

typedef enum io_result_ {
    IO_SUCCESS,
    IO_REDIRECT,
    IO_ERROR,
    IO_DECODE_ERROR,
    IO_ENCODE_ERROR,
    IO_FULL,
    IO_EMPTY
} __attribute__ ((__packed__)) io_result_t;

typedef enum {
    IO_DISABLED = 0,
    IO_INGRESS  = 1,
    IO_EGRESS   = 2,
    IO_DUPLEX   = 3
} __attribute__ ((__packed__)) io_direction_t;

typedef enum {
    IO_MODE_DISABLED = 0,
    IO_MODE_PACKET_MMAP_RAW,    /* packet_mmap ring (RX) and raw sockets (TX) */
    IO_MODE_PACKET_MMAP,        /* packet_mmap ring */
    IO_MODE_RAW,                /* raw sockets */
    IO_MODE_DPDK,               /* DPDK */
    IO_MODE_AF_XDP              /* AF_XDP */
} __attribute__ ((__packed__)) io_mode_t;

typedef struct io_bucket_ {
    double pps;
    uint64_t nsec;
    uint64_t base;

    struct io_bucket_ *next;

    bbl_stream_s *stream_head;
    bbl_stream_s *stream_cur;
    uint32_t stream_count;
} io_bucket_s;

typedef struct io_handle_ {
    io_mode_t mode;
    io_direction_t direction;

    int id;
    int fd;
    int fanout_id;
    int fanout_type;
    struct tpacket_req req;
    struct sockaddr_ll addr;

    volatile bool update_streams;

#ifdef BNGBLASTER_DPDK
    struct rte_eth_dev_tx_buffer *tx_buffer;
    struct rte_mempool *mbuf_pool;
    struct rte_mbuf *mbuf;
    uint16_t queue;
#endif

    uint8_t *ring; /* ring buffer */
    unsigned int cursor; /* ring buffer cursor */
    unsigned int queued;

    io_thread_s *thread;

    io_bucket_s *bucket_head;
    io_bucket_s *bucket_cur;

    bbl_interface_s *interface;
    bbl_ethernet_header_s *eth;

    uint8_t *buf;
    uint16_t buf_len;
    uint16_t vlan_tci;
    uint16_t vlan_tpid;

    uint32_t stream_count;
    double stream_pps;
    
    struct timespec timestamp; /* user space timestamps */

    struct {
        uint64_t packets;
        uint64_t bytes;
        uint64_t unknown;
        uint64_t protocol_errors;
        uint64_t io_errors;
        uint64_t to_long;
        uint64_t no_buffer;
        uint64_t polled;
        uint64_t dropped;
    } stats;

    struct io_handle_ *next;
} io_handle_s;

typedef void (*io_thread_cb_fn)(io_thread_s *thread);

typedef struct io_thread_ {
    pthread_t thread;
    pthread_mutex_t mutex;
    volatile bool active;
    volatile bool stopped;
    
    bool set_cpu_affinity;
    cpu_set_t cpuset;

    io_thread_cb_fn setup_fn;
    io_thread_cb_fn run_fn;
    io_thread_cb_fn teardown_fn;

    uint8_t *sp;

    io_handle_s *io;
    bbl_txq_s *txq;

    struct io_thread_ *next;
} io_thread_s;

#endif