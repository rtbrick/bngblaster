/*
 * BNG Blaster (BBL) - IO Definitions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_IO_DEF_H__
#define __BBL_IO_DEF_H__

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

typedef struct io_handle_ {
    io_mode_t mode;
    io_direction_t direction;

    int id;
    int fd;
    int fanout_id;
    int fanout_type;
    struct tpacket_req req;
    struct sockaddr_ll addr;

    uint8_t *ring; /* ring buffer */
    uint16_t cursor; /* ring buffer cursor */
    uint16_t queued;
    bool polled;

    bbl_interface_s *interface;
    bbl_txq_s *txq;

    uint8_t *sp;
    uint8_t *buf;
    uint16_t buf_len;

    bbl_ethernet_header_t *eth;

    struct timespec timestamp; /* user space timestamps */

    io_thread_s *thread;

    struct {
        uint64_t packets;
        uint64_t bytes;

        uint64_t stream_packets;
        uint64_t stream_bytes;
    } stats;

    struct io_handle_ *next;
} io_handle_s;

typedef void (*io_thread_start_fn)(void *arg);

typedef struct io_thread_ {
    pthread_t thread;
    pthread_mutex_t mutex;
    volatile bool active;
    volatile bool stopped;

    io_thread_start_fn start_fn;

    struct timer_root_ timer_root;
    struct timer_ *ctrl_timer;
    struct timer_ *io_timer;

    struct timer_ *main_rx_job; /* main loop RX job */

    io_handle_s *io;
    struct io_thread_ *next;
} io_thread_s;

#endif