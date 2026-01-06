/*
 * BNG Blaster (BBL) - IO Linux Socket Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

/* Bypass TC_QDISC, such that the kernel is hammered 30% less with 
 * processing packets. Only for the TX FD. */
static bool
set_qdisc_bypass(io_handle_s *io)
{
    /* PACKET_QDISC_BYPASS (since Linux 3.14)
     * By default, packets sent through packet sockets pass through
     * the kernel's qdisc (traffic control) layer, which is fine for
     * the vast majority of use cases.  For traffic generator appli‐
     * ances using packet sockets that intend to brute-force flood
     * the network—for example, to test devices under load in a simi‐
     * lar fashion to pktgen—this layer can be bypassed by setting
     * this integer option to 1. A side effect is that packet
     * buffering in the qdisc layer is avoided, which will lead to
     * increased drops when network device transmit queues are busy;
     * therefore, use at your own risk. */
    int qdisc_bypass = 1;
    if(setsockopt(io->fd, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass)) == -1) {
        LOG(ERROR, "Failed to set qdisc bypass for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;
    }
    return true;
}

/* Set fanout group. */
static bool
set_fanout(io_handle_s *io)
{
    if(io->fanout_id && io->direction == IO_INGRESS) {
        int fanout_arg = (io->fanout_id | (io->fanout_type << 16));
        if(setsockopt(io->fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) == -1) {
            LOG(ERROR, "Failed to set fanout group for interface %s - %s (%d)\n",
                io->interface->name, strerror(errno), errno);
            return false;    
        }
    }
    return true;
}

/* Set packet version (TPACKET_V1, TPACKET_V2 or TPACKET_V3). */
static bool
set_packet_version(io_handle_s *io, int version)
{
    if((setsockopt(io->fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
        LOG(ERROR, "Failed to set packet version error for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;    
    }
    return true;
}

/* Setup ringbuffer. */
static bool
set_ring(io_handle_s *io, int slots)
{
    /* The following are conditions that are checked in packet_set_ring:
     * - tp_block_size must be a multiple of PAGE_SIZE (1)
     * - tp_frame_size must be greater than TPACKET_HDRLEN (obvious)
     * - tp_frame_size must be a multiple of TPACKET_ALIGNMENT
     * - tp_frame_nr   must be exactly frames_per_block*tp_block_nr
     * Note that tp_block_size should be chosen to be a power of two 
     * or there will be a waste of memory. */
    unsigned int ring_size = 0;
    int flag = 0;
    if(io->direction == IO_INGRESS) {
        flag = PACKET_RX_RING;
    } else {
        flag = PACKET_TX_RING;
    }
    io->req.tp_block_size = getpagesize(); /* 4096 */
    io->req.tp_frame_size = io->req.tp_block_size;
    io->req.tp_block_nr = slots;
    io->req.tp_frame_nr = slots;

    ring_size = io->req.tp_block_nr * io->req.tp_block_size;

    LOG(DEBUG, "Setup %u byte packet_mmap ringbuffer (%d slots) for interface %s\n", 
        ring_size, slots, io->interface->name);
    if(setsockopt(io->fd, SOL_PACKET, flag, &io->req, sizeof(struct tpacket_req)) == -1) {
        LOG(ERROR, "Allocating ringbuffer error for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;
    }
    io->ring = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, io->fd, 0);
    if(io->ring == NULL || io->ring == MAP_FAILED) {
        return false;
    }
    return true;
}

bool
io_socket_open(io_handle_s *io) {

    bbl_interface_s *interface = io->interface;
    bbl_link_config_s *config = interface->config;

    assert(io->mode == IO_MODE_PACKET_MMAP || io->mode == IO_MODE_RAW);

    int protocol = 0;
    int slots = config->io_slots_tx;

    if(io->direction == IO_INGRESS) {
        protocol = htobe16(ETH_P_ALL);
        slots = config->io_slots_rx;
    }

    /* Open RAW socket for all ethertypes.
     * https://man7.org/linux/man-pages/man7/packet.7.html */
    io->fd = socket(AF_PACKET, SOCK_RAW|SOCK_NONBLOCK, protocol);
    if(io->fd == -1) {
        LOG(ERROR, "Failed to open socket for interface %s - %s (%d)\n", 
            io->interface->name, strerror(errno), errno);
        return false;
    }
    /* Limit socket to the given interface index. */
    io->addr.sll_family = AF_PACKET;
    io->addr.sll_ifindex = io->interface->kernel_index;
    io->addr.sll_protocol = protocol;
    if(bind(io->fd, (struct sockaddr*)&io->addr, sizeof(io->addr)) == -1) {
        LOG(ERROR, "Failed to bind socket for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;
    }
    /* Ignore outgoing packets if socket is used for RX. 
     * PACKET_IGNORE_OUTGOING option is supported since linux 4.20. */
    if(io->direction == IO_INGRESS) {
        int one=1;
        if(setsockopt(io->fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) == -1) {
            kernel_version_s kv = get_kernel_version();
            const char *hint = "";
            if((kv.major < 4) || (kv.major == 4 && kv.minor < 20)) {
                hint = " Unsupported on linux kernel below 4.20.";
            }
            LOG(ERROR,
                "Warning: Failed to set PACKET_IGNORE_OUTGOING for interface %s RX socket - %s (%d).%s"
                " TX packets might be seen on RX.\n",
                io->interface->name, strerror(errno), errno, hint);
        }
    }
    if(io->direction == IO_EGRESS && interface->config->qdisc_bypass) {
        if(!set_qdisc_bypass(io)) {
            return false;
        }
    }
    if(io->mode == IO_MODE_PACKET_MMAP) {
        if(!set_packet_version(io, TPACKET_V2)) {
            return false;
        }
        if(!set_ring(io, slots)) {
            return false;
        }
    }

    if(!set_fanout(io)) {
        return false;
    }
    return true;
}