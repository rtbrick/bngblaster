/*
 * BNG Blaster (BBL) - IO Linux Socket Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
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

#ifndef PACKET_FANOUT_FLAG_IGNORE_OUTGOING
#define PACKET_FANOUT_FLAG_IGNORE_OUTGOING 0x4000
#endif

/* Set fanout group. The group ID is 16 bit, a group of another
 * interface with the same ID is rejected with EINVAL by the kernel,
 * in which case the next ID is tried. The RX threads of an interface
 * walk the same sequence and therefore join the same group.
 *
 * The kernel ignores PACKET_IGNORE_OUTGOING of a socket in a fanout
 * group, the group must be created with PACKET_FANOUT_FLAG_IGNORE_OUTGOING
 * (since Linux 4.20) instead. A group with different flags is also
 * rejected with EINVAL, therefore each ID is tried without this flag
 * before the next one, which joins a group created by a kernel without
 * support for this flag. */
static bool
set_fanout(io_handle_s *io)
{
    const int fanout_flags[] = {PACKET_FANOUT_FLAG_IGNORE_OUTGOING, 0};
    uint16_t fanout_id = io->fanout_id & 0xffff;
    int fanout_arg;
    int i, f;

    if(io->fanout_id && io->direction == IO_INGRESS) {
        for(i = 0; i < 64; i++) {
            if(!fanout_id) fanout_id++;
            for(f = 0; f < 2; f++) {
                fanout_arg = (fanout_id | ((io->fanout_type | fanout_flags[f]) << 16));
                if(setsockopt(io->fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg)) == 0) {
                    if(!fanout_flags[f]) {
                        LOG(ERROR, "Warning: Failed to set PACKET_FANOUT_FLAG_IGNORE_OUTGOING for interface %s RX socket."
                            " TX packets might be seen on RX.\n", io->interface->name);
                    }
                    return true;
                }
                if(errno != EINVAL) {
                    goto ERROR;
                }
            }
            fanout_id++;
        }
ERROR:
        LOG(ERROR, "Failed to set fanout group for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;
    }
    return true;
}

/* Discard frames rejected by the kernel (e.g. above the MTU) instead
 * of stopping the TX ring at this frame. */
static bool
set_packet_loss(io_handle_s *io)
{
    int one = 1;
    if(setsockopt(io->fd, SOL_PACKET, PACKET_LOSS, &one, sizeof(one)) == -1) {
        LOG(ERROR, "Failed to set packet loss for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;
    }
    return true;
}

/* Receive stripped VLAN tags as auxiliary data (raw RX). */
static bool
set_packet_auxdata(io_handle_s *io)
{
    int one = 1;
    if(setsockopt(io->fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) == -1) {
        LOG(ERROR, "Failed to set packet auxdata for interface %s - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
        return false;
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
    io->req.tp_block_size = io_packet_mmap_frame_size();

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

/* The default receive buffer (net.core.rmem_default, 212992 bytes) holds
 * only about 90 frames on some drivers (e.g. i40e), which raw mode loses
 * with bursts. Size it for the configured RX slots instead. */
static bool
set_rcvbuf(io_handle_s *io, int slots)
{
    int size = slots * 2048;

    if(setsockopt(io->fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) == -1 &&
       setsockopt(io->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1) {
        LOG(ERROR, "Failed to set receive buffer of interface %s RX socket - %s (%d)\n",
            io->interface->name, strerror(errno), errno);
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
    /* Ignore outgoing packets if socket is used for RX (IO_INGRESS). 
     * The PACKET_IGNORE_OUTGOING option is supported since Linux kernel 4.20. */
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
        if(io->direction == IO_EGRESS && !set_packet_loss(io)) {
            return false;
        }
        if(!set_ring(io, slots)) {
            return false;
        }
    } else if(io->direction == IO_INGRESS) {
        if(!set_packet_auxdata(io)) {
            return false;
        }
        if(!set_rcvbuf(io, slots)) {
            return false;
        }
    }

    if(!set_fanout(io)) {
        return false;
    }
    return true;
}