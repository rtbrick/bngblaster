/*
 * BNG Blaster (BBL) - PACKET_MMAP
 *
 * Christian Giese, October 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_io_packet_mmap.h"
#include "bbl_pcap.h"
#include "bbl_rx.h"
#include "bbl_tx.h"

void
bbl_io_packet_mmap_rx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    bbl_io_packet_mmap_ctx *io_ctx;
    struct pollfd fds[1] = {0};

    uint8_t *frame_ptr;
    struct tpacket2_hdr *tphdr;

    uint8_t *eth_start;
    uint eth_len;

    bbl_ethernet_header_t *eth;
    protocol_error_t decode_result;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;
    io_ctx = interface->io_ctx;


    /* Get RX timestamp */
    clock_gettime(CLOCK_REALTIME, &interface->rx_timestamp);

    frame_ptr = io_ctx->ring_rx + (io_ctx->cursor_rx * io_ctx->req_rx.tp_frame_size);
    tphdr = (struct tpacket2_hdr*)frame_ptr;
    if (!(tphdr->tp_status & TP_STATUS_USER)) {
        /* If no buffer is available poll kernel */
        fds[0].fd = io_ctx->fd_rx;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        if (poll(fds, 1, 0) == -1) {
            LOG(IO, "Failed to RX poll interface %s", interface->name);
        }
        interface->stats.poll_rx++;
    }

    while ((tphdr->tp_status & TP_STATUS_USER)) {

        eth_start = (uint8_t*)tphdr + tphdr->tp_mac;
        eth_len = tphdr->tp_len;
        interface->stats.packets_rx++;
        interface->stats.bytes_rx += eth_len;

        /*
	     * Dump the packet into pcap file.
	     */
        if (ctx->pcap.write_buf) {
	        pcapng_push_packet_header(ctx, &interface->rx_timestamp, eth_start, eth_len,
				                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
        }

        decode_result = decode_ethernet(eth_start, eth_len, interface->ctx->sp_rx, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {            
#if 0
            /* The outer VLAN is stripped from header */
            eth->vlan_inner = eth->vlan_outer;
            eth->vlan_outer = tphdr->tp_vlan_tci & ETH_VLAN_ID_MAX;
#endif
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = tphdr->tp_sec; /* ktime/hw timestamp */
            eth->timestamp.tv_nsec = tphdr->tp_nsec; /* ktime/hw timestamp */
            if(interface->access) {
                bbl_rx_handler_access(eth, interface);
            } else {
                bbl_rx_handler_network(eth, interface);
            }
        } else if (decode_result == UNKNOWN_PROTOCOL) {
            interface->stats.packets_rx_drop_unknown++;
        } else {
            interface->stats.packets_rx_drop_decode_error++;
        }

        tphdr->tp_status = TP_STATUS_KERNEL; /* Return ownership back to kernel */
        io_ctx->cursor_rx = (io_ctx->cursor_rx + 1) % io_ctx->req_rx.tp_frame_nr;

        frame_ptr = io_ctx->ring_rx + (io_ctx->cursor_rx * io_ctx->req_rx.tp_frame_size);
        tphdr = (struct tpacket2_hdr*)frame_ptr;
    }
    pcapng_fflush(ctx);
}

void
bbl_io_packet_mmap_tx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    bbl_io_packet_mmap_ctx *io_ctx;

    struct tpacket2_hdr* tphdr;
    struct pollfd fds[1] = {0};

    uint8_t *frame_ptr;
    uint8_t *buf;
    uint16_t len;

    protocol_error_t tx_result = IGNORED;

    interface = timer->data;
    if (!interface) {
        return;
    }

    ctx = interface->ctx;
    io_ctx = interface->io_ctx;

    frame_ptr = io_ctx->ring_tx + (io_ctx->cursor_tx * io_ctx->req_tx.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;

    if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
        /* If no buffer is available poll kernel. */
        fds[0].fd = io_ctx->fd_tx;
        fds[0].events = POLLOUT;
        fds[0].revents = 0;
        if (poll(fds, 1, 0) == -1) {
            LOG(IO, "Failed to TX poll interface %s", interface->name);
        }
        interface->stats.poll_tx++;
        return;
    }

    /* Get TX timestamp */
    clock_gettime(CLOCK_REALTIME, &interface->tx_timestamp);

    while(tx_result != EMPTY) {
        /* Check if this slot available for writing. */
        if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
            interface->stats.no_tx_buffer++;
            break;
        }

        buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
        tx_result = bbl_tx(ctx, interface, buf, &len);
        if (tx_result == PROTOCOL_SUCCESS) {
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += len;
            tphdr->tp_len = len;
            tphdr->tp_status = TP_STATUS_SEND_REQUEST;
            io_ctx->cursor_tx = (io_ctx->cursor_tx + 1) % io_ctx->req_tx.tp_frame_nr;
            /* Dump the packet into pcap file. */
            if (ctx->pcap.write_buf) {
                pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                          buf, len, interface->pcap_index, 
                                          PCAPNG_EPB_FLAGS_OUTBOUND);
            }
            frame_ptr = io_ctx->ring_tx + (io_ctx->cursor_tx * io_ctx->req_tx.tp_frame_size);
            tphdr = (struct tpacket2_hdr *)frame_ptr;
        }
    }

    pcapng_fflush(ctx);

    /* Notify kernel. */
    if (sendto(io_ctx->fd_tx, NULL, 0 , 0, NULL, 0) == -1) {
        LOG(IO, "Sendto failed with errno: %i\n", errno);
        interface->stats.sendto_failed++;
        return;
    }
}

/** 
 * bbl_io_packet_mmap_send 
 * 
 * @param interface interface.
 * @param packet packet to be send
 * @param packet_len packet length
 */
bool
bbl_io_packet_mmap_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    bbl_ctx_s *ctx;
    bbl_io_packet_mmap_ctx *io_ctx;

    struct tpacket2_hdr* tphdr;

    uint8_t *frame_ptr;

    ctx = interface->ctx;
    io_ctx = interface->io_ctx;

    frame_ptr = io_ctx->ring_tx + (io_ctx->cursor_tx * io_ctx->req_tx.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;

    if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
        interface->stats.no_tx_buffer++;
        return false;
    }

    memcpy(frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll), packet, packet_len);
    interface->stats.packets_tx++;
    interface->stats.bytes_tx += packet_len;
    tphdr->tp_len = packet_len;
    tphdr->tp_status = TP_STATUS_SEND_REQUEST;
    io_ctx->cursor_tx = (io_ctx->cursor_tx + 1) % io_ctx->req_tx.tp_frame_nr;
    /* Dump the packet into pcap file. */
    if (ctx->pcap.write_buf) {
        pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                  packet, packet_len, interface->pcap_index, 
                                  PCAPNG_EPB_FLAGS_OUTBOUND);
        pcapng_fflush(ctx);
    }

#if 0
    /* Notify kernel. */
    if (sendto(io_ctx->fd_tx, NULL, 0 , 0, NULL, 0) == -1) {
        LOG(IO, "Sendto failed with errno: %i\n", errno);
        interface->stats.sendto_failed++;
        return false;
    } 
#endif

    return true;
}

/** 
 * bbl_io_packet_mmap_add_interface 
 * 
 * @param ctx global context
 * @param interface interface.
 * @param slots ring buffer size 
 */
bool
bbl_io_packet_mmap_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface, int slots) {
    bbl_io_packet_mmap_ctx *io_ctx;
    size_t ring_size;
    char timer_name[32];
    struct ifreq ifr;
    int version, qdisc_bypass;

    io_ctx = calloc(1, sizeof(bbl_io_packet_mmap_ctx));
    interface->io_mode = IO_MODE_PACKET_MMAP;
    interface->io_ctx = io_ctx;

    /*
     * Open RAW socket for all Ethertypes.
     * https://man7.org/linux/man-pages/man7/packet.7.html
     */
    io_ctx->fd_tx = socket(PF_PACKET, SOCK_RAW, 0);
    if (io_ctx->fd_tx == -1) {
        LOG(ERROR, "socket() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }
    io_ctx->fd_rx = socket(PF_PACKET, SOCK_RAW, htobe16(ETH_P_ALL));
    if (io_ctx->fd_rx == -1) {
        LOG(ERROR, "socket() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }

    /*
     * Use API version 2 which is good enough for what we're doing.
     */
    version = TPACKET_V2;
    if ((setsockopt(io_ctx->fd_tx, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
        LOG(ERROR, "setsockopt() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }

    if ((setsockopt(io_ctx->fd_rx, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
        LOG(ERROR, "setsockopt() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }

    /*
     * Limit socket to the given interface index.
     */
    io_ctx->addr.sll_family = PF_PACKET;
    io_ctx->addr.sll_ifindex = interface->ifindex;
    io_ctx->addr.sll_protocol = 0;
    if (bind(io_ctx->fd_tx, (struct sockaddr*)&io_ctx->addr, sizeof(io_ctx->addr)) == -1) {
        LOG(ERROR, "bind() TX error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }
    io_ctx->addr.sll_protocol = htobe16(ETH_P_ALL);
    if (bind(io_ctx->fd_rx, (struct sockaddr*)&io_ctx->addr, sizeof(io_ctx->addr)) == -1) {
        LOG(ERROR, "bind() RX error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    /*
     * Set the interface to promiscuous mode. Only for the RX FD.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if (ioctl(io_ctx->fd_rx, SIOCGIFFLAGS, &ifr) == -1) {
        LOG(ERROR, "Getting socket flags error %s (%d) when setting promiscuous mode for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(io_ctx->fd_rx, SIOCSIFFLAGS, ifr) == -1){
        LOG(ERROR, "Setting socket flags error %s (%d) when setting promiscuous mode for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    /*
     *   Bypass TC_QDISC, such that the kernel is hammered 30% less with processing packets. Only for the TX FD.
     *
     *   PACKET_QDISC_BYPASS (since Linux 3.14)
     *          By default, packets sent through packet sockets pass through
     *          the kernel's qdisc (traffic control) layer, which is fine for
     *          the vast majority of use cases.  For traffic generator appli‐
     *          ances using packet sockets that intend to brute-force flood
     *          the network—for example, to test devices under load in a simi‐
     *          lar fashion to pktgen—this layer can be bypassed by setting
     *          this integer option to 1.  A side effect is that packet
     *          buffering in the qdisc layer is avoided, which will lead to
     *          increased drops when network device transmit queues are busy;
     *          therefore, use at your own risk.
     */
    if(ctx->config.qdisc_bypass) {
        qdisc_bypass = 1;
        if (setsockopt(io_ctx->fd_tx, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass)) == -1) {
            LOG(ERROR, "Setting qdisc bypass error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
            return false;
        }
    }

    /*
     * Setup TX ringbuffer.
     * 
     *  The following are conditions that are checked in packet_set_ring
    
     *  tp_block_size must be a multiple of PAGE_SIZE (1)
     *  tp_frame_size must be greater than TPACKET_HDRLEN (obvious)
     *  tp_frame_size must be a multiple of TPACKET_ALIGNMENT
     *  tp_frame_nr   must be exactly frames_per_block*tp_block_nr
     *  
     *  Note that tp_block_size should be chosen to be a power of two or there will
     *  be a waste of memory.
     */
    memset(&io_ctx->req_tx, 0, sizeof(io_ctx->req_tx));
    io_ctx->req_tx.tp_block_size = sysconf(_SC_PAGESIZE); /* 4096 */
    io_ctx->req_tx.tp_frame_size = io_ctx->req_tx.tp_block_size/2; /* 2048 */
    io_ctx->req_tx.tp_block_nr = slots/2;
    io_ctx->req_tx.tp_frame_nr = slots;
    if (setsockopt(io_ctx->fd_tx, SOL_PACKET, PACKET_TX_RING, &io_ctx->req_tx, sizeof(io_ctx->req_tx)) == -1) {
        LOG(ERROR, "Allocating TX ringbuffer error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    /*
     * Open the shared memory TX window between kernel and userspace.
     */
    ring_size = io_ctx->req_tx.tp_block_nr * io_ctx->req_tx.tp_block_size;
    io_ctx->ring_tx = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, io_ctx->fd_tx, 0);

    /*
     * Setup RX ringbuffer. Double the slots, such that we do not miss any packets.
     */
    slots <<= 1;
    memset(&io_ctx->req_rx, 0, sizeof(io_ctx->req_rx));
    io_ctx->req_rx.tp_block_size = sysconf(_SC_PAGESIZE); /* 4096 */
    io_ctx->req_rx.tp_frame_size = io_ctx->req_rx.tp_block_size/2; /* 2048 */
    io_ctx->req_rx.tp_block_nr = slots/2;
    io_ctx->req_rx.tp_frame_nr = slots;
    if (setsockopt(io_ctx->fd_rx, SOL_PACKET, PACKET_RX_RING, &io_ctx->req_rx, sizeof(io_ctx->req_rx)) == -1) {
        LOG(ERROR, "Allocating RX ringbuffer error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    /*
     * Open the shared memory RX window between kernel and userspace.
     */
    ring_size = io_ctx->req_rx.tp_block_nr * io_ctx->req_rx.tp_block_size;
    io_ctx->ring_rx = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, io_ctx->fd_rx, 0);

    /*
     * Add an periodic timer for polling I/O.
     */
    snprintf(timer_name, sizeof(timer_name), "%s TX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval, interface, bbl_io_packet_mmap_tx_job);
    snprintf(timer_name, sizeof(timer_name), "%s RX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval, interface, bbl_io_packet_mmap_rx_job);

    return true;
}