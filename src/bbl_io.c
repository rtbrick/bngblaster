/*
 * BNG Blaster (BBL) - PACKET_MMAP
 *
 * Christian Giese, October 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_pcap.h"
#include "bbl_rx.h"
#include "bbl_tx.h"
#ifdef BNGBLASTER_NETMAP
#include "bbl_io_netmap.h"
#endif

void
bbl_io_packet_mmap_rx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    struct pollfd fds[1] = {0};

    uint8_t *frame_ptr;
    struct tpacket2_hdr *tphdr;

    uint8_t *eth_start;
    uint16_t eth_len;

    bbl_ethernet_header_t *eth;
    protocol_error_t decode_result;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;


    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &interface->rx_timestamp);

    frame_ptr = interface->io.ring_rx + (interface->io.cursor_rx * interface->io.req_rx.tp_frame_size);
    tphdr = (struct tpacket2_hdr*)frame_ptr;
    if (!(tphdr->tp_status & TP_STATUS_USER)) {
        /* If no buffer is available poll kernel */
        fds[0].fd = interface->io.fd_rx;
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

        /* Dump the packet into pcap file. */
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
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = tphdr->tp_sec; /* ktime/hw timestamp */
            eth->timestamp.tv_nsec = tphdr->tp_nsec; /* ktime/hw timestamp */
#endif
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = interface->rx_timestamp.tv_sec;
            eth->timestamp.tv_nsec = interface->rx_timestamp.tv_nsec;
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
        interface->io.cursor_rx = (interface->io.cursor_rx + 1) % interface->io.req_rx.tp_frame_nr;

        frame_ptr = interface->io.ring_rx + (interface->io.cursor_rx * interface->io.req_rx.tp_frame_size);
        tphdr = (struct tpacket2_hdr*)frame_ptr;
    }
    pcapng_fflush(ctx);
}

void
bbl_io_raw_rx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;

    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    int rx_len;

    uint8_t *eth_start;
    uint16_t eth_len;

    bbl_ethernet_header_t *eth;
    protocol_error_t decode_result;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;

    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &interface->rx_timestamp);

    while (true) {
        rx_len = recvfrom(interface->io.fd_rx, interface->io.buf, IO_BUFFER_LEN, 0, &saddr , (socklen_t*)&saddr_size);
		if(rx_len < 14) {
            break;
        }
        eth_start = interface->io.buf;
        eth_len = rx_len;

        interface->stats.packets_rx++;
        interface->stats.bytes_rx += eth_len;

        /* Dump the packet into pcap file. */
        if (ctx->pcap.write_buf) {
	        pcapng_push_packet_header(ctx, &interface->rx_timestamp, eth_start, eth_len,
				                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
        }

        decode_result = decode_ethernet(eth_start, eth_len, interface->ctx->sp_rx, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = interface->rx_timestamp.tv_sec;
            eth->timestamp.tv_nsec = interface->rx_timestamp.tv_nsec;
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
    }
    pcapng_fflush(ctx);
}

void
bbl_io_packet_mmap_tx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    protocol_error_t tx_result = IGNORED;

    struct tpacket2_hdr* tphdr;
    struct pollfd fds[1] = {0};

    uint8_t *frame_ptr;
    uint8_t *buf;
    uint16_t len;
    uint16_t packets = 0;

    interface = timer->data;
    if (!interface) {
        return;
    }
    ctx = interface->ctx;

    frame_ptr = interface->io.ring_tx + (interface->io.cursor_tx * interface->io.req_tx.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;

    if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
        if(interface->io.pollout) {
            /* We already polled kernel. */
            return;
        }
        /* If no buffer is available poll kernel. */
        fds[0].fd = interface->io.fd_tx;
        fds[0].events = POLLOUT;
        fds[0].revents = 0;
        if (poll(fds, 1, 0) == -1) {
            LOG(IO, "Failed to TX poll interface %s", interface->name);
        }
        interface->io.pollout = true;
        interface->stats.poll_tx++;
        return;
    }
    interface->io.pollout = false;

    /* Get TX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &interface->tx_timestamp);

    while(tx_result != EMPTY) {
        /* Check if this slot available for writing. */
        if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
            interface->stats.no_tx_buffer++;
            break;
        }
        buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
        tx_result = bbl_tx(ctx, interface, buf, &len);
        if (tx_result == PROTOCOL_SUCCESS) {
            packets++;
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += len;
            tphdr->tp_len = len;
            tphdr->tp_status = TP_STATUS_SEND_REQUEST;
            interface->io.cursor_tx = (interface->io.cursor_tx + 1) % interface->io.req_tx.tp_frame_nr;
            /* Dump the packet into pcap file. */
            if (ctx->pcap.write_buf) {
                pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                          buf, len, interface->pcap_index, 
                                          PCAPNG_EPB_FLAGS_OUTBOUND);
            }
            frame_ptr = interface->io.ring_tx + (interface->io.cursor_tx * interface->io.req_tx.tp_frame_size);
            tphdr = (struct tpacket2_hdr *)frame_ptr;
        }
    }
    if(packets) {
        pcapng_fflush(ctx);
        /* Notify kernel. */
        if (sendto(interface->io.fd_tx, NULL, 0 , 0, NULL, 0) == -1) {
            LOG(IO, "Sendto failed with errno: %i\n", errno);
            interface->stats.sendto_failed++;
        }
    }
}

void
bbl_io_raw_tx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    protocol_error_t tx_result = IGNORED;

    uint16_t len;

    interface = timer->data;
    if (!interface) {
        return;
    }

    ctx = interface->ctx;

    /* Get TX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &interface->tx_timestamp);
    while(tx_result != EMPTY) {
        tx_result = bbl_tx(ctx, interface, interface->io.buf, &len);
        if (tx_result == PROTOCOL_SUCCESS) {
            if (sendto(interface->io.fd_tx, interface->io.buf, len, 0, (struct sockaddr*)&interface->io.addr, sizeof(struct sockaddr_ll)) <0 ) {
                LOG(IO, "Sendto failed with errno: %i\n", errno);
                interface->stats.sendto_failed++;
                return;
            }
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += len;
            /* Dump the packet into pcap file. */
            if (ctx->pcap.write_buf) {
                pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                          interface->io.buf, len, interface->pcap_index, 
                                          PCAPNG_EPB_FLAGS_OUTBOUND);
            }
        }
    }
    pcapng_fflush(ctx);
}

bool
bbl_io_packet_mmap_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    struct tpacket2_hdr* tphdr;
    uint8_t *frame_ptr;
    uint8_t *buf;
    frame_ptr = interface->io.ring_tx + (interface->io.cursor_tx * interface->io.req_tx.tp_frame_size);
    tphdr = (struct tpacket2_hdr *)frame_ptr;
    if (tphdr->tp_status != TP_STATUS_AVAILABLE) {
        interface->stats.no_tx_buffer++;
        return false;
    }
    buf = frame_ptr + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
    memcpy(buf, packet, packet_len);
    tphdr->tp_len = packet_len;
    tphdr->tp_status = TP_STATUS_SEND_REQUEST;
    interface->io.cursor_tx = (interface->io.cursor_tx + 1) % interface->io.req_tx.tp_frame_nr;
    return true;
}

bool
bbl_io_raw_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    if (sendto(interface->io.fd_tx, packet, packet_len, 0, (struct sockaddr*)&interface->io.addr, sizeof(struct sockaddr_ll)) <0 ) {
        LOG(IO, "Sendto failed with errno: %i\n", errno);
        interface->stats.sendto_failed++;
        return false;
    }
    return true;   
}

/** 
 * bbl_io_send 
 * 
 * Send single packet trough given interface.
 * 
 * @param interface interface.
 * @param packet packet to be send
 * @param packet_len packet length
 */
bool
bbl_io_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    bbl_ctx_s *ctx = interface->ctx;
    bool result = false;

    switch (interface->io.mode) {
        case IO_MODE_PACKET_MMAP_RAW:
        case IO_MODE_RAW:
            result = bbl_io_raw_send(interface, packet, packet_len);
            break;
        case IO_MODE_PACKET_MMAP:
            result = bbl_io_packet_mmap_send(interface, packet, packet_len);
            break;
        case IO_MODE_NETMAP:
#ifdef BNGBLASTER_NETMAP
            result = bbl_io_netmap_send(interface, packet, packet_len);
#else
            result = false;
#endif
            break;
    }

    if(result) {
        interface->stats.packets_tx++;
        interface->stats.bytes_tx += packet_len;
        /* Dump the packet into pcap file. */
        if (ctx->pcap.write_buf) {
            pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                    packet, packet_len, interface->pcap_index, 
                                    PCAPNG_EPB_FLAGS_OUTBOUND);
            pcapng_fflush(ctx);
        }
    }
    return result;
}

/** 
 * bbl_io_add_interface 
 * 
 * @param ctx global context
 * @param interface interface.
 */
bool
bbl_io_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface) {

    size_t ring_size;
    char timer_name[32];
    struct ifreq ifr;
    int version = TPACKET_V2; 
    int qdisc_bypass = 1;
    int slots = ctx->config.io_slots;

    interface->io.mode = ctx->config.io_mode;
    interface->io.buf = malloc(IO_BUFFER_LEN);
    
#ifdef BNGBLASTER_NETMAP
    if(interface->io.mode == IO_MODE_NETMAP) {
        return bbl_io_netmap_add_interface(ctx, interface);
    }
#endif

    /*
     * Open RAW socket for all ethertypes.
     * https://man7.org/linux/man-pages/man7/packet.7.html
     */
    interface->io.fd_tx = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
    if (interface->io.fd_tx == -1) {
        LOG(ERROR, "socket() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }
    interface->io.fd_rx = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htobe16(ETH_P_ALL));
    if (interface->io.fd_rx == -1) {
        LOG(ERROR, "socket() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }

    /* Set TPACKET version 2 for packet_mmap ring. */
    if(interface->io.mode == IO_MODE_PACKET_MMAP) {
        if ((setsockopt(interface->io.fd_tx, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
            LOG(ERROR, "setsockopt() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
            return false;
        }
    }
    if(interface->io.mode == IO_MODE_PACKET_MMAP_RAW || interface->io.mode == IO_MODE_PACKET_MMAP) {
        if ((setsockopt(interface->io.fd_rx, SOL_PACKET, PACKET_VERSION, &version, sizeof(version))) == -1) {
            LOG(ERROR, "setsockopt() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
            return false;
        }
    }

    /* Limit socket to the given interface index. */
    interface->io.addr.sll_family = PF_PACKET;
    interface->io.addr.sll_ifindex = interface->ifindex;
    interface->io.addr.sll_protocol = 0;
    if (bind(interface->io.fd_tx, (struct sockaddr*)&interface->io.addr, sizeof(interface->io.addr)) == -1) {
        LOG(ERROR, "bind() TX error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }
    interface->io.addr.sll_protocol = htobe16(ETH_P_ALL);
    if (bind(interface->io.fd_rx, (struct sockaddr*)&interface->io.addr, sizeof(interface->io.addr)) == -1) {
        LOG(ERROR, "bind() RX error %s (%d) for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    /* Set the interface to promiscuous mode. Only for the RX FD. */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if (ioctl(interface->io.fd_rx, SIOCGIFFLAGS, &ifr) == -1) {
        LOG(ERROR, "Getting socket flags error %s (%d) when setting promiscuous mode for interface %s\n",
        strerror(errno), errno, interface->name);
        return false;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(interface->io.fd_rx, SIOCSIFFLAGS, ifr) == -1){
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
        if (setsockopt(interface->io.fd_tx, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass)) == -1) {
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
    snprintf(timer_name, sizeof(timer_name), "%s TX", interface->name);
    if(interface->io.mode == IO_MODE_PACKET_MMAP) {
        memset(&interface->io.req_tx, 0, sizeof(interface->io.req_tx));
        interface->io.req_tx.tp_block_size = sysconf(_SC_PAGESIZE); /* 4096 */
        interface->io.req_tx.tp_frame_size = interface->io.req_tx.tp_block_size/2; /* 2048 */
        interface->io.req_tx.tp_block_nr = slots/2;
        interface->io.req_tx.tp_frame_nr = slots;
        if (setsockopt(interface->io.fd_tx, SOL_PACKET, PACKET_TX_RING, &interface->io.req_tx, sizeof(interface->io.req_tx)) == -1) {
            LOG(ERROR, "Allocating TX ringbuffer error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
            return false;
        }
        /* Open the shared memory TX window between kernel and userspace. */
        ring_size = interface->io.req_tx.tp_block_nr * interface->io.req_tx.tp_block_size;
        interface->io.ring_tx = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, interface->io.fd_tx, 0);
        timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval, interface, bbl_io_packet_mmap_tx_job);
    } else {
        timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval, interface, bbl_io_raw_tx_job);
    }

    /*
     * Setup RX ringbuffer. Double the slots, such that we do not miss any packets.
     */
    snprintf(timer_name, sizeof(timer_name), "%s RX", interface->name);
    if(interface->io.mode == IO_MODE_PACKET_MMAP_RAW || interface->io.mode == IO_MODE_PACKET_MMAP) {
        slots <<= 1;
        memset(&interface->io.req_rx, 0, sizeof(interface->io.req_rx));
        interface->io.req_rx.tp_block_size = sysconf(_SC_PAGESIZE); /* 4096 */
        interface->io.req_rx.tp_frame_size = interface->io.req_rx.tp_block_size/2; /* 2048 */
        interface->io.req_rx.tp_block_nr = slots/2;
        interface->io.req_rx.tp_frame_nr = slots;
        if (setsockopt(interface->io.fd_rx, SOL_PACKET, PACKET_RX_RING, &interface->io.req_rx, sizeof(interface->io.req_rx)) == -1) {
            LOG(ERROR, "Allocating RX ringbuffer error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
            return false;
        }

        /* Open the shared memory RX window between kernel and userspace. */
        ring_size = interface->io.req_rx.tp_block_nr * interface->io.req_rx.tp_block_size;
        interface->io.ring_rx = mmap(0, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, interface->io.fd_rx, 0);
        timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval, interface, bbl_io_packet_mmap_rx_job);
    } else {
        timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval, interface, bbl_io_raw_rx_job);
    }
    return true;
}