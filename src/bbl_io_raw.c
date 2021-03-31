/*
 * BNG Blaster (BBL) - RAW Sockets
 *
 * Christian Giese, October 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_io_raw.h"
#include "bbl_pcap.h"
#include "bbl_rx.h"
#include "bbl_tx.h"

void
bbl_io_raw_rx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    bbl_io_raw_ctx *io_ctx;

    struct sockaddr saddr;
    int saddr_size = sizeof(saddr);
    int rx_len;

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

    while (true) {
        rx_len = recvfrom(io_ctx->fd_rx, io_ctx->buf, SCRATCHPAD_LEN , 0, &saddr , (socklen_t*)&saddr_size);
		if(rx_len < 14) {
            break;
        }
        eth_start = io_ctx->buf;
        eth_len = rx_len;

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
bbl_io_raw_tx_job (timer_s *timer) {
    bbl_interface_s *interface;
    bbl_ctx_s *ctx;
    bbl_io_raw_ctx *io_ctx;

    uint16_t len;

    protocol_error_t tx_result = IGNORED;

    interface = timer->data;
    if (!interface) {
        return;
    }

    ctx = interface->ctx;
    io_ctx = interface->io_ctx;

    /* Get TX timestamp */
    clock_gettime(CLOCK_REALTIME, &interface->tx_timestamp);

    while(tx_result != EMPTY) {
        tx_result = bbl_tx(ctx, interface, io_ctx->buf, &len);
        if (tx_result == PROTOCOL_SUCCESS) {
            if (sendto(io_ctx->fd_rx, io_ctx->buf, len, 0, (struct sockaddr*)&io_ctx->addr, sizeof(struct sockaddr_ll)) <0 ) {
                LOG(IO, "Sendto failed with errno: %i\n", errno);
                interface->stats.sendto_failed++;
                return;
            }
            interface->stats.packets_tx++;
            interface->stats.bytes_tx += len;
            /* Dump the packet into pcap file. */
            if (ctx->pcap.write_buf) {
                pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                          io_ctx->buf, len, interface->pcap_index, 
                                          PCAPNG_EPB_FLAGS_OUTBOUND);
            }
        }
    }

    pcapng_fflush(ctx);
}

/** 
 * bbl_io_raw_send 
 * 
 * @param interface interface.
 * @param packet packet to be send
 * @param packet_len packet length
 */
bool
bbl_io_raw_send (bbl_interface_s *interface, uint8_t *packet, uint16_t packet_len) {
    bbl_ctx_s *ctx;
    bbl_io_raw_ctx *io_ctx;

    ctx = interface->ctx;
    io_ctx = interface->io_ctx;

    if (sendto(io_ctx->fd_rx, packet, packet_len, 0, (struct sockaddr*)&io_ctx->addr, sizeof(struct sockaddr_ll)) <0 ) {
        LOG(IO, "Sendto failed with errno: %i\n", errno);
        interface->stats.sendto_failed++;
        return false;
    }
    interface->stats.packets_tx++;
    interface->stats.bytes_tx += packet_len;
    /* Dump the packet into pcap file. */
    if (ctx->pcap.write_buf) {
        pcapng_push_packet_header(ctx, &interface->tx_timestamp,
                                  packet, packet_len, interface->pcap_index, 
                                  PCAPNG_EPB_FLAGS_OUTBOUND);
        pcapng_fflush(ctx);
    }
    return true;   
}

/** 
 * bbl_io_raw_add_interface 
 * 
 * @param ctx global context
 * @param interface interface.
 * @param slots ring buffer size 
 */
bool
bbl_io_raw_add_interface(bbl_ctx_s *ctx, bbl_interface_s *interface, int slots) {
    bbl_io_raw_ctx *io_ctx;
    char timer_name[32];
    struct ifreq ifr;
    int qdisc_bypass;

    io_ctx = calloc(1, sizeof(bbl_io_raw_ctx));
    io_ctx->buf = malloc(BBL_IO_RAW_BUFFER_LEN);
    interface->io_mode = IO_MODE_RAW;
    interface->io_ctx = io_ctx;

    UNUSED(slots);

    /*
     * Open RAW socket for all Ethertypes.
     * https://man7.org/linux/man-pages/man7/packet.7.html
     */
    io_ctx->fd_tx = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, 0);
    if (io_ctx->fd_tx == -1) {
        LOG(ERROR, "socket() TX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }
    io_ctx->fd_rx = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htobe16(ETH_P_ALL));
    if (io_ctx->fd_rx == -1) {
        LOG(ERROR, "socket() RX error %s (%d) for interface %s\n", strerror(errno), errno, interface->name);
        return false;
    }

    /*
     * Limit socket to the given interface index.
     */
    io_ctx->addr.sll_family = AF_PACKET;
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

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 10;
    setsockopt(io_ctx->fd_rx, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));

    /*
     * Add an periodic timer for polling I/O.
     */
    snprintf(timer_name, sizeof(timer_name), "%s TX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->tx_job, timer_name, 0, ctx->config.tx_interval, interface, bbl_io_raw_tx_job);
    snprintf(timer_name, sizeof(timer_name), "%s RX", interface->name);
    timer_add_periodic(&ctx->timer_root, &interface->rx_job, timer_name, 0, ctx->config.rx_interval, interface, bbl_io_raw_rx_job);

    return true;
}