/*
 * BNG Blaster (BBL) - IO DPDK Functions (EXPERIMENTAL/WIP)
 *
 * TESTED WITH DPDK 25.11.3
 *
 * Christian Giese, September 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

//#ifndef BNGBLASTER_DPDK
//#define BNGBLASTER_DPDK 1
//#endif

#ifdef BNGBLASTER_DPDK

#include <dev_driver.h>

#include <rte_memory.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_bbdev.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_hexdump.h>
#include <rte_interrupts.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#define MBUF_CACHE_SIZE 256
#define NUM_MBUFS_RX (131072 - 1)
#define NUM_MBUFS_TX (8192 - 1)
#define BURST_SIZE_RX 256
#define BURST_SIZE_TX 32
#define PREFETCH_OFFSET 3

extern bool g_init_phase;
extern bool g_traffic;

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_ETH|RTE_ETH_RSS_IP|RTE_ETH_RSS_TCP|RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

static bbl_interface_s *
io_dpdk_get_interface_by_port_id(uint16_t port_id)
{
    bbl_interface_s *interface;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(interface->port_id == port_id) {
            return interface;
        }
    }
    return NULL;
}

static bool
io_dpdk_link_status(uint16_t port_id)
{
    struct rte_eth_link link = {0};
    bbl_interface_s *interface;
    
    interface = io_dpdk_get_interface_by_port_id(port_id);
    if(!interface) return false; /* unlikely */
    
    if(rte_eth_link_get_nowait(port_id, &link) == 0) {
        if(link.link_status) {
            interface->state = INTERFACE_UP;
            LOG(DPDK, "DPDK: interface %s (%u) link up (speed %u Mbps %s)\n", 
                interface->name, port_id, (unsigned)link.link_speed,
                (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex"));
        } else {
            interface->state = INTERFACE_DOWN;
            LOG(DPDK, "DPDK: interface %s (%u) link down\n", 
                interface->name, port_id);
        }
    } else {
        return false;
    }
    return true;
}

static bool
io_dpdk_dev_info(uint16_t port_id, struct rte_eth_dev_info *dev_info)
{
    int ret = rte_eth_dev_info_get(port_id, dev_info);
    if(ret != 0) {
        LOG(ERROR, "DPDK: Error during getting device (port %u) info: %s\n",
            port_id, strerror(-ret));
        return false;
    }
    return true;
}

int 
io_dpdk_event_callback(uint16_t port_id, enum rte_eth_event_type type, void *cb_arg, void *ret_param)
{
    RTE_SET_USED(cb_arg);
    RTE_SET_USED(ret_param);

    LOG(DPDK, "DPDK: %s event\n", type == RTE_ETH_EVENT_INTR_LSC ? "LSC interrupt" : "unknown");

    io_dpdk_link_status(port_id);
    return 0;
}

bool
io_dpdk_init()
{
    uint16_t port_id;
    uint16_t dpdk_ports;

    char fw_version[64];

    struct rte_eth_dev_info dev_info;
    
    if(!g_ctx->dpdk) {
        return true;
    }

    char *dpdk_args[64];
    char **argv=dpdk_args;
    int argc = 2;
    dpdk_args[0] = "bngblaster";
    dpdk_args[1] = "-v";

    bbl_link_config_s *link_config = g_ctx->config.link_config;
    while(link_config && argc < 62) {
        dpdk_args[argc++] = "-a";
        dpdk_args[argc++] = link_config->interface;
        link_config = link_config->next;
    }
    if(link_config) {
        LOG_NOARG(ERROR, "DPDK: too many link interfaces, EAL argument list truncated\n");
    }

    LOG_NOARG(DPDK, "DPDK: init the EAL\n");
    if(rte_eal_init(argc, argv) < 0) {
        LOG(ERROR, "DPDK: failed to init the EAL (%s)\n", rte_strerror(rte_errno));
        return false;
    }
    LOG(DPDK, "DPDK: version %s\n", rte_version());

    dpdk_ports = rte_eth_dev_count_avail();
    LOG(DPDK, "DPDK: %u ports available\n", dpdk_ports);

    RTE_ETH_FOREACH_DEV(port_id) {
        if(!io_dpdk_dev_info(port_id, &dev_info)) {
            LOG_NOARG(ERROR, "DPDK: failed to get device info\n");
            return false;
        }
        memset(fw_version, 0x0, sizeof(fw_version));
        if(rte_eth_dev_fw_version_get(port_id, fw_version, sizeof(fw_version)) == 0) {
            LOG(DPDK, "DPDK: interface %s (%u) driver %s firmware %s\n",
                dev_info.device->name, port_id, dev_info.driver_name, fw_version);

        } else {
            LOG(DPDK, "DPDK: interface %s (%u) driver %s\n",
                dev_info.device->name, port_id, dev_info.driver_name);
        }
        LOG(DPDK, "DPDK: interface %s (%u) max queues rx %u tx %u\n",
            dev_info.device->name, port_id, dev_info.max_rx_queues, dev_info.max_tx_queues);

        LOG(DPDK, "DPDK: interface %s (%u) RSS offload capa: 0x%lx\n",
            dev_info.device->name, port_id, dev_info.flow_type_rss_offloads);
    }

    return true;
}

/**
 * This job is for DPDK RX in main thread!
 */
void
io_dpdk_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    bbl_ethernet_header_s *eth;

    struct rte_mbuf *packet_burst[BURST_SIZE_RX];
    struct rte_mbuf *packet;
    uint16_t nb_rx;
    uint16_t i;

    protocol_error_t decode_result;
    bool pcap = false;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    /* Get RX timestamp */
    //clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;
    while(true) {
        nb_rx = rte_eth_rx_burst(interface->port_id, io->queue, packet_burst, BURST_SIZE_RX);
        if(nb_rx == 0) {
            break;
        }
        /* Prefetch the first few packets of the burst before processing
         * starts, so their data has time to land before it's touched. */
        for(i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(packet_burst[i], void *));
        }
        for(i = 0; i < nb_rx; i++) {
            /* Prefetch packets ahead of the one being processed to hide
             * memory latency behind the current packet's processing. */
            if(likely(i + PREFETCH_OFFSET < nb_rx)) {
                rte_prefetch0(rte_pktmbuf_mtod(packet_burst[i + PREFETCH_OFFSET], void *));
            }
            packet = packet_burst[i];
            io->buf = rte_pktmbuf_mtod(packet, uint8_t *);
            io->buf_len = packet->pkt_len;
            io->stats.packets++;
            io->stats.bytes += io->buf_len;
            decode_result = decode_ethernet(io->buf, io->buf_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
            if(decode_result == PROTOCOL_SUCCESS) {
                /* Copy RX timestamp */
                eth->timestamp.tv_sec = io->timestamp.tv_sec;
                eth->timestamp.tv_nsec = io->timestamp.tv_nsec;
                /* Dump the packet into pcap file */
                if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
                    pcap = true;
                    pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                              interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND);
                }
                bbl_rx_handler(interface, eth);
            } else {
                /* Dump the packet into pcap file */
                if(g_ctx->pcap.write_buf) {
                    pcap = true;
                    pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                              interface->ifindex, PCAPNG_EPB_FLAGS_INBOUND);
                }
                if(decode_result == UNKNOWN_PROTOCOL) {
                    io->stats.unknown++;
                } else {
                    io->stats.protocol_errors++;
                }
            }
            rte_pktmbuf_free(packet);
        }
    }
    if(pcap) {
        pcapng_fflush();
    }
}

static bool
io_dpdk_mbuf_alloc(io_handle_s *io)
{
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(io->mbuf_pool);
    if(!mbuf) {
        io->stats.no_buffer++;
        return false;
    }
    if(rte_pktmbuf_append(mbuf, 2048) == NULL) {
        rte_pktmbuf_free(mbuf);
        io->stats.no_buffer++;
        return false;
    }
    mbuf->data_len = 0;
    mbuf->pkt_len = 0;
    mbuf->next = NULL;
    
    io->mbuf = mbuf;
    io->buf = rte_pktmbuf_mtod(mbuf, uint8_t *);
    io->buf_len = 0;
    return true;
}

/*
 * This job is for DPDK TX in main thread!
 */
void
io_dpdk_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    bbl_stream_s *stream = NULL;
    bbl_stream_s *streams[BURST_SIZE_TX];
    struct rte_mbuf *mbufs[BURST_SIZE_TX];
    uint16_t burst = interface->config->io_burst;
    uint16_t built;
    uint16_t n;
    uint16_t nb_tx;
    uint16_t i;
    uint64_t now;
    bool pcap = false;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    if(io->update_streams) {
        io_stream_update_pps(io);
    }

    /* Get TX timestamp */
    //clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    io->timestamp.tv_sec = timer->timestamp->tv_sec;
    io->timestamp.tv_nsec = timer->timestamp->tv_nsec;

    while(burst) {
        if(!io->mbuf) {
            if(!io_dpdk_mbuf_alloc(io)) {
                break;
            }
        }
        if(likely(io->buf_len == 0)) {
            if(bbl_tx(interface, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                io->buf_len = 0;
                break;
            }        
        }
        /* Transmit the packet. */
        io->mbuf->data_len = io->buf_len;
        io->mbuf->pkt_len = io->buf_len;
        if(rte_eth_tx_burst(interface->port_id, io->queue, &io->mbuf, 1) != 0) {
            /* Dump the packet into pcap file. */
            if(unlikely(g_ctx->pcap.write_buf != NULL)) {
                pcap = true;
                pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                          interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
            }
            io->stats.packets++;
            io->stats.bytes += io->buf_len;
            io->mbuf = NULL;
            io->buf_len = 0;
            burst--;
        } else {
            /* This packet will be retried next interval 
             * because io->buf_len is not reset to zero. */
            io->stats.io_errors++;
            burst = 0;
        }
    }
    if(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP) {
        now = timespec_to_nsec(timer->timestamp);
        while(burst) {
            /* Build a batch of up to BURST_SIZE_TX stream packets, then
             * hand the whole batch to rte_eth_tx_burst() in one call. Stream
             * accounting (flow_seq/tx_packets) is only applied below to the
             * packets rte_eth_tx_burst() confirms it actually sent - a
             * packet that never leaves the NIC (e.g. because the generator
             * is offering more than line rate) must not advance its stream
             * sequence number, or the receiver will report it as network
             * loss when it was really dropped locally before transmission. */
            n = burst < BURST_SIZE_TX ? burst : BURST_SIZE_TX;
            if(unlikely(rte_pktmbuf_alloc_bulk(io->mbuf_pool, mbufs, n) != 0)) {
                io->stats.no_buffer++;
                break;
            }
            built = 0;
            while(built < n) {
                stream = bbl_stream_io_send_iter(io, now);
                if(unlikely(stream == NULL)) {
                    break;
                }
                if(unlikely(rte_pktmbuf_append(mbufs[built], stream->tx_len) == NULL)) {
                    io->stats.no_buffer++;
                    break;
                }
                memcpy(rte_pktmbuf_mtod(mbufs[built], uint8_t *), stream->tx_buf, stream->tx_len);
                streams[built] = stream;
                stream->flow_seq++;
                built++;
            }
            if(built < n) {
                /* Return the mbufs bulk-allocated but not built into a
                 * packet this round. */
                rte_pktmbuf_free_bulk(&mbufs[built], n - built);
            }
            if(built) {
                nb_tx = rte_eth_tx_burst(interface->port_id, io->queue, mbufs, built);
                for(i = 0; i < nb_tx; i++) {
                    /* Dump the packet into pcap file. */
                    if(unlikely(g_ctx->pcap.write_buf && g_ctx->pcap.include_streams)) {
                        pcap = true;
                        pcapng_push_packet_header(&io->timestamp, streams[i]->tx_buf, streams[i]->tx_len,
                                                interface->ifindex, PCAPNG_EPB_FLAGS_OUTBOUND);
                    }
                    streams[i]->tx_packets++;
                    io->stats.packets++;
                    io->stats.bytes += streams[i]->tx_len;
                }
                if(unlikely(nb_tx < built)) {
                    /* Offered more than the NIC could actually transmit.
                     * These packets never left the box, so just count them
                     * as locally dropped instead of as sent stream traffic. */
                    io->stats.dropped += (built - nb_tx);
                    rte_pktmbuf_free_bulk(&mbufs[nb_tx], built - nb_tx);
                }
                burst -= built;
            }
            if(built < n) {
                /* Nothing more was due this round. */
                break;
            }
        }
    } else {
        bbl_stream_io_stop(io);
    }
    if(pcap) {
        pcapng_fflush();
    }
}

void
io_dpdk_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;

    struct rte_mbuf *pkts_burst[BURST_SIZE_RX];
    struct rte_mbuf *packet;

    uint16_t port_id = interface->port_id;
    uint16_t nb_rx;
    uint16_t i;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_INGRESS);
    assert(io->thread);

    while(thread->active) {
        nb_rx = rte_eth_rx_burst(port_id, io->queue, pkts_burst, BURST_SIZE_RX);
        if(nb_rx == 0) {
            /* rte_pause() optimizes CPU pipeline without context switching */
            rte_pause();
            continue;
        }
        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        /* Prefetch the first few packets of the burst before processing
         * starts, so their data has time to land before it's touched. */
        for(i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
        }
        for(i = 0; i < nb_rx; i++) {
            /* Prefetch packets ahead of the one being processed to hide
             * memory latency behind the current packet's processing. */
            if(likely(i + PREFETCH_OFFSET < nb_rx)) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + PREFETCH_OFFSET], void *));
            }
            packet = pkts_burst[i];
            io->buf = rte_pktmbuf_mtod(packet, uint8_t *);
            io->buf_len = packet->pkt_len;
            /* Process packet */
            io_thread_rx_handler(thread, io);
            rte_pktmbuf_free(packet);
        }
    }
}

void
io_dpdk_thread_tx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    bbl_stream_s *stream = NULL;
    bbl_stream_s *streams[BURST_SIZE_TX];
    struct rte_mbuf *mbufs[BURST_SIZE_TX];
    uint16_t io_burst = interface->config->io_burst;
    uint16_t burst = 0;
    uint16_t built;
    uint16_t n;
    uint16_t nb_tx;
    uint16_t i;
    uint64_t now;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 1000;

    /* Number of consecutive rounds without anything sent before we back
     * off with a nanosleep. With many independently paced stream instances,
     * a single round finding nothing due is common even under heavy
     * aggregate load (the next stream may become due microseconds later),
     * so we only throttle once idleness looks sustained rather than after
     * a single empty round. */
    uint32_t idle_rounds = 0;
    const uint32_t idle_spin_rounds = 10000;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    while(thread->active) {
        if(io->update_streams) {
            io_stream_update_pps(io);
        }
        burst = io_burst;

        /* First send all control traffic which has higher priority. */
        while((slot = bbl_txq_read_slot(txq))) {
            /* This packet will be retried next interval
             * because slot is not marked as read. */
            if(!io->mbuf) {
                if(!io_dpdk_mbuf_alloc(io)) {
                    break;
                }
            }
            /* Transmit the packet. */
            io->mbuf->data_len = slot->packet_len;
            io->mbuf->pkt_len = slot->packet_len;
            memcpy(io->buf, slot->packet, slot->packet_len);
            if(rte_eth_tx_burst(interface->port_id, io->queue, &io->mbuf, 1) != 0) {
                io->stats.packets++;
                io->stats.bytes += slot->packet_len;
                io->mbuf = NULL;
                bbl_txq_read_next(txq);
                if(burst) burst--;
            } else {
                io->stats.io_errors++;
                nanosleep(&sleep, &rem);
                burst = 0;
                break;
            }
        }

        /* Get TX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);

        if(g_traffic && g_init_phase == false && interface->state == INTERFACE_UP) {
            now = timespec_to_nsec(&io->timestamp);
            while(burst) {
                /* Build a batch of up to BURST_SIZE_TX stream packets, then
                 * hand the whole batch to rte_eth_tx_burst() in one call.
                 * Stream accounting (flow_seq/tx_packets) is only applied
                 * below to the packets rte_eth_tx_burst() confirms it
                 * actually sent - a packet that never leaves the NIC (e.g.
                 * because the generator is offering more than line rate)
                 * must not advance its stream sequence number, or the
                 * receiver will report it as network loss when it was
                 * really dropped locally before transmission. */
                n = burst < BURST_SIZE_TX ? burst : BURST_SIZE_TX;
                if(unlikely(rte_pktmbuf_alloc_bulk(io->mbuf_pool, mbufs, n) != 0)) {
                    io->stats.no_buffer++;
                    break;
                }
                built = 0;
                while(built < n) {
                    stream = bbl_stream_io_send_iter(io, now);
                    if(unlikely(stream == NULL)) {
                        break;
                    }
                    if(unlikely(rte_pktmbuf_append(mbufs[built], stream->tx_len) == NULL)) {
                        io->stats.no_buffer++;
                        break;
                    }
                    memcpy(rte_pktmbuf_mtod(mbufs[built], uint8_t *), stream->tx_buf, stream->tx_len);
                    streams[built] = stream;
                    stream->flow_seq++;
                    built++;
                }
                if(built < n) {
                    /* Return the mbufs bulk-allocated but not built into a
                     * packet this round. */
                    rte_pktmbuf_free_bulk(&mbufs[built], n - built);
                }
                if(built) {
                    nb_tx = rte_eth_tx_burst(interface->port_id, io->queue, mbufs, built);
                    for(i = 0; i < nb_tx; i++) {
                        streams[i]->tx_packets++;
                        io->stats.packets++;
                        io->stats.bytes += streams[i]->tx_len;
                    }
                    if(unlikely(nb_tx < built)) {
                        /* Offered more than the NIC could actually transmit.
                         * These packets never left the box, so just count
                         * them as locally dropped instead of as sent stream
                         * traffic. */
                        io->stats.dropped += (built - nb_tx);
                        rte_pktmbuf_free_bulk(&mbufs[nb_tx], built - nb_tx);
                    }
                    burst -= built;
                }
                if(built < n) {
                    /* Nothing more was due this round. */
                    break;
                }
            }
        } else {
            bbl_stream_io_stop(io);
        }

        if(burst != io_burst) {
            idle_rounds = 0;
        } else if(++idle_rounds >= idle_spin_rounds) {
            /* Nothing was sent for many consecutive rounds in a row.
             * Only now back off, instead of busy-spinning forever, or
             * sleeping after every single empty round (which would also
             * throttle bursty-but-busy streams that just missed being
             * due by a few microseconds). */
            nanosleep(&sleep, &rem);
            idle_rounds = 0;
        }
    }
}

static bool
io_dpdk_add_mbuf_pool(io_handle_s *io, unsigned int num_mbufs)
{
    struct rte_mempool *mbuf_pool;
    char name[16] = {0};
    static uint16_t id = 0;

    snprintf(name, sizeof(name), "MBUF_POOL_%u", ++id);

    mbuf_pool = rte_pktmbuf_pool_create(name, num_mbufs,
            MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_eth_dev_socket_id(io->interface->port_id));
    if(!mbuf_pool) {
        return false;
    }
    io->mbuf_pool = mbuf_pool;
    return true;
}

bool
io_dpdk_interface_init(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;

    int ret;
    bool found = false;

    uint16_t port_id;
    uint16_t queue;
    uint16_t id;
    uint16_t nb_rx_queue = 1;
    uint16_t nb_tx_queue = 1;
    struct rte_eth_dev_info dev_info = {0};
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_rxconf rx_conf = {0};
    struct rte_eth_txconf tx_conf = {0};
    struct rte_ether_addr mac = {0};
    io_handle_s *io;

    RTE_ETH_FOREACH_DEV(port_id) {
        if(io_dpdk_dev_info(port_id, &dev_info)) {
            if(strcmp(dev_info.device->name, interface->name) == 0) {
                found = true;
                interface->port_id = port_id;
                break;
            }
        }
    }
    if(!found) {
        LOG(ERROR, "DPDK: interface %s not found\n", interface->name);
        return false;
    }

    if((config->rx_auto_cpuset && !config->rx_cpuset_count) ||
       (config->tx_auto_cpuset && !config->tx_cpuset_count)) {
        if(!io_interface_init_topology(interface, rte_eth_dev_socket_id(port_id))) {
            LOG(ERROR, "DPDK: failed to discover local CPU topology for interface %s (%u)\n",
                interface->name, port_id);
            return false;
        }
    }

    /* Get MAC address */
    if(*(uint32_t*)config->mac) {
        memcpy(interface->mac, config->mac, ETH_ADDR_LEN);
    } else {
        if(rte_eth_macaddr_get(port_id, &mac) < 0) {
            LOG(ERROR, "DPDK: interface %s (%u) failed to get MAC\n", 
                interface->name, port_id);
            return false;
        }
        LOG(DPDK, "DPDK: interface %s (%u) MAC address %s\n", 
            interface->name, port_id, format_mac_address(mac.addr_bytes));
        memcpy(interface->mac, mac.addr_bytes, ETH_ADDR_LEN);
    }

    /* Configure interface */
    if(config->tx_threads) {
        nb_tx_queue = config->tx_threads;
    }
    if(config->rx_threads) {
        nb_rx_queue = config->rx_threads;
    }
    if(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    local_port_conf.rx_adv_conf.rss_conf.rss_hf =
        (RTE_ETH_RSS_VLAN | RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_PPPOE | RTE_ETH_RSS_L2TPV2| RTE_ETH_RSS_MPLS) &
        dev_info.flow_type_rss_offloads;

    ret = rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue, &local_port_conf);
    if(ret < 0) {
        LOG(ERROR, "DPDK: interface %s (%u) failed to configure interface (error %d)\n",
            interface->name, port_id, ret);
        return false;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &config->io_slots_rx, &config->io_slots_tx);
    if(ret < 0) {
        LOG(ERROR, "DPDK: %s (%u) failed to adjust number of rx/tx descriptors (error %d)\n",
            interface->name, port_id, ret);
        return false;
    }

    ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, (rte_eth_dev_cb_fn)io_dpdk_event_callback, NULL);
    if(ret < 0) {
        LOG(ERROR, "DPDK: interface %s (%u) failed to register callback (error %d)\n",
            interface->name, port_id, ret);
        return false;
    }

    id = nb_rx_queue;
    for(queue = 0; queue < nb_rx_queue; queue++) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --id;
        io->mode = config->io_mode;
        io->direction = IO_INGRESS;
        io->next = interface->io.rx;
        interface->io.rx = io;
        io->interface = interface;
        if(config->rx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
            io->thread->run_fn = io_dpdk_thread_rx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 0, 
                               config->rx_interval, io, &io_dpdk_rx_job);
        }
        io->queue = queue;
        if(!io_dpdk_add_mbuf_pool(io, NUM_MBUFS_RX)) {
            LOG(ERROR, "DPDK: interface %s (%u) failed to create RX mbuf pool for queue %u\n",
                interface->name, port_id, queue);
            return false;
        }

        rx_conf = dev_info.default_rxconf;
        rx_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(port_id, queue, config->io_slots_rx,
                                     rte_eth_dev_socket_id(port_id), 
                                     &rx_conf, io->mbuf_pool);
        if(ret < 0) {
            LOG(ERROR, "DPDK: interface %s (%u) failed to setup RX queue %u (error %d)\n",
                interface->name, port_id, queue, ret);
            return false;
        }
    }

    id = nb_tx_queue;
    for(queue = 0; queue < nb_tx_queue; queue++) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --id;
        io->mode = config->io_mode;
        io->direction = IO_EGRESS;
        io->next = interface->io.tx;
        interface->io.tx = io;
        io->interface = interface;
        io->buf = malloc(IO_BUFFER_LEN);
        if(config->tx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
            io->thread->run_fn = io_dpdk_thread_tx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0, 
                config->tx_interval, io, &io_dpdk_tx_job);
        }
        io->queue = queue;
        if(!io_dpdk_add_mbuf_pool(io, NUM_MBUFS_TX)) {
            LOG(ERROR, "DPDK: interface %s (%u) failed to create TX mbuf pool for queue %u\n",
                interface->name, port_id, queue);
            return false;
        }

        tx_conf = dev_info.default_txconf;
        tx_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(port_id, queue, config->io_slots_tx,
                                     rte_eth_dev_socket_id(port_id),
                                     &tx_conf);
        if(ret < 0) {
            LOG(ERROR, "DPDK: interface %s (%u) failed to setup TX queue %u (error %d)\n",
                interface->name, port_id, queue, ret);
            return false;
        }
    }

    ret = rte_eth_dev_set_ptypes(port_id, RTE_PTYPE_UNKNOWN, NULL, 0);
    if (ret < 0) {
        LOG(ERROR, "DPDK: interface %s (%u) failed to disable ptype parsing (error %d)\n",
            interface->name, port_id, ret);
        return false;
    }
 
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        LOG(ERROR, "DPDK: interface %s (%u) failed to start device (error %d)\n",
            interface->name, port_id, ret);
        return false;
    }

    ret = rte_eth_promiscuous_enable(port_id);
    if (ret < 0) {
        LOG(ERROR, "DPDK: interface %s (%u) failed to enable promiscuous mode (error %d)\n",
            interface->name, port_id, ret);
        return false;
    }

    io_dpdk_link_status(port_id);
    return true;
}

#endif
